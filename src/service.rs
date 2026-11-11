//! The Keyhole as a service: the only way the rest of AppDoorman reaches a Doorkey app.
//!
//! The service holds its own secret. It seals every app credential it is handed, so what the web
//! app stores is something it cannot open; it opens a credential only to make a call, loads only
//! signed, bundled Doorkeys (by id, never a spec from the caller), and signs the evidence of every
//! change with a key per workspace. It runs either in this process ([`KeyholeClient::local`]: dev,
//! tests, and a server that does not run the separate service yet) or as AppDoorman's `keyhole` command on a
//! Unix socket ([`KeyholeClient::remote`]): a separate process, under its own user, whose key the
//! web app never has. A compromised web app can then still ask for the handful of allowlisted
//! member changes, but cannot read an admin credential or send it anywhere.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use zeroize::Zeroizing;

use super::{evidence_hash, load_bundled, Created, Evidence, Keyhole, KeyholeError, Sealer, TargetGroup, TargetUser};
use crate::crypto::{sha256_hex, Key};

/// The largest call or reply read from the socket. A call is small; a reply can list every member.
const MAX_MESSAGE_BYTES: u64 = 64 * 1024 * 1024;

/// How long a caller waits for one call, a full member list of a large app included.
const CALL_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// One call to the Keyhole, about one app of one workspace.
#[derive(Serialize, Deserialize)]
pub struct Call {
    pub tenant: String,
    pub app: String,
    /// The bundled Doorkey that drives the app, by id.
    pub doorkey: String,
    pub base_url: String,
    /// The app's credential as this Keyhole sealed it; empty for `info` and `seal`.
    #[serde(default)]
    pub credential: String,
    /// The hash of the app's last evidence record, which the record of this change is chained to.
    #[serde(default)]
    pub prev: String,
    /// The app's settings for the Doorkey's declared parameters (Microsoft 365's usage location).
    #[serde(default)]
    pub params: BTreeMap<String, String>,
    pub action: Action,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Action {
    /// The id credentials are sealed under, and the workspace's evidence key.
    Info,
    /// Check a new credential against the Doorkey and the app's address, then seal it to this
    /// Keyhole. Nothing is sent to the app.
    Seal { credential: String },
    ListUsers,
    CreateUser { user_name: String, given: String, family: String, email: String },
    SetActive { id: String, active: bool },
    DeleteUser { id: String },
    WithdrawInvite { user_name: String, email: String },
    ListGroups,
    GroupMembers { group_id: String },
    CreateGroup { name: String },
    AddGroupMember { group_id: String, id: String },
    RemoveGroupMember { group_id: String, id: String },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "snake_case")]
pub enum Reply {
    Info { key_id: String, evidence_key: String },
    Sealed { credential: String },
    Users { users: Vec<TargetUser> },
    Created { created: Created },
    Changed { evidence: Evidence },
    Groups { groups: Vec<TargetGroup> },
    GroupCreated { group: TargetGroup, evidence: Evidence },
}

/// The Keyhole itself: its secret, and the HTTP client every Doorkey call goes out through.
pub struct Service {
    secret: Key,
    key_id: String,
    http: reqwest::Client,
    dev_mode: bool,
}

impl Service {
    pub fn new(secret: Key, dev_mode: bool) -> Self {
        // A short public name for the secret, written into every credential it seals.
        let key_id = sha256_hex(secret.derive("keyhole-key-id").to_base64().as_bytes())[..12].to_string();
        Self { secret, key_id, http: crate::net::outbound_client(dev_mode), dev_mode }
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The workspace's evidence signer: a key of its own per workspace.
    fn sealer(&self, tenant: &str) -> Sealer {
        Sealer::new(&self.secret.derive(&format!("evidence:{tenant}")))
    }

    fn credential_key(&self) -> Key {
        self.secret.derive("credentials")
    }

    /// Seal a credential for one app of one workspace: it opens only here, and only for that app.
    fn seal_credential(&self, tenant: &str, app: &str, plaintext: &str) -> String {
        format!("kh1.{}.{}", self.key_id, self.credential_key().seal(plaintext.as_bytes(), &credential_aad(tenant, app)))
    }

    /// Open a credential this Keyhole sealed for this app.
    pub fn open_credential(&self, tenant: &str, app: &str, sealed: &str) -> Result<Zeroizing<String>, KeyholeError> {
        let (id, inner) = split_sealed(sealed).ok_or_else(|| KeyholeError::Sealed("it was not sealed by a Keyhole".into()))?;
        if id != self.key_id {
            return Err(KeyholeError::Sealed(format!("it was sealed by Keyhole {id}")));
        }
        let plain = self.credential_key().open_string(inner, &credential_aad(tenant, app)).map_err(|_| KeyholeError::Sealed("it belongs to another app".into()))?;
        Ok(Zeroizing::new(plain))
    }

    /// A Keyhole for one call: the signed, bundled Doorkey at the app's address, holding `secret`,
    /// stamping its evidence with the workspace, the app and the chain head.
    fn keyhole(&self, call: &Call, secret: &str) -> Result<Keyhole, KeyholeError> {
        // The whole chain of causes: "the Doorkey is invalid" alone would not say what to fix.
        let setup = |e: anyhow::Error| KeyholeError::Setup(format!("{e:#}"));
        let spec = load_bundled(&call.doorkey, &call.base_url).map_err(setup)?;
        let keyhole = Keyhole::with_client(spec, secret, self.sealer(&call.tenant), self.dev_mode, self.http.clone()).map_err(setup)?;
        // A Seal checks the credential alone; the settings come with the calls that use them.
        let keyhole = if matches!(call.action, Action::Seal { .. } | Action::Info) { keyhole } else { keyhole.with_params(&call.params).map_err(setup)? };
        Ok(keyhole.stamped(&call.tenant, &call.app, &call.prev))
    }

    /// The Keyhole a call runs through, with the app's credential opened for it.
    fn opened(&self, call: &Call) -> Result<Keyhole, KeyholeError> {
        let secret = self.open_credential(&call.tenant, &call.app, &call.credential)?;
        self.keyhole(call, &secret)
    }

    pub async fn handle(&self, call: Call) -> Result<Reply, KeyholeError> {
        Ok(match &call.action {
            Action::Info => Reply::Info { key_id: self.key_id.clone(), evidence_key: self.sealer(&call.tenant).public_key().into() },
            Action::Seal { credential } => {
                self.keyhole(&call, credential)?;
                Reply::Sealed { credential: self.seal_credential(&call.tenant, &call.app, credential) }
            }
            Action::ListUsers => Reply::Users { users: self.opened(&call)?.list_users().await? },
            Action::CreateUser { user_name, given, family, email } => Reply::Created { created: self.opened(&call)?.create_user(user_name, given, family, email).await? },
            Action::SetActive { id, active } => Reply::Changed { evidence: self.opened(&call)?.set_active(id, *active).await? },
            Action::DeleteUser { id } => Reply::Changed { evidence: self.opened(&call)?.delete_user(id).await? },
            Action::WithdrawInvite { user_name, email } => Reply::Changed { evidence: self.opened(&call)?.withdraw_invite(user_name, email).await? },
            Action::ListGroups => Reply::Groups { groups: self.opened(&call)?.list_groups().await? },
            Action::GroupMembers { group_id } => Reply::Users { users: self.opened(&call)?.group_members(group_id).await? },
            Action::CreateGroup { name } => {
                let (group, evidence) = self.opened(&call)?.create_group(name).await?;
                Reply::GroupCreated { group, evidence }
            }
            Action::AddGroupMember { group_id, id } => Reply::Changed { evidence: self.opened(&call)?.add_group_member(group_id, id).await? },
            Action::RemoveGroupMember { group_id, id } => Reply::Changed { evidence: self.opened(&call)?.remove_group_member(group_id, id).await? },
        })
    }
}

fn credential_aad(tenant: &str, app: &str) -> String {
    format!("keyhole-credential:{tenant}:{app}")
}

/// Splits `kh1.<key id>.<ciphertext>` into (key id, ciphertext).
fn split_sealed(sealed: &str) -> Option<(&str, &str)> {
    sealed.strip_prefix("kh1.")?.split_once('.')
}

/// The id of the Keyhole that sealed a stored credential; `None` for one it did not seal.
pub fn sealed_by(sealed: &str) -> Option<&str> {
    split_sealed(sealed).map(|(id, _)| id)
}

/// How the web app reaches the Keyhole.
#[derive(Clone)]
pub struct KeyholeClient {
    remote: Option<PathBuf>,
    /// The Keyhole in this process, keyed from the master key. It serves every call when there is
    /// no separate service; with one, it only opens credentials it sealed before, once, so the
    /// service can seal them again.
    local: Arc<Service>,
}

impl KeyholeClient {
    /// The Keyhole in this process.
    pub fn local(service: Service) -> Self {
        Self { remote: None, local: Arc::new(service) }
    }

    /// The Keyhole service on `socket`; `legacy` is the in-process Keyhole it takes over from.
    pub fn remote(socket: PathBuf, legacy: Service) -> Self {
        Self { remote: Some(socket), local: Arc::new(legacy) }
    }

    pub async fn call(&self, call: Call) -> Result<Reply, KeyholeError> {
        match &self.remote {
            None => self.local.handle(call).await,
            Some(socket) => tokio::time::timeout(CALL_TIMEOUT, remote_call(socket, &call))
                .await
                .unwrap_or_else(|_| Err(KeyholeError::Unavailable("it did not answer in time".into()))),
        }
    }

    /// The id credentials are sealed under now, and the workspace's evidence key.
    pub async fn info(&self, tenant: &str) -> Result<(String, String), KeyholeError> {
        match self.call(Call { tenant: tenant.into(), app: String::new(), doorkey: String::new(), base_url: String::new(), credential: String::new(), prev: String::new(), params: BTreeMap::new(), action: Action::Info }).await? {
            Reply::Info { key_id, evidence_key } => Ok((key_id, evidence_key)),
            _ => Err(unexpected()),
        }
    }

    /// Check a new credential for an app and seal it to the Keyhole.
    pub async fn seal(&self, tenant: &str, app: &str, doorkey: &str, base_url: &str, credential: &str) -> Result<String, KeyholeError> {
        let call = Call {
            tenant: tenant.into(),
            app: app.into(),
            doorkey: doorkey.into(),
            base_url: base_url.into(),
            credential: String::new(),
            prev: String::new(),
            params: BTreeMap::new(),
            action: Action::Seal { credential: credential.into() },
        };
        match self.call(call).await? {
            Reply::Sealed { credential } => Ok(credential),
            _ => Err(unexpected()),
        }
    }

    /// Every key that may have signed this workspace's evidence: the Keyhole's, and, once a
    /// separate service has taken over, the in-process one's that signed the records before.
    pub async fn evidence_keys(&self, tenant: &str) -> Result<Vec<String>, KeyholeError> {
        let (_, current) = self.info(tenant).await?;
        let earlier = self.local.sealer(tenant).public_key().to_string();
        Ok(if earlier == current { vec![current] } else { vec![current, earlier] })
    }

    /// A credential the in-process Keyhole sealed, opened so the active Keyhole can seal it again.
    pub fn open_earlier(&self, tenant: &str, app: &str, sealed: &str) -> Option<Zeroizing<String>> {
        self.local.open_credential(tenant, app, sealed).ok()
    }
}

fn unexpected() -> KeyholeError {
    KeyholeError::Unavailable("it gave an answer that does not fit the call".into())
}

/// One call over the socket: a line of JSON out, a line of JSON back.
async fn remote_call(socket: &Path, call: &Call) -> Result<Reply, KeyholeError> {
    let unavailable = |e: std::io::Error| KeyholeError::Unavailable(e.to_string());
    let mut stream = tokio::net::UnixStream::connect(socket).await.map_err(unavailable)?;
    // The call can hold a credential to seal; the buffer is wiped once sent.
    let mut line = Zeroizing::new(serde_json::to_string(call).map_err(|e| KeyholeError::Unavailable(e.to_string()))?);
    line.push('\n');
    stream.write_all(line.as_bytes()).await.map_err(unavailable)?;
    stream.shutdown().await.map_err(unavailable)?;
    let mut reply = String::new();
    BufReader::new(stream.take(MAX_MESSAGE_BYTES)).read_line(&mut reply).await.map_err(unavailable)?;
    serde_json::from_str::<Result<Reply, KeyholeError>>(&reply).map_err(|_| unexpected())?
}

/// Serve the Keyhole on a Unix socket, one call per connection. The socket is group-accessible so
/// the web app (in the group) can call it; the key never leaves this process.
pub async fn serve(socket: &Path, service: Arc<Service>) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if socket.exists() {
        std::fs::remove_file(socket)?;
    }
    let listener = tokio::net::UnixListener::bind(socket)?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o660))?;
    tracing::info!(socket = %socket.display(), key_id = service.key_id(), "the Keyhole is listening");
    loop {
        let (stream, _) = listener.accept().await?;
        let service = service.clone();
        tokio::spawn(async move {
            if let Err(e) = answer(stream, &service).await {
                tracing::warn!(error = %e, "a Keyhole call could not be answered");
            }
        });
    }
}

async fn answer(stream: tokio::net::UnixStream, service: &Service) -> Result<()> {
    let (read, mut write) = stream.into_split();
    let mut line = Zeroizing::new(String::new());
    BufReader::new(read.take(MAX_MESSAGE_BYTES)).read_line(&mut line).await?;
    // Never log the call: it can hold a credential to seal.
    let reply = match serde_json::from_str::<Call>(&line) {
        Ok(call) => service.handle(call).await,
        Err(_) => Err(KeyholeError::Setup("the Keyhole could not read the call".into())),
    };
    let mut out = serde_json::to_string(&reply)?;
    out.push('\n');
    write.write_all(out.as_bytes()).await?;
    Ok(())
}

/// A Doorkey app as the sync run sees it: every call goes to the Keyhole, which holds the
/// credential. Each change advances the app's evidence chain head.
pub struct KeyholeApp {
    client: KeyholeClient,
    tenant: String,
    app: String,
    doorkey: String,
    base_url: String,
    credential: String,
    supports_delete: bool,
    supports_suspend: bool,
    supports_withdraw: bool,
    supports_groups: bool,
    supports_create_group: bool,
    params: BTreeMap<String, String>,
    head: Mutex<String>,
}

impl KeyholeApp {
    /// `credential` is the app's credential as the Keyhole sealed it; `head` the hash of the app's
    /// last evidence record ("" before the first).
    pub fn new(client: KeyholeClient, tenant: &str, app: &str, doorkey: &str, base_url: &str, credential: &str, head: String) -> Result<Self> {
        // The spec is public; reading it here only answers what the app can do.
        let spec = load_bundled(doorkey, base_url)?;
        let (supports_delete, supports_suspend, supports_withdraw) = (spec.ops.contains_key("delete_user"), spec.can_suspend(), spec.ops.contains_key("withdraw_invite"));
        let (supports_groups, supports_create_group) = (spec.supports_groups(), spec.ops.contains_key("create_group"));
        Ok(Self {
            client,
            tenant: tenant.into(),
            app: app.into(),
            doorkey: doorkey.into(),
            base_url: base_url.into(),
            credential: credential.into(),
            supports_delete,
            supports_suspend,
            supports_withdraw,
            supports_groups,
            supports_create_group,
            params: BTreeMap::new(),
            head: Mutex::new(head),
        })
    }

    /// The app's settings for the Doorkey's parameters, sent with every call.
    pub fn with_params(mut self, params: BTreeMap<String, String>) -> Self {
        self.params = params;
        self
    }

    pub fn supports_delete(&self) -> bool {
        self.supports_delete
    }

    pub fn supports_suspend(&self) -> bool {
        self.supports_suspend
    }

    pub fn supports_withdraw(&self) -> bool {
        self.supports_withdraw
    }

    pub fn supports_groups(&self) -> bool {
        self.supports_groups
    }

    pub fn supports_create_group(&self) -> bool {
        self.supports_create_group
    }

    pub async fn list_groups(&self) -> Result<Vec<TargetGroup>> {
        match self.send(Action::ListGroups).await? {
            Reply::Groups { groups } => Ok(groups),
            _ => Err(unexpected().into()),
        }
    }

    pub async fn group_members(&self, group_id: &str) -> Result<Vec<TargetUser>> {
        match self.send(Action::GroupMembers { group_id: group_id.into() }).await? {
            Reply::Users { users } => Ok(users),
            _ => Err(unexpected().into()),
        }
    }

    pub async fn create_group(&self, name: &str) -> Result<(TargetGroup, Evidence)> {
        match self.send(Action::CreateGroup { name: name.into() }).await? {
            Reply::GroupCreated { group, evidence } => {
                self.advance(&evidence);
                Ok((group, evidence))
            }
            _ => Err(unexpected().into()),
        }
    }

    pub async fn add_group_member(&self, group_id: &str, id: &str) -> Result<Evidence> {
        self.changed(Action::AddGroupMember { group_id: group_id.into(), id: id.into() }).await
    }

    pub async fn remove_group_member(&self, group_id: &str, id: &str) -> Result<Evidence> {
        self.changed(Action::RemoveGroupMember { group_id: group_id.into(), id: id.into() }).await
    }

    async fn send(&self, action: Action) -> Result<Reply, KeyholeError> {
        let prev = self.head.lock().unwrap().clone();
        let call = Call {
            tenant: self.tenant.clone(),
            app: self.app.clone(),
            doorkey: self.doorkey.clone(),
            base_url: self.base_url.clone(),
            credential: self.credential.clone(),
            prev,
            params: self.params.clone(),
            action,
        };
        self.client.call(call).await
    }

    fn advance(&self, evidence: &Evidence) {
        *self.head.lock().unwrap() = evidence_hash(evidence);
    }

    pub async fn list_users(&self) -> Result<Vec<TargetUser>> {
        match self.send(Action::ListUsers).await? {
            Reply::Users { users } => Ok(users),
            _ => Err(unexpected().into()),
        }
    }

    pub async fn create_user(&self, user_name: &str, given: &str, family: &str, email: &str) -> Result<Created> {
        let action = Action::CreateUser { user_name: user_name.into(), given: given.into(), family: family.into(), email: email.into() };
        match self.send(action).await? {
            Reply::Created { created } => {
                self.advance(match &created {
                    Created::Confirmed(_, evidence) => evidence,
                    Created::Pending(p) => &p.evidence,
                });
                Ok(created)
            }
            _ => Err(unexpected().into()),
        }
    }

    pub async fn set_active(&self, id: &str, active: bool) -> Result<Evidence> {
        self.changed(Action::SetActive { id: id.into(), active }).await
    }

    pub async fn delete_user(&self, id: &str) -> Result<Evidence> {
        self.changed(Action::DeleteUser { id: id.into() }).await
    }

    pub async fn withdraw_invite(&self, user_name: &str, email: &str) -> Result<Evidence> {
        self.changed(Action::WithdrawInvite { user_name: user_name.into(), email: email.into() }).await
    }

    async fn changed(&self, action: Action) -> Result<Evidence> {
        match self.send(action).await? {
            Reply::Changed { evidence } => {
                self.advance(&evidence);
                Ok(evidence)
            }
            _ => Err(unexpected().into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify_evidence;

    async fn mock_app() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, crate::mock::mock_router::<()>().into_make_service()).await.unwrap() });
        format!("http://127.0.0.1:{port}/svc-{}/v2", crate::crypto::random_token(8))
    }

    fn app(client: &KeyholeClient, base_url: &str, credential: &str, head: &str) -> KeyholeApp {
        KeyholeApp::new(client.clone(), "t1", "a1", "mock", base_url, credential, head.into()).unwrap()
    }

    #[tokio::test]
    async fn a_sealed_credential_opens_only_in_its_keyhole_and_for_its_app() {
        let base = mock_app().await;
        let client = KeyholeClient::local(Service::new(Key::generate(), true));
        let sealed = client.seal("t1", "a1", "mock", &base, "dev-token").await.unwrap();
        assert!(sealed.starts_with("kh1.") && !sealed.contains("dev-token"));
        assert_eq!(app(&client, &base, &sealed, "").list_users().await.unwrap().len(), 3, "the mock starts with three accounts");

        // Copied to another app or workspace, or into another server's Keyhole, it does not open.
        let service = Service::new(Key::generate(), true);
        assert!(matches!(client.local.open_credential("t1", "a2", &sealed), Err(KeyholeError::Sealed(_))));
        assert!(matches!(client.local.open_credential("t2", "a1", &sealed), Err(KeyholeError::Sealed(_))));
        assert!(matches!(service.open_credential("t1", "a1", &sealed), Err(KeyholeError::Sealed(_))));

        // Sealing checks what can be checked without a request, and says why it refuses.
        let err = client.seal("t1", "a1", "github", "https://attacker.example/orgs/acme", "ghp_x").await.unwrap_err();
        assert!(matches!(&err, KeyholeError::Setup(m) if m.contains("api.github.com")), "{err:?}");
        let err = client.seal("t1", "a1", "microsoft365", "https://graph.microsoft.com/v1.0", "secret-only").await.unwrap_err();
        assert!(matches!(&err, KeyholeError::Setup(m) if !m.contains("secret-only")), "{err:?}");
        assert!(client.seal("t1", "a1", "unknown", &base, "dev-token").await.is_err());
    }

    #[tokio::test]
    async fn changes_are_signed_per_workspace_and_chained() {
        let base = mock_app().await;
        let client = KeyholeClient::local(Service::new(Key::generate(), true));
        let sealed = client.seal("t1", "a1", "mock", &base, "dev-token").await.unwrap();
        let target = app(&client, &base, &sealed, "genesis");
        let user = match target.create_user("c@x.eu", "C", "X", "c@x.eu").await.unwrap() {
            Created::Confirmed(user, evidence) => {
                assert_eq!((evidence.tenant.as_str(), evidence.app.as_str(), evidence.prev.as_str()), ("t1", "a1", "genesis"));
                user
            }
            Created::Pending(_) => unreachable!("the mock lists a user as soon as it is created"),
        };
        let first_hash = target.head.lock().unwrap().clone();
        let ev = target.set_active(&user.id, false).await.unwrap();
        assert_eq!(ev.prev, first_hash, "each record names the one before it");

        let keys = client.evidence_keys("t1").await.unwrap();
        assert!(verify_evidence(&ev, &keys));
        assert!(!verify_evidence(&ev, &client.evidence_keys("t2").await.unwrap()), "each workspace has its own key");
    }

    #[tokio::test]
    async fn over_the_socket_the_web_side_never_holds_what_it_cannot_open() {
        let base = mock_app().await;
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("keyhole.sock");
        let (path, service) = (socket.clone(), Arc::new(Service::new(Key::generate(), true)));
        tokio::spawn(async move { serve(&path, service).await });
        // Wait for the socket to appear.
        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // The web side keeps its in-process Keyhole only to hand over credentials it sealed itself.
        let client = KeyholeClient::remote(socket.clone(), Service::new(Key::generate(), true));
        let sealed = client.seal("t1", "a1", "mock", &base, "dev-token").await.unwrap();
        assert!(client.open_earlier("t1", "a1", &sealed).is_none(), "this process cannot open what the service sealed");
        let target = app(&client, &base, &sealed, "");
        let user = target.list_users().await.unwrap().into_iter().next().unwrap();
        let ev = target.set_active(&user.id, false).await.unwrap();
        let keys = client.evidence_keys("t1").await.unwrap();
        assert_eq!(keys.len(), 2, "the service's key, and the in-process one's for records from before");
        assert!(verify_evidence(&ev, &keys[..1]));

        // A Keyhole error crosses the socket as itself, so the sync run still knows a bad session.
        let wrong = client.seal("t1", "a1", "mock", &base, "wrong-token").await.unwrap();
        let err = app(&client, &base, &wrong, "").list_users().await.unwrap_err();
        assert!(matches!(err.downcast_ref::<KeyholeError>(), Some(KeyholeError::Http(401, ..))), "{err:?}");
        // No service on the socket is an error of its own, never an empty member list.
        let gone = KeyholeClient::remote(dir.path().join("nothing.sock"), Service::new(Key::generate(), true));
        assert!(matches!(gone.info("t1").await, Err(KeyholeError::Unavailable(_))));
    }
}
