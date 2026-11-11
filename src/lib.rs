//! Doorkeys and the Keyhole: provisioning for apps whose plan gives no SCIM.
//!
//! A **Doorkey** is a versioned spec for one app. It describes each lifecycle action
//! (list / create / deactivate / delete) as a declarative request against the app's own admin
//! API, together with optional guards, a read-back that must confirm every change, and a
//! fingerprint of the response shape so breakage is caught before a customer needs a change.
//! Doorkeys are data, not code: each is written from the app's API documentation, reviewed, and
//! run only by this deterministic interpreter. Doorkeys are signed offline before they ship, and
//! only a spec whose signature checks out against the key built into the binary is loaded.
//!
//! The **Keyhole** is the only code that uses an app credential. Every request it sends stays on
//! the Doorkey's own origin, which must be one of the hosts the Doorkey names (so a workspace URL
//! changed to another server can never carry the credential there), and every request is checked,
//! with the path as it will actually be sent and its parameter names, against the Doorkey's
//! allowlist. Reads are checked too, since RPC-style admin APIs change state on a GET. In
//! production the Keyhole runs as its own process ([`service`]), which caps what a compromise of
//! the rest of AppDoorman can do to the handful of member-management calls the Doorkey permits.
//! An export, a billing change or "make me owner" is not among them.
//!
//! Reads fail closed. A member list that cannot be read in full (a 404, an HTML page instead of
//! JSON, a renamed field, a user without an id, an app that stops paging or lists fewer users than
//! it reports, more pages than we will walk) is an error, never an empty or partial list: the
//! planner would read a short list as "these people have no access" and never remove them.
//!
//! The same lifecycle also has a native-SCIM implementation ([`Target::Scim`]), so AppDoorman's
//! sync engine can treat a SCIM app and a Doorkey app through one [`Target`] enum. The sync
//! engine itself is not part of this package.

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use url::Url;
use zeroize::Zeroizing;

use crate::crypto::Key;
use crate::scim::ScimClient;

pub mod canary;
pub mod crypto;
pub mod graphql;
#[cfg(any(test, feature = "mock"))]
pub mod mock;
pub mod net;
pub mod scim;
pub mod service;

/// HTTP methods that change state. An op sending one must be confirmed by a read-back.
const MUTATING: [&str; 4] = ["POST", "PUT", "PATCH", "DELETE"];

/// Attempts at a request the app refuses with 429, and the longest `Retry-After` honoured between
/// them. A 429 means the app did not act on the request, so sending it again is safe.
const RATE_LIMIT_TRIES: u32 = 3;
const RATE_LIMIT_MAX_WAIT_SECS: u64 = 30;

/// The public half of AppDoorman's Doorkey signing key (Ed25519, base64). The private half stays
/// offline with whoever reviews Doorkeys; a spec only loads with its signature, so it cannot be
/// changed without that key, whether in the repository, the build or the binary.
const SIGNING_KEY: &str = include_str!("../doorkeys/doorkey-signing.pub");

/// The Doorkey specs shipped with AppDoorman, by id, each with its detached signature. Their
/// `base_url` is a placeholder the caller overwrites with the customer's own workspace URL.
pub fn bundled(id: &str) -> Option<(&'static str, &'static str)> {
    match id {
        "mock" => Some((include_str!("../doorkeys/mock.doorkey.json"), include_str!("../doorkeys/mock.doorkey.json.sig"))),
        "cloudflare" => Some((include_str!("../doorkeys/cloudflare.doorkey.json"), include_str!("../doorkeys/cloudflare.doorkey.json.sig"))),
        "asana" => Some((include_str!("../doorkeys/asana.doorkey.json"), include_str!("../doorkeys/asana.doorkey.json.sig"))),
        "anthropic" => Some((include_str!("../doorkeys/anthropic.doorkey.json"), include_str!("../doorkeys/anthropic.doorkey.json.sig"))),
        "openai" => Some((include_str!("../doorkeys/openai.doorkey.json"), include_str!("../doorkeys/openai.doorkey.json.sig"))),
        "atlassian" => Some((include_str!("../doorkeys/atlassian.doorkey.json"), include_str!("../doorkeys/atlassian.doorkey.json.sig"))),
        "github" => Some((include_str!("../doorkeys/github.doorkey.json"), include_str!("../doorkeys/github.doorkey.json.sig"))),
        "microsoft365" => Some((include_str!("../doorkeys/microsoft365.doorkey.json"), include_str!("../doorkeys/microsoft365.doorkey.json.sig"))),
        "github-copilot" => Some((include_str!("../doorkeys/github-copilot.doorkey.json"), include_str!("../doorkeys/github-copilot.doorkey.json.sig"))),
        "linear" => Some((include_str!("../doorkeys/linear.doorkey.json"), include_str!("../doorkeys/linear.doorkey.json.sig"))),
        _ => None,
    }
}

/// Load a bundled Doorkey, once its signature checks out, and point it at `base_url` (the
/// customer's workspace).
pub fn load_bundled(id: &str, base_url: &str) -> Result<Doorkey> {
    let (raw, signature) = bundled(id).with_context(|| format!("unknown Doorkey `{id}`"))?;
    verify_signature(raw.as_bytes(), signature, SIGNING_KEY).with_context(|| format!("Doorkey `{id}` is not signed with AppDoorman's Doorkey key"))?;
    let mut dk: Doorkey = serde_json::from_str(raw).with_context(|| format!("bundled Doorkey `{id}` is invalid"))?;
    dk.base_url = base_url.to_string();
    Ok(dk)
}

/// The detached signature of a Doorkey spec (base64 Ed25519 over its exact bytes), made with the
/// offline signing key's 32-byte seed.
pub fn sign_spec(seed: &[u8; 32], spec: &[u8]) -> String {
    let pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(seed).expect("a 32-byte seed is a valid Ed25519 key");
    B64.encode(pair.sign(spec).as_ref())
}

/// The public key (base64) that checks signatures made with `seed`.
pub fn signing_public_key(seed: &[u8; 32]) -> String {
    use ring::signature::KeyPair;
    let pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(seed).expect("a 32-byte seed is a valid Ed25519 key");
    B64.encode(pair.public_key().as_ref())
}

/// Check a detached signature over `spec` with `public_key` (both base64).
pub fn verify_signature(spec: &[u8], signature: &str, public_key: &str) -> Result<()> {
    let signature = B64.decode(signature.trim()).map_err(|_| anyhow!("the signature is not base64"))?;
    let public_key = B64.decode(public_key.trim()).map_err(|_| anyhow!("the public key is not base64"))?;
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key)
        .verify(spec, &signature)
        .map_err(|_| anyhow!("the signature does not match"))
}

/// The public key bundled Doorkeys are checked against.
pub fn bundled_signing_key() -> &'static str {
    SIGNING_KEY.trim()
}

/// The parameters the engine itself puts in an op's context; a lookup may not shadow them.
const CONTEXT_KEYS: [&str; 9] = ["id", "user_name", "user_name_local", "given", "family", "email", "active", "group_id", "name"];

/// The ops that push a Google group as a group in the app. `create_group` is optional: without
/// it, only a group that already exists in the app by that name is kept in step.
const GROUP_OPS: [&str; 4] = ["list_group_members", "add_group_member", "remove_group_member", "create_group"];

/// Pages a list op may walk. Running out is an error, never a silent truncation.
const MAX_PAGES: usize = 1000;

// ---------------------------------------------------------------------------
// Doorkey spec (authored as JSON, versioned)
// ---------------------------------------------------------------------------

/// One app's recorded lifecycle spec.
///
/// Every struct in the spec refuses unknown keys: a misspelled `paginate` or `ok_field` would
/// otherwise load fine and quietly turn the protection off. Notes for humans go in `_comment`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Doorkey {
    /// Free-form notes for whoever reviews the Doorkey; the engine ignores them.
    #[serde(default, rename = "_comment", skip_serializing_if = "Option::is_none")]
    pub comment: Option<Value>,
    /// App identifier, e.g. `"github"`.
    pub doorkey: String,
    /// Bumped whenever the spec is re-recorded after a UI/API change.
    pub version: u32,
    /// Full origin + prefix every request is relative to, e.g. `https://acme.example/scim/v2`.
    pub base_url: String,
    /// The hosts the credential may be sent to: `api.example.com` exactly, or `*.example.com` for
    /// any subdomain of it. `base_url` must be on one of them, so the customer's workspace URL can
    /// name their workspace but never another server. `*` (any host) is honoured only in dev mode,
    /// for the built-in mock.
    pub hosts: Vec<String>,
    /// How the Keyhole-held secret is presented. The secret itself is never in the Doorkey.
    pub auth: AuthSpec,
    /// Every request the Keyhole will ever send for this app, reads included. A request outside
    /// this list is refused before it leaves the process, and a Doorkey whose ops it does not
    /// cover is refused when it loads.
    pub allow: Vec<AllowRule>,
    /// Some admin APIs answer HTTP 200 with a success flag in the body (an `ok` field) and carry the
    /// failure in an `error` field. When set, a 2xx response counts as success only when this dotted
    /// path is `true`; otherwise the op fails closed with [`KeyholeError::NotOk`].
    #[serde(default)]
    pub ok_field: Option<String>,
    /// Constant headers every request carries, such as Anthropic's `anthropic-version`. They are
    /// part of the signed spec, never templated, and may not touch authentication, cookies or how
    /// the request is framed (see [`RESERVED_HEADERS`]).
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Named lifecycle operations.
    pub ops: BTreeMap<String, OpSpec>,
    /// Read-backs are retried while the app catches up with a change it accepted (optional).
    #[serde(default)]
    pub settle: Option<Settle>,
    /// What to tell the admin when the app refuses a call with one of these error codes (its
    /// `error.code`, `code` or `error_code`), in place of the app's own wording. For refusals
    /// whose message doesn't say what to fix, like OpenAI's "couldn't send this invite".
    #[serde(default)]
    pub hints: BTreeMap<String, String>,
    /// Settings the admin gives the app (see [`DoorkeyParam`]).
    #[serde(default)]
    pub parameters: Vec<DoorkeyParam>,
    /// Statuses besides 429 that this app answers when it is briefly busy, retried like a rate
    /// limit (Microsoft Graph's 409 "concurrent requests being made to the tenant" right after
    /// users are created). Only for an app whose status means exactly that: elsewhere a 409 is a
    /// real conflict and must fail.
    #[serde(default)]
    pub retry_statuses: Vec<u16>,
}

/// Headers a Doorkey's constant `headers` may not set: the credential's, the session's, and the
/// ones that frame the request.
const RESERVED_HEADERS: [&str; 8] = ["authorization", "cookie", "host", "content-type", "content-length", "transfer-encoding", "connection", "proxy-authorization"];

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "scheme", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthSpec {
    /// `Authorization: Bearer <secret>`.
    Bearer,
    /// A custom header carrying the secret verbatim.
    Header { name: String },
    /// OAuth 2.0 client credentials (RFC 6749 §4.4), for an admin API that takes a short-lived
    /// access token, such as Microsoft Graph. The injected secret is a JSON object holding
    /// `client_id`, `client_secret` and each of `fields`. The Keyhole posts them to `token_url`
    /// (`grant_type`, the `scope` and the `fields` as form fields; the client id and secret as HTTP
    /// Basic auth, or as form fields when `credentials_in_body`), keeps the access token until
    /// shortly before it expires, and sends it as `Authorization: Bearer`. The client secret only
    /// ever goes to `token_url`, which is part of the signed spec. Its path may name a credential
    /// field (`/{tenant_id}/oauth2/v2.0/token`), filled in as one plain segment; the host never
    /// changes.
    OauthClientCredentials {
        token_url: String,
        #[serde(default = "client_credentials")]
        grant_type: String,
        /// Further credential fields, by name (Microsoft's `tenant_id`). Each is sent in the token
        /// request unless the `token_url` path names it.
        #[serde(default)]
        fields: Vec<String>,
        /// The `scope` form field, when the token endpoint wants one
        /// (`https://graph.microsoft.com/.default`).
        #[serde(default)]
        scope: Option<String>,
        #[serde(default)]
        credentials_in_body: bool,
    },
}

fn client_credentials() -> String {
    "client_credentials".into()
}

/// What an OAuth client-credentials secret always holds besides its `fields`.
const OAUTH_CLIENT_KEYS: [&str; 2] = ["client_id", "client_secret"];

/// An access token is fetched again this long before the app says it expires.
const TOKEN_EARLY_SECS: u64 = 60;

/// The credential fields a token URL's path names, as `{field}`.
fn token_url_fields(token_url: &str) -> Vec<String> {
    token_url.split('{').skip(1).filter_map(|p| p.split_once('}').map(|(k, _)| k.to_string())).collect()
}

/// A value safe to stand as one path segment of a token URL: a tenant id or domain, nothing that
/// could change the path or reach another endpoint.
fn token_segment_safe(v: &str) -> bool {
    !v.is_empty() && v.len() <= 253 && v != "." && v != ".." && v.chars().all(|c| c.is_ascii_alphanumeric() || "-._".contains(c))
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AllowRule {
    pub method: String,
    /// Path relative to `base_url`, with `{param}` segments, e.g. `/Users/{id}`.
    pub path: String,
    /// The query parameter names the request may carry. When set, a request with any
    /// other parameter is refused: an RPC-style endpoint can do more with the right argument.
    #[serde(default)]
    pub params: Option<Vec<String>>,
    /// For a GraphQL endpoint, the root fields its operations may select (`users`,
    /// `deactivate_users`). A rule with `graphql` covers only GraphQL ops, each only when every
    /// root field of its document is listed; a rule without it never covers a GraphQL op.
    #[serde(default)]
    pub graphql: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OpSpec {
    #[serde(default, rename = "_comment", skip_serializing_if = "Option::is_none")]
    pub comment: Option<Value>,
    pub request: RequestSpec,
    /// Preconditions re-checked by a read immediately before a mutation (optional).
    #[serde(default)]
    pub guard: Vec<Guard>,
    /// Values the request needs that differ from account to account and are read from the app
    /// first, each under its own `{param}` (Cloudflare's id for the role named "Administrator").
    #[serde(default)]
    pub lookup: BTreeMap<String, Lookup>,
    /// Where the user fields are in this op's response.
    #[serde(default)]
    pub extract: Option<Extract>,
    /// Where the groups are in this op's response, for `list_groups`: the op that group push reads
    /// the app's groups through, and `create_group` reads its new group back from.
    #[serde(default)]
    pub groups: Option<GroupExtract>,
    /// How a list op walks pages. Without it the first response must hold every user.
    #[serde(default)]
    pub paginate: Option<Paginate>,
    /// The read-back that must pass for a change to count as done. Required on every mutating op.
    #[serde(default)]
    pub verify: Option<Verify>,
    /// The app accepts the change before it shows it: an invite only lists the person once they
    /// accept. When the read-back cannot find the user yet, the change is reported pending rather
    /// than failed; the sync run keeps it and settles it from a later member list, without sending
    /// it again. Only `create_user` may set this, and only with a `present` read-back.
    #[serde(default)]
    pub allow_pending: bool,
    /// Structural fingerprint of the expected response (of one user item, for a list op); a
    /// mismatch flags the Doorkey as stale.
    #[serde(default)]
    pub shape: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestSpec {
    pub method: String,
    /// Absolute path relative to `base_url`, with `{param}` placeholders and no query string.
    pub path: String,
    /// Query parameters; values may use `{param}` placeholders.
    #[serde(default)]
    pub query: BTreeMap<String, String>,
    #[serde(default)]
    pub body: Option<Value>,
    /// A GraphQL operation, sent as the JSON body `{query, variables}` of a `POST`. Mutually
    /// exclusive with `body` and `query`.
    #[serde(default)]
    pub graphql: Option<GraphqlSpec>,
}

/// One GraphQL operation. The document is part of the signed spec and is sent exactly as written;
/// only the `variables` are filled in, so a value can never change what the operation does. Whether
/// the op is a read or a change comes from the document (`query` or `mutation`), not the method.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphqlSpec {
    /// The document: one `query` or `mutation`, no fragments or directives (see [`graphql::parse`]).
    pub query: String,
    /// Variable values, templated like a JSON body. Each must be declared by the document.
    #[serde(default)]
    pub variables: Map<String, Value>,
    /// Dotted paths in the answer that must be absent, null or an empty array, for an API that
    /// reports a failed change inside `data`, per user (`data.suspendUser.errors`).
    #[serde(default)]
    pub errors_at: Vec<String>,
}

/// Where the groups are in a list response, as dotted paths.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupExtract {
    pub list: String,
    pub id: String,
    pub name: String,
    /// For a group that is a pool of seats (a Microsoft 365 license): dotted paths to how many
    /// seats it has and how many are taken, so the admin sees what is left.
    #[serde(default)]
    pub seats_total: Option<String>,
    #[serde(default)]
    pub seats_used: Option<String>,
}

/// A setting the admin gives a Doorkey app when connecting it, used in its requests as `{name}`
/// (Microsoft 365's `usage_location`). Only declared parameters are accepted, each checked by kind.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DoorkeyParam {
    pub name: String,
    pub kind: ParamKind,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ParamKind {
    /// An ISO 3166-1 alpha-2 country code, upper case (`DE`).
    CountryCode,
}

impl ParamKind {
    fn accepts(self, v: &str) -> bool {
        match self {
            ParamKind::CountryCode => v.len() == 2 && v.chars().all(|c| c.is_ascii_uppercase()),
        }
    }
}

/// Where to find the user fields in a response, as dotted paths (`profile.email`). `list` names the
/// array of users in a list response (`""` when the response is the bare array); when absent, the
/// response is a single user object.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Extract {
    #[serde(default)]
    pub list: Option<String>,
    pub id: String,
    /// The name the sync run matches people by. It must be the field that holds the email
    /// address, because that is how the planner finds an account a person already has.
    pub user_name: String,
    /// The account's active flag. Omit it for an app where being listed is having access (a member
    /// list, with no suspend): every user it lists is active, and taking access away is a delete.
    #[serde(default)]
    pub active: Option<String>,
    /// When the field named by `active` really records the opposite (a `deleted` flag, a
    /// `disabled` or `suspended` flag), set this so the engine reads active as its negation.
    #[serde(default)]
    pub active_inverted: bool,
    /// For an app that records a status rather than a flag (Atlassian's `status`): the value of the
    /// `active` field that means active. Any other value of the same type is inactive; a missing or
    /// differently typed field is still an error, never inactive.
    #[serde(default)]
    pub active_when: Option<Value>,
    /// List items that are not people (bots, system accounts), each given as a dotted path and its value.
    /// An item matching every field of any entry is left out of the list. Everyone else must have
    /// all the fields above, so a person without an email is still an error.
    #[serde(default)]
    pub skip: Vec<Map<String, Value>>,
    /// Dotted paths that leave an item out when they hold any value but null, such as a Copilot
    /// seat's `pending_cancellation_date`: a seat already on its way out is not access to manage.
    #[serde(default)]
    pub skip_when_set: Vec<String>,
}

/// How a list op walks pages. A walk that stops making progress (a page of users already read, a
/// cursor that does not move on, or fewer users than the reported total) is an error, never a
/// short list.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "style", rename_all = "snake_case", deny_unknown_fields)]
pub enum Paginate {
    /// `param` is the index of the first item: `first` is 1 for SCIM's `startIndex`, 0 for an offset.
    Offset {
        param: String,
        size_param: String,
        size: u32,
        first: u64,
        /// Dotted path to the total count, when the app reports one; saves the final empty page.
        #[serde(default)]
        total: Option<String>,
    },
    /// `param` is the page number, starting at `first`.
    Page {
        param: String,
        size_param: String,
        size: u32,
        first: u64,
        #[serde(default)]
        total: Option<String>,
    },
    /// The next page's cursor is read from the dotted path `next` and sent back as `param`.
    Cursor {
        param: String,
        next: String,
        #[serde(default)]
        size_param: Option<String>,
        #[serde(default)]
        size: Option<u32>,
        /// Dotted path to a has-more flag (GraphQL's `pageInfo.hasNextPage`). When set, the walk
        /// ends only when it is `false`; a missing flag, or `true` without a cursor, is an error.
        #[serde(default)]
        more: Option<String>,
    },
    /// The answer names the next page by URL at `path` (OData's `@odata.nextLink`); only its
    /// `param` query value (`$skiptoken`) is read and sent. The URL itself is never followed. No
    /// URL means the last page.
    NextUrl { path: String, param: String },
}

/// A value read from the app before an op runs: the `take` field of the one item in the `list` of a
/// GET op's answer that has every `where` field. No match, or more than one, sends nothing.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Lookup {
    pub op: String,
    pub list: String,
    #[serde(rename = "where", default)]
    pub matching: Map<String, Value>,
    pub take: String,
    /// Take the one item the read returns, with no `where`: for a read the request itself filters
    /// to the subject (Atlassian's directories for one account). None, or two or more, sends
    /// nothing, as for any lookup.
    #[serde(default)]
    pub single: bool,
}

/// How long an app may take to show a change it accepted. Atlassian's single-user read shows the
/// old status for a second or two after a suspend. The read-back is tried again, after `wait_ms`,
/// until it confirms or `tries` reads have not; only a read that disagrees, or finds nobody yet, is
/// tried again, never an error.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Settle {
    pub tries: u32,
    pub wait_ms: u64,
}

/// A precondition, evaluated against a named read op's extracted fields before mutating.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Guard {
    pub op: String,
    pub expect: Map<String, Value>,
}

/// The read-back contract: a fresh GET, never the mutation's own answer. The user is found by the
/// op's `id` (or, failing that, `user_name`), across every page when the read op is a list.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Verify {
    /// Require the user to be there with these fields. `{param}` placeholders in `expect` are
    /// filled from the op's context.
    Present { op: String, expect: Map<String, Value> },
    /// Require the user to be gone.
    /// Require the user to be gone. `by` names a value one of the op's lookups found (an invite's
    /// id) to find the item by, in place of the op's `id` or `user_name`.
    Absent {
        op: String,
        #[serde(default)]
        by: Option<String>,
    },
}

impl Verify {
    fn op(&self) -> &str {
        match self {
            Verify::Present { op, .. } | Verify::Absent { op, .. } => op,
        }
    }

    /// The context the read-back finds its subject with: by the `by` value when one is set, so an
    /// invite is confirmed gone by its own id, not by an email an accepted invite may share.
    fn subject_ctx(&self, op_name: &str, ctx: &Map<String, Value>) -> Result<Map<String, Value>, KeyholeError> {
        let Verify::Absent { by: Some(key), .. } = self else {
            return Ok(ctx.clone());
        };
        let id = ctx.get(key).filter(|v| scalar_string(v).is_some()).cloned().ok_or_else(|| KeyholeError::BadParam { op: op_name.to_string(), param: key.clone() })?;
        let mut subject = ctx.clone();
        subject.remove("user_name");
        subject.insert("id".into(), id);
        Ok(subject)
    }
}

impl OpSpec {
    /// The op's GraphQL operation, when it has a document that reads cleanly.
    fn graphql_operation(&self) -> Option<graphql::Operation> {
        self.request.graphql.as_ref().and_then(|g| graphql::parse(&g.query).ok())
    }

    /// Whether the op only reads: a `GET`, or a GraphQL `query`. Only a read may confirm a change,
    /// guard one or supply a lookup.
    fn is_read(&self) -> bool {
        match &self.request.graphql {
            Some(_) => self.graphql_operation().is_some_and(|o| o.kind == graphql::Kind::Query),
            None => self.request.method.eq_ignore_ascii_case("GET"),
        }
    }

    /// Whether the op changes state, and so must be confirmed by a read-back: a mutating method, or
    /// a GraphQL document that is not a plain `query`.
    fn changes_state(&self) -> bool {
        match &self.request.graphql {
            Some(_) => !self.is_read(),
            None => MUTATING.contains(&self.request.method.to_uppercase().as_str()),
        }
    }
}

impl Doorkey {
    /// The app's settings for this Doorkey's parameters, each present and valid for its kind;
    /// nothing undeclared is kept.
    pub fn checked_params(&self, given: &BTreeMap<String, String>) -> Result<BTreeMap<String, String>> {
        let mut out = BTreeMap::new();
        for p in &self.parameters {
            let label = p.name.replace('_', " ");
            match given.get(&p.name).map(|v| v.trim()) {
                Some(v) if p.kind.accepts(v) => {
                    out.insert(p.name.clone(), v.to_string());
                }
                Some(v) if !v.is_empty() => bail!("`{v}` is not a valid {label}"),
                _ => bail!("Fill in the {label}"),
            }
        }
        Ok(out)
    }

    /// The values an OAuth client-credentials Doorkey's credential is made of, in form order.
    pub fn credential_fields(&self) -> Option<Vec<String>> {
        match &self.auth {
            AuthSpec::OauthClientCredentials { fields, .. } => Some(oauth_field_names(fields).into_iter().map(str::to_string).collect()),
            _ => None,
        }
    }

    /// The base URL, once it passes the outbound rules every app URL does (public HTTPS outside
    /// dev mode) and is on one of the Doorkey's `hosts`. The errors are worded for the admin who
    /// typed the workspace URL.
    pub fn origin(&self, dev_mode: bool) -> Result<Url> {
        let base = Url::parse(&net::validate_base_url(&self.base_url, dev_mode)?)?;
        let host = base.host_str().unwrap_or_default();
        if !host_allowed(&self.hosts, host, dev_mode) {
            bail!("This app's credential may only be sent to {}, and {host} is not one of them", self.hosts.join(", "));
        }
        Ok(base)
    }

    /// Refuse a Doorkey that could not be run safely, before it is ever used.
    fn validate(&self) -> Result<()> {
        if self.hosts.is_empty() {
            bail!("a Doorkey must name the `hosts` its credential may be sent to");
        }
        for pattern in &self.hosts {
            host_pattern(pattern).with_context(|| format!("hosts entry `{pattern}`"))?;
        }
        if let Some(bad) = self.retry_statuses.iter().find(|s| !(400..600).contains(*s) || [401, 403, 404].contains(*s)) {
            bail!("retry_statuses may not include {bad}: only a status that means the app is briefly busy");
        }
        let mut param_names = HashSet::new();
        for p in &self.parameters {
            if !is_param(&p.name) || CONTEXT_KEYS.contains(&p.name.as_str()) || !param_names.insert(p.name.as_str()) {
                bail!("parameter `{}` must be a plain, distinct name that is not a context key", p.name);
            }
        }
        if let AuthSpec::OauthClientCredentials { token_url, grant_type, fields, scope, .. } = &self.auth {
            let in_path = token_url_fields(token_url);
            // Validated with each named field as a stand-in segment: the origin must be fixed.
            let probe = in_path.iter().fold(token_url.clone(), |u, f| u.replace(&format!("{{{f}}}"), "segment"));
            let url = Url::parse(&probe).with_context(|| format!("token_url `{token_url}`"))?;
            if !matches!(url.scheme(), "https" | "http") || url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() || url.query().is_some() || url.fragment().is_some() {
                bail!("token_url `{token_url}` must be a plain URL without credentials, query or fragment");
            }
            if token_url.split("://").nth(1).and_then(|rest| rest.split('/').next()).is_some_and(|host| host.contains('{')) {
                bail!("token_url `{token_url}` may name a credential field only in its path");
            }
            if grant_type.is_empty() || !grant_type.chars().all(|c| c.is_ascii_alphanumeric() || "_-.:".contains(c)) {
                bail!("grant_type `{grant_type}` is not a plain grant type name");
            }
            if scope.as_deref().is_some_and(|s| s.is_empty() || s.chars().any(char::is_control)) {
                bail!("scope must be a non-empty single line");
            }
            let mut names: HashSet<&str> = OAUTH_CLIENT_KEYS.into_iter().collect();
            for field in fields {
                if !is_param(field) || ["grant_type", "scope"].contains(&field.as_str()) || !names.insert(field) {
                    bail!("credential field `{field}` must be a plain, distinct name other than grant_type, scope, client_id and client_secret");
                }
            }
            if let Some(unknown) = in_path.iter().find(|f| !fields.contains(f)) {
                bail!("token_url names `{unknown}`, which is not one of the credential fields");
            }
        }
        for rule in &self.allow {
            known_method(&rule.method).and_then(|_| safe_template(&rule.path)).with_context(|| format!("allow rule {} {}", rule.method, rule.path))?;
        }
        for (name, value) in &self.headers {
            let lower = name.to_ascii_lowercase();
            let auth_header = matches!(&self.auth, AuthSpec::Header { name: a } if a.eq_ignore_ascii_case(name));
            if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') || RESERVED_HEADERS.contains(&lower.as_str()) || auth_header {
                bail!("header `{name}` may not be set by a Doorkey");
            }
            if value.is_empty() || !value.chars().all(|c| c.is_ascii_graphic() || c == ' ') || value.contains(['{', '}']) {
                bail!("header `{name}` must be a constant, printable value");
            }
        }
        for (name, op) in &self.ops {
            let method = known_method(&op.request.method).with_context(|| format!("op `{name}`"))?;
            safe_template(&op.request.path).with_context(|| format!("op `{name}`"))?;
            if let Some(g) = &op.request.graphql {
                self.validate_graphql(name, op, g, &method)?;
            }
            if op.changes_state() {
                let verify = op.verify.as_ref().with_context(|| format!("op `{name}` changes state but has no `verify` read-back"))?;
                if name == "create_group" {
                    self.read_group_op(verify.op()).with_context(|| format!("op `{name}` verify"))?;
                } else {
                    self.read_op(verify.op()).with_context(|| format!("op `{name}` verify"))?;
                }
            }
            for guard in &op.guard {
                self.read_op(&guard.op).with_context(|| format!("op `{name}` guard"))?;
            }
            for (key, l) in &op.lookup {
                if !is_param(key) || CONTEXT_KEYS.contains(&key.as_str()) {
                    bail!("op `{name}` looks up `{key}`, which is not a free parameter name");
                }
                if l.matching.is_empty() && !l.single {
                    bail!("op `{name}` looks up `{key}` without a `where`, which would take any item");
                }
                if l.single && !l.matching.is_empty() {
                    bail!("op `{name}` looks up `{key}` with both `single` and a `where`; use one");
                }
                match self.ops.get(&l.op) {
                    Some(read) if read.is_read() && read.lookup.is_empty() => {}
                    Some(_) => bail!("op `{name}` looks up `{key}` through `{}`, which must be a read (GET or GraphQL query) without lookups of its own", l.op),
                    None => bail!("op `{name}` looks up `{key}` through unknown op `{}`", l.op),
                }
            }
            if op.allow_pending && (name != "create_user" || !matches!(op.verify, Some(Verify::Present { .. }))) {
                bail!("op `{name}` sets `allow_pending`, which only `create_user` with a `present` read-back may do");
            }
            if op.extract.as_ref().is_some_and(|ex| ex.skip.iter().any(Map::is_empty)) {
                bail!("op `{name}` has an empty `skip` entry, which would leave out every user");
            }
            if let Some(Verify::Absent { by: Some(key), .. }) = &op.verify {
                if !op.lookup.contains_key(key) {
                    bail!("op `{name}` confirms by `{key}`, which none of its lookups provides");
                }
            }
            let params = self.op_params(op);
            let covered = match op.graphql_operation() {
                Some(g) => self.allow.iter().any(|r| r.covers_graphql(&method, &op.request.path, &params, &g.root_fields)),
                None => self.allow.iter().any(|r| r.covers(&method, &op.request.path, &params)),
            };
            if !covered {
                bail!("op `{name}` ({method} {}) is not covered by the allowlist", op.request.path);
            }
        }
        if let Some(settle) = &self.settle {
            if !(1..=10).contains(&settle.tries) || settle.wait_ms > 5000 {
                bail!("`settle` must try 1 to 10 times and wait at most 5000 ms between reads");
            }
        }
        if self.ops.get("withdraw_invite").is_some_and(|op| !matches!(op.verify, Some(Verify::Absent { .. }))) {
            bail!("op `withdraw_invite` must confirm with an `absent` read-back that the invite is gone");
        }
        if self.ops.get("list_users").and_then(|o| o.extract.as_ref()).and_then(|e| e.list.as_ref()).is_none() {
            bail!("a Doorkey needs a `list_users` op whose `extract` names the `list` field");
        }
        self.validate_groups()?;
        self.validate_membership()
    }

    /// An app either reads an active flag everywhere or only lists members. One that only lists
    /// members cannot confirm a suspend, so access is taken away by removing the member.
    fn validate_membership(&self) -> Result<()> {
        let extracts = || self.ops.iter().filter_map(|(name, op)| op.extract.as_ref().map(|ex| (name, ex)));
        if let Some((name, _)) = extracts().find(|(_, ex)| ex.active.is_none() && ex.active_inverted) {
            bail!("op `{name}` sets `active_inverted` without an `active` field");
        }
        if let Some((name, _)) = extracts().find(|(_, ex)| ex.active.is_none() && ex.active_when.is_some()) {
            bail!("op `{name}` sets `active_when` without an `active` field");
        }
        if let Some((name, _)) = extracts().find(|(_, ex)| ex.active_inverted && ex.active_when.is_some()) {
            bail!("op `{name}` sets both `active_inverted` and `active_when`; name the active value instead");
        }
        if let Some((name, _)) = extracts().find(|(_, ex)| ex.active_when.as_ref().is_some_and(|v| !(v.is_string() || v.is_number() || v.is_boolean()))) {
            bail!("op `{name}` sets `active_when` to something other than a string, number or boolean");
        }
        let flagged = self.has_active_flag();
        let invites = self.invite_reads();
        if let Some((name, _)) = extracts().find(|(name, ex)| ex.active.is_some() != flagged && !invites.contains(name.as_str())) {
            bail!("op `{name}` disagrees with `list_users` on whether the app has an `active` flag");
        }
        if flagged {
            return Ok(());
        }
        for op in ["deactivate_user", "reactivate_user"] {
            if self.ops.contains_key(op) {
                bail!("op `{op}` cannot be confirmed without an `active` flag; an app that only lists members removes them with `delete_user`");
            }
        }
        if !self.ops.contains_key("delete_user") {
            bail!("an app without an `active` flag needs a `delete_user` op, the only way to take access away");
        }
        for (name, op) in &self.ops {
            let verify = match &op.verify {
                Some(Verify::Present { expect, .. }) => Some(expect),
                _ => None,
            };
            if verify.into_iter().chain(op.guard.iter().map(|g| &g.expect)).any(|e| e.contains_key("active")) {
                bail!("op `{name}` expects an `active` value, which this app does not have");
            }
        }
        Ok(())
    }

    /// The read ops used only to find and confirm a withdrawn invite, never to read a user. An app
    /// whose invites are a list of their own (Linear's) has no active flag on an invite even when
    /// its members have one, so these need not agree with `list_users` on it.
    fn invite_reads(&self) -> HashSet<&str> {
        let Some(withdraw) = self.ops.get("withdraw_invite") else {
            return HashSet::new();
        };
        let mut reads: HashSet<&str> = withdraw.lookup.values().map(|l| l.op.as_str()).chain(withdraw.verify.as_ref().map(Verify::op)).collect();
        for (_, op) in self.ops.iter().filter(|(name, _)| name.as_str() != "withdraw_invite") {
            for used in op.verify.iter().map(Verify::op).chain(op.guard.iter().map(|g| g.op.as_str())).chain(op.lookup.values().map(|l| l.op.as_str())) {
                reads.remove(used);
            }
        }
        reads.remove("list_users");
        reads.remove("find_user");
        reads
    }

    /// Whether the app records an active flag. Without one it only lists members.
    pub fn has_active_flag(&self) -> bool {
        self.ops.get("list_users").and_then(|o| o.extract.as_ref()).is_some_and(|ex| ex.active.is_some())
    }

    /// Whether an account can be suspended, and so kept while access is off. Otherwise a leaver is
    /// removed.
    pub fn can_suspend(&self) -> bool {
        self.ops.contains_key("deactivate_user")
    }

    /// The query parameter names an op can send: its own and its paging ones.
    fn op_params(&self, op: &OpSpec) -> Vec<String> {
        let mut params: Vec<String> = op.request.query.keys().cloned().collect();
        // A GraphQL op pages through its variables, which the signed document declares.
        let paging = if op.request.graphql.is_some() { None } else { op.paginate.as_ref() };
        match paging {
            Some(Paginate::Offset { param, size_param, .. } | Paginate::Page { param, size_param, .. }) => params.extend([param.clone(), size_param.clone()]),
            Some(Paginate::Cursor { param, size_param, .. }) => params.extend(std::iter::once(param.clone()).chain(size_param.clone())),
            Some(Paginate::NextUrl { param, .. }) => params.push(param.clone()),
            None => {}
        }
        params
    }

    /// A read-back or guard must name a read op (GET or GraphQL query) that knows where the user
    /// fields are.
    fn read_op(&self, name: &str) -> Result<()> {
        match self.ops.get(name) {
            Some(op) if op.is_read() && op.extract.is_some() => Ok(()),
            Some(_) => bail!("`{name}` must be a read (GET or GraphQL query) op with an `extract` block"),
            None => bail!("unknown op `{name}`"),
        }
    }

    /// Whether the app's groups can be pushed: a group list, a member list, and adding and removing
    /// members. Creating a group is optional.
    pub fn supports_groups(&self) -> bool {
        self.ops.get("list_groups").is_some_and(|o| o.groups.is_some()) && ["list_group_members", "add_group_member", "remove_group_member"].iter().all(|o| self.ops.contains_key(*o))
    }

    /// Group push ops must come as a set, each read back the way it can be confirmed: a member
    /// change through the member list, a new group through the group list.
    fn validate_groups(&self) -> Result<()> {
        if !GROUP_OPS.iter().any(|o| self.ops.contains_key(*o)) {
            return Ok(());
        }
        if !self.supports_groups() {
            bail!("group push needs `list_groups` with a `groups` block, `list_group_members`, `add_group_member` and `remove_group_member`");
        }
        let members = &self.ops["list_group_members"];
        if !members.request.method.eq_ignore_ascii_case("GET") || members.extract.as_ref().and_then(|e| e.list.as_ref()).is_none() {
            bail!("`list_group_members` must be a GET op whose `extract` names the `list` field");
        }
        for op in ["add_group_member", "remove_group_member"] {
            if self.ops[op].verify.as_ref().map(Verify::op) != Some("list_group_members") {
                bail!("op `{op}` must be read back through `list_group_members`");
            }
        }
        if let Some(create) = self.ops.get("create_group") {
            match &create.verify {
                Some(Verify::Present { op, .. }) if op == "list_groups" => {}
                _ => bail!("op `create_group` must be read back as `present` through `list_groups`"),
            }
        }
        Ok(())
    }

    fn read_group_op(&self, name: &str) -> Result<()> {
        match self.ops.get(name) {
            Some(op) if op.request.method.eq_ignore_ascii_case("GET") && op.groups.is_some() => Ok(()),
            Some(_) => bail!("`{name}` must be a GET op with a `groups` block"),
            None => bail!("unknown op `{name}`"),
        }
    }
}

impl Doorkey {
    /// A GraphQL op is a `POST` of one signed document whose every variable it declares, paging
    /// included; nothing else of the request may be set, so nothing but its variables varies.
    fn validate_graphql(&self, name: &str, op: &OpSpec, g: &GraphqlSpec, method: &str) -> Result<()> {
        if method != "POST" || op.request.body.is_some() || !op.request.query.is_empty() {
            bail!("op `{name}` is a GraphQL op, so it must be a POST with no `body` or `query` of its own");
        }
        let operation = graphql::parse(&g.query).with_context(|| format!("op `{name}`"))?;
        let mut needed: Vec<&String> = g.variables.keys().collect();
        match &op.paginate {
            None => {}
            Some(Paginate::Offset { param, size_param, .. } | Paginate::Page { param, size_param, .. }) => needed.extend([param, size_param]),
            Some(Paginate::Cursor { param, size_param, .. }) => needed.extend(std::iter::once(param).chain(size_param.as_ref())),
            Some(Paginate::NextUrl { .. }) => bail!("op `{name}` is a GraphQL op, which cannot page by a next URL"),
        }
        if let Some(var) = needed.into_iter().find(|v| !operation.variables.contains(v)) {
            bail!("op `{name}` sets GraphQL variable `{var}`, which its document does not declare");
        }
        if g.errors_at.iter().any(String::is_empty) {
            bail!("op `{name}` has an empty `errors_at` path");
        }
        Ok(())
    }
}

impl AllowRule {
    /// Does this rule let `method` reach `path` (a template or a path as sent) with these
    /// parameter names? Never for a GraphQL rule: its endpoint takes only the listed operations.
    fn covers(&self, method: &str, path: &str, params: &[String]) -> bool {
        self.graphql.is_none() && self.reaches(method, path, params)
    }

    /// Does this rule let a GraphQL operation selecting `root_fields` reach `path`?
    fn covers_graphql(&self, method: &str, path: &str, params: &[String], root_fields: &[String]) -> bool {
        self.graphql.as_ref().is_some_and(|allowed| root_fields.iter().all(|f| allowed.contains(f))) && self.reaches(method, path, params)
    }

    fn reaches(&self, method: &str, path: &str, params: &[String]) -> bool {
        self.method.eq_ignore_ascii_case(method)
            && path_matches(&self.path, path)
            && self.params.as_ref().is_none_or(|allowed| params.iter().all(|p| allowed.contains(p)))
    }
}

fn known_method(method: &str) -> Result<String> {
    let m = method.to_uppercase();
    if m != "GET" && !MUTATING.contains(&m.as_str()) {
        bail!("unsupported HTTP method `{method}`");
    }
    Ok(m)
}

/// A path template must be a plain absolute path: no query or fragment (use `query`), and no `.`
/// or `..` segments, which URL normalisation would resolve to a different endpoint.
fn safe_template(path: &str) -> Result<()> {
    if !path.starts_with('/') || path.contains(['?', '#', '\\']) || path.split('/').any(|s| s == "." || s == "..") {
        bail!("path `{path}` must start with / and have no query, fragment or dot segments");
    }
    Ok(())
}

/// A `hosts` entry is `*`, a lowercase host name, or `*.` and a host name with at least one dot,
/// so `*.com` cannot stand in for every host.
fn host_pattern(pattern: &str) -> Result<()> {
    let name = pattern.strip_prefix("*.").unwrap_or(pattern);
    let plain = !name.is_empty() && name.split('.').all(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'));
    if pattern != "*" && !(plain && (name.len() == pattern.len() || name.contains('.'))) {
        bail!("must be `*`, a lowercase host name, or `*.` followed by a domain such as `*.example.com`");
    }
    Ok(())
}

/// Is `host` one of the Doorkey's `hosts`? `*.example.com` matches any subdomain of example.com,
/// not example.com itself; `*` matches any host, and only in dev mode.
fn host_allowed(patterns: &[String], host: &str, dev_mode: bool) -> bool {
    let host = host.to_ascii_lowercase();
    patterns.iter().any(|p| match p.strip_prefix("*.") {
        _ if p == "*" => dev_mode,
        Some(domain) => host.strip_suffix(domain).is_some_and(|sub| sub.len() > 1 && sub.ends_with('.')),
        None => host == *p,
    })
}

/// Refuse a credential the Keyhole could not send intact, before it is stored or used. The errors
/// name what is missing and never echo a value.
fn check_secret(auth: &AuthSpec, secret: &str) -> Result<()> {
    let header_safe = |v: &str| !v.is_empty() && !v.chars().any(char::is_control);
    match auth {
        AuthSpec::Bearer | AuthSpec::Header { .. } => {
            if !header_safe(secret) {
                bail!("The credential is empty or contains line breaks");
            }
        }
        AuthSpec::OauthClientCredentials { token_url, fields, credentials_in_body, .. } => {
            let cred: Map<String, Value> = serde_json::from_str(secret).map_err(|_| anyhow!("The OAuth credential must be a JSON object holding its {}", oauth_field_names(fields).join(", ")))?;
            for name in oauth_field_names(fields) {
                if !cred.get(name).and_then(Value::as_str).is_some_and(|v| header_safe(v) && v.trim() == v) {
                    bail!("The OAuth credential has no usable `{name}`");
                }
            }
            for name in token_url_fields(token_url) {
                if !cred.get(&name).and_then(Value::as_str).is_some_and(token_segment_safe) {
                    bail!("The OAuth credential's `{name}` must be a plain id or domain");
                }
            }
            // HTTP Basic auth joins the two with a colon, so a colon in the id would move it.
            if !credentials_in_body && cred.get("client_id").and_then(Value::as_str).is_some_and(|id| id.contains(':')) {
                bail!("The OAuth `client_id` cannot contain a colon");
            }
        }
    }
    Ok(())
}

/// The token URL with each credential field its path names filled in, as one plain segment.
fn oauth_token_url(token_url: &str, secret: &str) -> Result<String> {
    let cred: Map<String, Value> = serde_json::from_str(secret).map_err(|_| anyhow!("The OAuth credential must be a JSON object"))?;
    token_url_fields(token_url).iter().try_fold(token_url.to_string(), |url, name| {
        let value = cred.get(name).and_then(Value::as_str).filter(|v| token_segment_safe(v)).ok_or_else(|| anyhow!("The OAuth credential's `{name}` must be a plain id or domain"))?;
        Ok(url.replace(&format!("{{{name}}}"), value))
    })
}

/// Every value an OAuth client-credentials secret must hold, in the order an admin enters them.
pub fn oauth_field_names(fields: &[String]) -> Vec<&str> {
    fields.iter().map(String::as_str).chain(OAUTH_CLIENT_KEYS).collect()
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

/// A record of one change. It is only produced after the read-back passed, or, when `pending`, after
/// the app accepted a change it does not show yet. It is signed with an Ed25519 key only the
/// Keyhole holds, so a record edited after the fact, or forged without the key, fails
/// [`verify_evidence`]; anyone with the public key can check it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// The workspace and app the change was made for, and the hash of the app's previous record
    /// ([`evidence_hash`]). Signed with the rest, so a record cannot be moved to another app, or
    /// dropped from or reordered in the chain, unnoticed. Empty outside a sync run.
    #[serde(default)]
    pub tenant: String,
    #[serde(default)]
    pub app: String,
    #[serde(default)]
    pub prev: String,
    /// The Doorkey's app identifier, or `"scim"` for native SCIM.
    pub doorkey: String,
    pub version: u32,
    pub op: String,
    pub method: String,
    pub path: String,
    /// The app's id for the user the change was about.
    pub subject_id: String,
    /// The user's name in the app, when the read-back or the request knew it.
    pub subject_user_name: String,
    pub request_fingerprint: String,
    /// HTTP status of the change, when the transport reports it (the SCIM client does not).
    pub status: Option<u16>,
    /// The read op whose fresh answer confirmed the change, or, when `pending`, could not see it yet.
    pub verified_by: String,
    /// The app accepted the change but does not show it yet (an invite not yet accepted).
    pub pending: bool,
    pub at: String,
    /// The signer's public key (base64 Ed25519), and its signature over every other field.
    pub key: String,
    pub signature: String,
}

/// Signs evidence records with an Ed25519 key derived from `seed` under its own label, so it is
/// independent of every other key derived from the seed. Only the holder of the seed can make a
/// record; anyone with [`Sealer::public_key`] can check one.
#[derive(Clone)]
pub struct Sealer {
    pair: std::sync::Arc<ring::signature::Ed25519KeyPair>,
    public: String,
}

impl Sealer {
    pub fn new(seed: &Key) -> Self {
        use ring::signature::KeyPair;
        let pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed.derive("doorkey-evidence").bytes()).expect("a 32-byte seed is a valid Ed25519 key");
        let public = B64.encode(pair.public_key().as_ref());
        Self { pair: std::sync::Arc::new(pair), public }
    }

    /// The key that checks this sealer's records (base64 Ed25519).
    pub fn public_key(&self) -> &str {
        &self.public
    }

    pub fn seal(&self, mut evidence: Evidence) -> Evidence {
        evidence.key = self.public.clone();
        evidence.signature = format!("ed25519:{}", B64.encode(self.pair.sign(&signed_bytes(&evidence)).as_ref()));
        evidence
    }
}

/// True when `evidence` is exactly what one of the `trusted` public keys signed.
pub fn verify_evidence(evidence: &Evidence, trusted: &[String]) -> bool {
    let Some(signature) = evidence.signature.strip_prefix("ed25519:").and_then(|s| B64.decode(s).ok()) else {
        return false;
    };
    trusted.contains(&evidence.key)
        && B64.decode(&evidence.key).is_ok_and(|key| ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key).verify(&signed_bytes(evidence), &signature).is_ok())
}

/// The hash the next record of the same app chains to: SHA-256 of the whole record, signature
/// included, as it is stored.
pub fn evidence_hash(evidence: &Evidence) -> String {
    crypto::sha256_hex(serde_json::to_string(evidence).expect("evidence serialises").as_bytes())
}

/// What a signature covers: every field but the signature, as JSON with sorted keys.
fn signed_bytes(evidence: &Evidence) -> Vec<u8> {
    let mut body = serde_json::to_value(evidence).expect("evidence serialises");
    if let Some(fields) = body.as_object_mut() {
        fields.remove("signature");
    }
    body.to_string().into_bytes()
}

/// What a Keyhole change returns: the user as the read-back saw it (for a `present` verify), sealed
/// evidence, and whether the change is still pending (see [`OpSpec::allow_pending`]).
#[derive(Debug, Clone)]
pub struct RunResult {
    pub user: Option<TargetUser>,
    pub evidence: Evidence,
    pub pending: bool,
}

/// What a read-back found.
enum ReadBack {
    /// The change shows: the user as read for a `present` verify, nothing for an `absent` one.
    Confirmed(Option<TargetUser>),
    /// A `present` verify found no such user at all.
    NotYet,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// What went wrong in the Keyhole. Serialisable, so a Keyhole service can hand it back as it is and
/// the sync run still knows a bad session (which stops the run) from a change that failed.
#[derive(Debug, thiserror::Error, Serialize, Deserialize)]
pub enum KeyholeError {
    /// The spec, the app's address or the shape of the credential is unusable; nothing was sent.
    #[error("{0}")]
    Setup(String),
    /// The OAuth token endpoint refused the client credentials, or answered without a token.
    #[error("the app refused the OAuth client credentials (HTTP {0}{why}); check the app's client id, secret and tenant", why = explained(.1))]
    TokenRefused(u16, Option<String>),
    /// The saved credential cannot be opened by this Keyhole: sealed by another one, or for
    /// another app.
    #[error("the saved credential cannot be opened by this Keyhole ({0}); connect it again")]
    Sealed(String),
    #[error("the Keyhole service cannot be reached: {0}")]
    Unavailable(String),
    #[error("unknown Doorkey op `{0}`")]
    UnknownOp(String),
    #[error("Doorkey op `{0}` has no `verify` read-back, so it cannot be run as a change")]
    NoVerify(String),
    #[error("`{op}` has no usable value for `{{{param}}}` (missing, empty, `.` or `..`)")]
    BadParam { op: String, param: String },
    #[error("request outside the Doorkey allowlist was refused: {0} {1}")]
    NotAllowed(String, String),
    #[error("refused: the request would leave the Doorkey origin ({0})")]
    OffHost(String),
    #[error("refused: the request path `{0}` changes when normalised")]
    UnsafePath(String),
    #[error("guard failed before `{0}`: the app no longer matches the expected state")]
    GuardFailed(String),
    #[error("read-back failed after `{0}`: the change could not be confirmed")]
    VerifyFailed(String),
    #[error("the app's response for `{op}` no longer matches the recorded shape; Doorkey `{doorkey}` v{version} needs re-recording")]
    ShapeChanged { doorkey: String, version: u32, op: String },
    /// The status, the path, and the app's own explanation when its answer had one.
    #[error("the app returned HTTP {0} for `{1}`{why}", why = explained(.2))]
    Http(u16, String, Option<String>),
    #[error("the app reported a failure for `{op}`: {error}")]
    NotOk { op: String, error: String },
    /// `seen` is what the app listed instead, by the fields the lookup matches on.
    #[error("`{op}` needs exactly one `{key}` from the app, and the app listed {found} (it has: {seen})")]
    LookupFailed { op: String, key: String, found: usize, seen: String },
    #[error("the credential for `{0}` is not the expected JSON of its fields")]
    BadCredential(String),
    #[error("the app's answer to `{0}` is not JSON (a refused sign-in often gets a login page)")]
    NotJson(String),
    #[error("the app's answer to `{op}` has no `{field}`")]
    MissingField { op: String, field: String },
    #[error("`{0}` returned a different user than the one asked for")]
    WrongSubject(String),
    #[error("`{0}` still had more pages after {max}", max = MAX_PAGES)]
    TooManyPages(String),
    #[error("`{op}` could not be read in full: {why}")]
    Incomplete { op: String, why: String },
    #[error("could not reach the app: {0}")]
    Transport(String),
}

fn missing(op: &str, field: &str) -> KeyholeError {
    KeyholeError::MissingField { op: op.into(), field: field.into() }
}

// ---------------------------------------------------------------------------
// Keyhole: the only holder of the app credential
// ---------------------------------------------------------------------------

/// One HTTP exchange as the Keyhole saw it.
struct Reply {
    status: u16,
    body: Value,
    method: String,
    path: String,
}

/// Runs one app's Doorkey. Holds the live credential; nothing else in the process does.
pub struct Keyhole {
    http: reqwest::Client,
    doorkey: Doorkey,
    secret: Zeroizing<String>,
    sealer: Sealer,
    base: Url,
    base_path: String,
    stamp: Stamp,
    /// For OAuth client credentials: the access token last fetched and when to fetch a new one.
    token: tokio::sync::Mutex<Option<(Zeroizing<String>, std::time::Instant)>>,
    /// The app's settings for the Doorkey's declared parameters.
    params: Map<String, Value>,
}

/// Where a change belongs, written into its evidence: the workspace, the app, and the hash of the
/// app's previous record.
#[derive(Default)]
struct Stamp {
    tenant: String,
    app: String,
    prev: String,
}

impl Keyhole {
    /// The Keyhole builds its own HTTP client with the same outbound rules as SCIM apps: public
    /// HTTPS only and no redirects (a 307 would otherwise replay a change to a path the allowlist
    /// never saw). `dev_mode` relaxes them exactly as it does for SCIM. The base URL must be on one
    /// of the Doorkey's `hosts`, and the credential must be one it can send intact.
    pub fn new(doorkey: Doorkey, secret: impl Into<String>, sealer: Sealer, dev_mode: bool) -> Result<Self> {
        Self::with_client(doorkey, secret, sealer, dev_mode, net::outbound_client(dev_mode))
    }

    /// As [`Keyhole::new`], sharing an HTTP client built by [`net::outbound_client`].
    pub fn with_client(doorkey: Doorkey, secret: impl Into<String>, sealer: Sealer, dev_mode: bool, http: reqwest::Client) -> Result<Self> {
        doorkey.validate().with_context(|| format!("Doorkey {} v{} is invalid", doorkey.doorkey, doorkey.version))?;
        let base = doorkey.origin(dev_mode)?;
        let secret = Zeroizing::new(secret.into());
        check_secret(&doorkey.auth, &secret)?;
        let base_path = base.path().trim_end_matches('/').to_string();
        // The token endpoint follows the same outbound rules as the app's own URL.
        if let AuthSpec::OauthClientCredentials { token_url, .. } = &doorkey.auth {
            net::validate_base_url(&oauth_token_url(token_url, &secret)?, dev_mode).context("token_url")?;
        }
        Ok(Self { http, doorkey, secret, sealer, base, base_path, stamp: Stamp::default(), token: tokio::sync::Mutex::default(), params: Map::new() })
    }

    /// Record the workspace, the app and the app's last evidence hash in the evidence of the
    /// change this Keyhole makes.
    /// The app's settings for the Doorkey's parameters. Every declared one must be given, valid for
    /// its kind; anything else is refused.
    pub fn with_params(mut self, given: &BTreeMap<String, String>) -> Result<Self> {
        self.params = self.doorkey.checked_params(given)?.into_iter().map(|(k, v)| (k, json!(v))).collect();
        Ok(self)
    }

    pub fn stamped(mut self, tenant: &str, app: &str, prev: &str) -> Self {
        self.stamp = Stamp { tenant: tenant.into(), app: app.into(), prev: prev.into() };
        self
    }

    pub fn doorkey(&self) -> &Doorkey {
        &self.doorkey
    }

    /// Every member the app lists, read in full or not at all.
    pub async fn list_users(&self) -> Result<Vec<TargetUser>, KeyholeError> {
        let ex = extract_of("list_users", self.op("list_users")?)?;
        let users = self.list_items("list_users", &Map::new()).await?;
        users.iter().map(|u| user_from("list_users", ex, u)).collect()
    }

    /// Create (or invite) a user. Confirmed once a separate read sees them, active; pending when
    /// the app takes the request but lists the user only later.
    pub async fn create_user(&self, user_name: &str, given: &str, family: &str, email: &str) -> Result<Created, KeyholeError> {
        let out = self.run("create_user", &create_ctx(user_name, given, family, email)).await?;
        if out.pending {
            return Ok(Created::Pending(PendingCreate {
                user_name: user_name.into(),
                given: given.into(),
                family: family.into(),
                email: email.into(),
                since: out.evidence.at.clone(),
                evidence: out.evidence,
            }));
        }
        let user = out.user.ok_or_else(|| KeyholeError::VerifyFailed("create_user".into()))?;
        Ok(Created::Confirmed(user, out.evidence))
    }

    pub async fn set_active(&self, id: &str, active: bool) -> Result<Evidence, KeyholeError> {
        let op = if active { "reactivate_user" } else { "deactivate_user" };
        let ctx = Map::from_iter([("id".into(), json!(id)), ("active".into(), json!(active))]);
        Ok(self.run(op, &ctx).await?.evidence)
    }

    pub async fn delete_user(&self, id: &str) -> Result<Evidence, KeyholeError> {
        let ctx = Map::from_iter([("id".into(), json!(id))]);
        Ok(self.run("delete_user", &ctx).await?.evidence)
    }

    /// Withdraw the pending invite of someone who left before accepting it, so it can no longer be
    /// accepted and stops holding a seat where the app counts one. The op finds the invite by email
    /// (a `lookup`); no pending invite for them is [`KeyholeError::LookupFailed`] with nothing found.
    pub async fn withdraw_invite(&self, user_name: &str, email: &str) -> Result<Evidence, KeyholeError> {
        let ctx = Map::from_iter([("user_name".into(), json!(user_name)), ("email".into(), json!(email))]);
        Ok(self.run("withdraw_invite", &ctx).await?.evidence)
    }

    /// Every group the app lists, read in full or not at all.
    pub async fn list_groups(&self) -> Result<Vec<TargetGroup>, KeyholeError> {
        let items = self.group_items("list_groups", &Map::new()).await?;
        let ex = self.op("list_groups")?.groups.as_ref().ok_or_else(|| missing("list_groups", "groups"))?;
        items.iter().map(|g| group_from("list_groups", ex, g)).collect()
    }

    /// The members of one of the app's groups, read in full or not at all.
    pub async fn group_members(&self, group_id: &str) -> Result<Vec<TargetUser>, KeyholeError> {
        let ex = extract_of("list_group_members", self.op("list_group_members")?)?;
        let ctx = Map::from_iter([("group_id".into(), json!(group_id))]);
        let users = self.list_items("list_group_members", &ctx).await?;
        users.iter().map(|u| user_from("list_group_members", ex, u)).collect()
    }

    /// Add a member to a group, confirmed by the group's member list.
    pub async fn add_group_member(&self, group_id: &str, id: &str) -> Result<Evidence, KeyholeError> {
        let ctx = Map::from_iter([("group_id".into(), json!(group_id)), ("id".into(), json!(id))]);
        Ok(self.run("add_group_member", &ctx).await?.evidence)
    }

    /// Remove a member from a group, confirmed by the group's member list.
    pub async fn remove_group_member(&self, group_id: &str, id: &str) -> Result<Evidence, KeyholeError> {
        let ctx = Map::from_iter([("group_id".into(), json!(group_id)), ("id".into(), json!(id))]);
        Ok(self.run("remove_group_member", &ctx).await?.evidence)
    }

    /// Create a group, confirmed once the group list shows exactly one group by that name.
    pub async fn create_group(&self, name: &str) -> Result<(TargetGroup, Evidence), KeyholeError> {
        let op_name = "create_group";
        let op = self.op(op_name)?;
        let Some(Verify::Present { op: read, expect }) = op.verify.as_ref() else {
            return Err(KeyholeError::NoVerify(op_name.to_string()));
        };
        // The name is also the record's subject, as an email is for a user.
        let ctx = Map::from_iter([("name".into(), json!(name)), ("user_name".into(), json!(name))]);
        let ctx = &self.with_lookups(op_name, op, &ctx).await?;
        let reply = self.send(op_name, op, ctx, &[]).await?;
        self.ensure_success(&reply)?;
        self.fingerprint_guard(op_name, op, &reply.body)?;
        let ex = self.op(read)?.groups.as_ref().ok_or_else(|| missing(read, "groups"))?;
        let want = render_map(expect, ctx).map_err(|param| KeyholeError::BadParam { op: op_name.to_string(), param })?;
        let (tries, wait) = self.doorkey.settle.as_ref().map_or((1, 0), |s| (s.tries.max(1), s.wait_ms));
        let mut attempt = 1;
        let group = loop {
            let items = self.group_items(read, ctx).await?;
            let found: Vec<&Value> = items.iter().filter(|g| group_matches(ex, g, &want)).collect();
            if let [only] = found.as_slice() {
                break group_from(read, ex, only)?;
            }
            // Two groups by that name is not something waiting can fix.
            if found.len() > 1 || attempt >= tries {
                return Err(KeyholeError::VerifyFailed(op_name.to_string()));
            }
            attempt += 1;
            tokio::time::sleep(std::time::Duration::from_millis(wait)).await;
        };
        let mut vctx = ctx.clone();
        vctx.insert("id".into(), json!(group.id));
        let evidence = self.evidence(op_name, op, &vctx, (reply.method, reply.path, Some(reply.status)), None, false);
        Ok((group, evidence))
    }

    /// Every item of a groups op's list, across all its pages.
    async fn group_items(&self, op_name: &str, ctx: &Map<String, Value>) -> Result<Vec<Value>, KeyholeError> {
        let op = self.op(op_name)?;
        let ex = op.groups.as_ref().ok_or_else(|| missing(op_name, "groups"))?;
        self.walk(op_name, op, ctx, &ex.list, &ex.id, |_| false).await
    }

    /// Make one change end to end: guards, request, read-back, sealed evidence. Nothing is
    /// returned as done unless a fresh read confirms it; an `allow_pending` op whose user does not
    /// show yet is returned with `pending` set.
    pub async fn run(&self, op_name: &str, ctx: &Map<String, Value>) -> Result<RunResult, KeyholeError> {
        let op = self.op(op_name)?;
        let verify = op.verify.as_ref().ok_or_else(|| KeyholeError::NoVerify(op_name.to_string()))?;
        // The app's settings are there for every change; their names never clash with the run's own.
        let mut ctx = ctx.clone();
        for (k, v) in &self.params {
            ctx.entry(k.clone()).or_insert_with(|| v.clone());
        }
        let ctx = &self.with_lookups(op_name, op, &ctx).await?;

        for guard in &op.guard {
            if self.check(&guard.op, ctx, &guard.expect).await?.is_none() {
                return Err(KeyholeError::GuardFailed(op_name.to_string()));
            }
        }

        // A removal's read-back finds nobody, so its record names the user from the app's own
        // answer just before the change.
        let before = match verify {
            Verify::Absent { op: read, .. } => match self.find_subject(read, &verify.subject_ctx(op_name, ctx)?).await? {
                Some(found) => Some(user_from(read, extract_of(read, self.op(read)?)?, &found)?),
                None => None,
            },
            Verify::Present { .. } => None,
        };

        let reply = self.send(op_name, op, ctx, &[]).await?;
        self.ensure_success(&reply)?;
        self.fingerprint_guard(op_name, op, &reply.body)?;

        // When this op created the user, read back by the id the app just assigned.
        let mut vctx = ctx.clone();
        if let Some(id) = op.extract.as_ref().and_then(|ex| field_string(&reply.body, &ex.id)) {
            vctx.entry("id").or_insert(Value::String(id));
        }
        let (user, pending) = match self.settled_read_back(op_name, verify, &vctx).await? {
            ReadBack::Confirmed(user) => (user, false),
            ReadBack::NotYet if op.allow_pending => (None, true),
            ReadBack::NotYet => return Err(KeyholeError::VerifyFailed(op_name.to_string())),
        };
        let evidence = self.evidence(op_name, op, &vctx, (reply.method, reply.path, Some(reply.status)), user.as_ref().or(before.as_ref()), pending);
        Ok(RunResult { user, evidence, pending })
    }

    /// The op's context with every value it looks up from the app added.
    async fn with_lookups(&self, op_name: &str, op: &OpSpec, ctx: &Map<String, Value>) -> Result<Map<String, Value>, KeyholeError> {
        let mut ctx = ctx.clone();
        for (key, l) in &op.lookup {
            // Every page: the one item may be anywhere in the list.
            let items = self.walk(&l.op, self.op(&l.op)?, &ctx, &l.list, &l.take, |_| false).await?;
            // A `where` value may name the subject (`"email": "{user_name}"`, to find someone's
            // invite); such a value matches in any case, as email addresses do.
            let wants = render_map(&l.matching, &ctx).map_err(|param| KeyholeError::BadParam { op: op_name.to_string(), param })?;
            let found: Vec<&Value> = items
                .iter()
                .filter(|item| {
                    wants.iter().all(|(path, want)| {
                        let templated = l.matching.get(path).and_then(Value::as_str).is_some_and(|t| t.contains('{'));
                        match (lookup(item, path), want) {
                            (Some(Value::String(have)), Value::String(want)) if templated => have.eq_ignore_ascii_case(want),
                            (have, want) => have == Some(want),
                        }
                    })
                })
                .collect();
            let [item] = found.as_slice() else {
                // What the app has, by the fields the lookup matches on, so a renamed role shows.
                let seen: Vec<String> = items
                    .iter()
                    .take(30)
                    .map(|item| l.matching.keys().map(|path| lookup(item, path).map_or("-".to_string(), |v| v.as_str().map_or(v.to_string(), str::to_string))).collect::<Vec<_>>().join("/"))
                    .collect();
                return Err(KeyholeError::LookupFailed { op: op_name.to_string(), key: key.clone(), found: found.len(), seen: if seen.is_empty() { "nothing".into() } else { seen.join(", ") } });
            };
            let value = lookup(item, &l.take).filter(|v| !v.is_null()).cloned().ok_or_else(|| missing(&l.op, &l.take))?;
            ctx.insert(key.clone(), value);
        }
        Ok(ctx)
    }

    fn op<'a>(&'a self, name: &str) -> Result<&'a OpSpec, KeyholeError> {
        self.doorkey.ops.get(name).ok_or_else(|| KeyholeError::UnknownOp(name.to_string()))
    }

    /// The read-back, tried again as the Doorkey's `settle` allows while the app has not caught up:
    /// a read that disagrees or finds nobody yet. An error from the read itself is never retried.
    async fn settled_read_back(&self, op_name: &str, verify: &Verify, ctx: &Map<String, Value>) -> Result<ReadBack, KeyholeError> {
        let (tries, wait) = self.doorkey.settle.as_ref().map_or((1, 0), |s| (s.tries.max(1), s.wait_ms));
        let mut attempt = 1;
        loop {
            let read = self.read_back(op_name, verify, ctx).await;
            if attempt >= tries || !matches!(read, Ok(ReadBack::NotYet) | Err(KeyholeError::VerifyFailed(_))) {
                return read;
            }
            attempt += 1;
            tokio::time::sleep(std::time::Duration::from_millis(wait)).await;
        }
    }

    /// Run a change's read-back. A user who is there but not as the change left them is a failure,
    /// never pending: only a user the app does not show at all can be waiting.
    async fn read_back(&self, op_name: &str, verify: &Verify, ctx: &Map<String, Value>) -> Result<ReadBack, KeyholeError> {
        let failed = || KeyholeError::VerifyFailed(op_name.to_string());
        match verify {
            Verify::Present { op: read, expect } => match self.find_subject(read, ctx).await? {
                None => Ok(ReadBack::NotYet),
                Some(found) => self.matching(read, ctx, expect, &found)?.map(|user| ReadBack::Confirmed(Some(user))).ok_or_else(failed),
            },
            Verify::Absent { op: read, .. } => match self.find_subject(read, &verify.subject_ctx(op_name, ctx)?).await? {
                Some(_) => Err(failed()),
                None => Ok(ReadBack::Confirmed(None)),
            },
        }
    }

    /// Seal the record of a change. `sent` is the method, path and status of the request that made
    /// it.
    fn evidence(&self, op_name: &str, op: &OpSpec, ctx: &Map<String, Value>, sent: (String, String, Option<u16>), user: Option<&TargetUser>, pending: bool) -> Evidence {
        let (method, path, status) = sent;
        self.sealer.seal(Evidence {
            doorkey: self.doorkey.doorkey.clone(),
            version: self.doorkey.version,
            op: op_name.to_string(),
            method,
            path,
            subject_id: user.map(|u| u.id.clone()).or_else(|| ctx_string(ctx, "id")).unwrap_or_default(),
            subject_user_name: user.map(|u| u.user_name.clone()).or_else(|| ctx_string(ctx, "user_name")).unwrap_or_default(),
            // A GraphQL op's path is the same for every op, so its signed document stands in for it.
            request_fingerprint: match &op.request.graphql {
                Some(g) => request_fingerprint(&op.request.method, &format!("{} {}", op.request.path, g.query), Some(&Value::Object(g.variables.clone()))),
                None => request_fingerprint(&op.request.method, &op.request.path, op.request.body.as_ref()),
            },
            status,
            verified_by: op.verify.as_ref().map(|v| v.op().to_string()).unwrap_or_default(),
            pending,
            at: chrono::Utc::now().to_rfc3339(),
            tenant: self.stamp.tenant.clone(),
            app: self.stamp.app.clone(),
            prev: self.stamp.prev.clone(),
            key: String::new(),
            signature: String::new(),
        })
    }

    /// Re-read the op's subject; `Some(user)` when it is there with the `expect`ed fields.
    async fn check(&self, read: &str, ctx: &Map<String, Value>, expect: &Map<String, Value>) -> Result<Option<TargetUser>, KeyholeError> {
        let Some(found) = self.find_subject(read, ctx).await? else {
            return Ok(None);
        };
        self.matching(read, ctx, expect, &found)
    }

    /// The user as `read` extracts it, when `found` has the `expect`ed fields.
    fn matching(&self, read: &str, ctx: &Map<String, Value>, expect: &Map<String, Value>, found: &Value) -> Result<Option<TargetUser>, KeyholeError> {
        let ex = extract_of(read, self.op(read)?)?;
        let expect = render_map(expect, ctx).map_err(|param| KeyholeError::BadParam { op: read.into(), param })?;
        if !matches(ex, found, &expect) {
            return Ok(None);
        }
        Ok(Some(user_from(read, ex, found)?))
    }

    /// Look the op's subject up with a GET op: through every page of a list op, or as one object.
    /// `None` only when the app positively says the user is not there.
    async fn find_subject(&self, read: &str, ctx: &Map<String, Value>) -> Result<Option<Value>, KeyholeError> {
        if ctx_string(ctx, "id").is_none() && ctx_string(ctx, "user_name").is_none() {
            return Err(KeyholeError::BadParam { op: read.into(), param: "id".into() });
        }
        let op = self.op(read)?;
        let ex = extract_of(read, op)?;
        if ex.list.is_some() {
            let users = self.list_items(read, ctx).await?;
            return Ok(users.into_iter().find(|u| is_subject(ex, u, ctx)));
        }
        let reply = self.send(read, op, ctx, &[]).await?;
        if reply.status == 404 {
            return Ok(None);
        }
        self.ensure_success(&reply)?;
        let body = require_json(read, reply.body)?;
        self.fingerprint_guard(read, op, &body)?;
        if !is_subject(ex, &body, ctx) {
            return Err(KeyholeError::WrongSubject(read.to_string()));
        }
        Ok(Some(body))
    }

    /// Read every page of a list op, deduplicated by id, leaving out the items `skip` names. Fails
    /// rather than return a short list: the planner would read a missing user as an account removed
    /// outside AppDoorman and stop managing it, so a leaver would keep their access.
    async fn list_items(&self, op_name: &str, ctx: &Map<String, Value>) -> Result<Vec<Value>, KeyholeError> {
        let op = self.op(op_name)?;
        let ex = extract_of(op_name, op)?;
        let list = ex.list.as_deref().ok_or_else(|| missing(op_name, "extract.list"))?;
        self.walk(op_name, op, ctx, list, &ex.id, |item| is_skipped(ex, item)).await
    }

    /// Every item of the `list` in a GET op's answers, across all its pages, each told apart by the
    /// field at `id`, leaving out those `skip` names. Users go through [`Keyhole::list_items`];
    /// lookups read their lists this way too.
    async fn walk(&self, op_name: &str, op: &OpSpec, ctx: &Map<String, Value>, list: &str, id: &str, skip: impl Fn(&Value) -> bool) -> Result<Vec<Value>, KeyholeError> {
        let incomplete = |why: String| KeyholeError::Incomplete { op: op_name.to_string(), why };
        let mut users = Vec::new();
        // Every id read, skipped items included: progress and the reported total count them all.
        let mut seen = HashSet::new();
        let mut position = match &op.paginate {
            Some(Paginate::Offset { first, .. } | Paginate::Page { first, .. }) => *first,
            _ => 0,
        };
        let mut cursor: Option<String> = None;

        for _ in 0..MAX_PAGES {
            // Paging values keep their type: a GraphQL op sends them as variables (`Int`, `String`).
            let mut query: Vec<(String, Value)> = Vec::new();
            match &op.paginate {
                None => {}
                Some(Paginate::Offset { param, size_param, size, .. } | Paginate::Page { param, size_param, size, .. }) => {
                    query.push((param.clone(), json!(position)));
                    query.push((size_param.clone(), json!(size)));
                }
                Some(Paginate::Cursor { param, size_param, size, .. }) => {
                    if let Some(c) = &cursor {
                        query.push((param.clone(), json!(c)));
                    }
                    if let (Some(p), Some(s)) = (size_param, size) {
                        query.push((p.clone(), json!(s)));
                    }
                }
                Some(Paginate::NextUrl { param, .. }) => {
                    if let Some(c) = &cursor {
                        query.push((param.clone(), json!(c)));
                    }
                }
            }

            let reply = self.send(op_name, op, ctx, &query).await?;
            self.ensure_success(&reply)?;
            let body = require_json(op_name, reply.body)?;
            // An empty `list` is an app that answers with the bare array (GitHub's members).
            let page = if list.is_empty() { Some(&body) } else { lookup(&body, list) };
            let page = page.and_then(Value::as_array).ok_or_else(|| missing(op_name, if list.is_empty() { "the list" } else { list }))?;
            if let Some(first) = page.first() {
                self.fingerprint_guard(op_name, op, first)?;
            }
            let mut added = 0;
            for item in page {
                let item_id = field_string(item, id).ok_or_else(|| missing(op_name, id))?;
                if seen.insert(item_id) {
                    added += 1;
                    if !skip(item) {
                        users.push(item.clone());
                    }
                }
            }

            match &op.paginate {
                None => return Ok(users),
                Some(Paginate::Offset { total, .. } | Paginate::Page { total, .. }) => {
                    let total = total.as_deref().and_then(|t| lookup(&body, t)).and_then(Value::as_u64);
                    if page.is_empty() {
                        // The end of the list. When the app reported a total, it must have been reached.
                        if let Some(t) = total.filter(|&t| (seen.len() as u64) < t) {
                            return Err(incomplete(format!("the app reported {t} users but listed {}", seen.len())));
                        }
                        return Ok(users);
                    }
                    if added == 0 {
                        return Err(incomplete("a page held only users already read, so the app is not paging".into()));
                    }
                    if total.is_some_and(|t| seen.len() as u64 >= t) {
                        return Ok(users);
                    }
                    position += match &op.paginate {
                        Some(Paginate::Offset { .. }) => page.len() as u64,
                        _ => 1,
                    };
                }
                Some(Paginate::Cursor { next, more, .. }) => {
                    let next = lookup(&body, next).and_then(scalar_string);
                    // With a has-more flag, only `false` ends the walk: a cursor alone is not trusted
                    // to run out (a GraphQL connection keeps its endCursor on the last page).
                    let next = match more.as_deref().map(|m| (m, lookup(&body, m).and_then(Value::as_bool))) {
                        Some((m, None)) => return Err(incomplete(format!("the answer has no `{m}` flag"))),
                        Some((_, Some(false))) => None,
                        Some((_, Some(true))) if next.is_none() => return Err(incomplete("the app says there is more but gave no cursor".into())),
                        _ => next,
                    };
                    let Some(next) = next else {
                        return Ok(users);
                    };
                    // An empty page with a fresh cursor is progress (some apps filter after paging);
                    // the same cursor again, or a page of users already read, is not.
                    if cursor.as_deref() == Some(next.as_str()) || (!page.is_empty() && added == 0) {
                        return Err(incomplete("the cursor did not move on".into()));
                    }
                    cursor = Some(next);
                }
                Some(Paginate::NextUrl { path, param }) => {
                    let Some(next) = next_url_cursor(&body, path, param).map_err(incomplete)? else {
                        return Ok(users);
                    };
                    if cursor.as_deref() == Some(next.as_str()) || (!page.is_empty() && added == 0) {
                        return Err(incomplete("the cursor did not move on".into()));
                    }
                    cursor = Some(next);
                }
            }
        }
        Err(KeyholeError::TooManyPages(op_name.to_string()))
    }

    /// A non-2xx answer fails with the app's explanation, or the Doorkey's hint for its error code.
    fn ensure_success(&self, reply: &Reply) -> Result<(), KeyholeError> {
        if (200..300).contains(&reply.status) {
            return Ok(());
        }
        let code = ["error.code", "code", "error_code"].iter().find_map(|p| lookup(&reply.body, p).and_then(Value::as_str));
        let why = code.and_then(|c| self.doorkey.hints.get(c)).cloned().or_else(|| app_message(&reply.body));
        Err(KeyholeError::Http(reply.status, reply.path.clone(), why))
    }

    /// The OAuth access token: the one fetched before while it has more than a minute left, else a
    /// new one from the token endpoint. The client secret is sent there and nowhere else.
    async fn access_token(&self) -> Result<Zeroizing<String>, KeyholeError> {
        let mut held = self.token.lock().await;
        if let Some((token, renew_at)) = held.as_ref() {
            if std::time::Instant::now() < *renew_at {
                return Ok(token.clone());
            }
        }
        let AuthSpec::OauthClientCredentials { token_url, grant_type, fields, scope, credentials_in_body } = &self.doorkey.auth else {
            return Err(KeyholeError::Setup("this Doorkey does not use OAuth client credentials".into()));
        };
        let url = oauth_token_url(token_url, &self.secret).map_err(|e| KeyholeError::Setup(e.to_string()))?;
        let cred: Map<String, Value> = serde_json::from_str(self.secret.as_str()).map_err(|_| KeyholeError::BadCredential("token".into()))?;
        let field = |name: &str| cred.get(name).and_then(Value::as_str).map(str::to_string).ok_or_else(|| KeyholeError::BadCredential("token".into()));
        let in_path = token_url_fields(token_url);
        let mut form = vec![("grant_type".to_string(), Zeroizing::new(grant_type.clone()))];
        if let Some(scope) = scope {
            form.push(("scope".into(), Zeroizing::new(scope.clone())));
        }
        for name in fields.iter().filter(|f| !in_path.contains(f)) {
            form.push((name.clone(), Zeroizing::new(field(name)?)));
        }
        let mut req = self.http.post(url).header("Accept", "application/json");
        if *credentials_in_body {
            form.push(("client_id".into(), Zeroizing::new(field("client_id")?)));
            form.push(("client_secret".into(), Zeroizing::new(field("client_secret")?)));
        } else {
            req = req.basic_auth(field("client_id")?, Some(Zeroizing::new(field("client_secret")?).as_str()));
        }
        let pairs: Vec<(&str, &str)> = form.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let resp = send_with_retry(req.form(&pairs), &[]).await?;
        let status = resp.status().as_u16();
        let text = Zeroizing::new(resp.text().await.map_err(|e| KeyholeError::Transport(e.to_string()))?);
        let body: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        if !(200..300).contains(&status) {
            return Err(KeyholeError::TokenRefused(status, app_message(&body)));
        }
        let token = body
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|t| !t.is_empty() && !t.chars().any(char::is_control))
            .ok_or(KeyholeError::TokenRefused(status, Some("the answer holds no access_token".into())))?;
        let token = Zeroizing::new(token.to_string());
        // Without a lifetime the token is used for this one request only.
        let lifetime = body.get("expires_in").and_then(Value::as_u64).unwrap_or(0);
        if lifetime > TOKEN_EARLY_SECS {
            *held = Some((token.clone(), std::time::Instant::now() + std::time::Duration::from_secs(lifetime - TOKEN_EARLY_SECS)));
        }
        Ok(token)
    }

    /// Build, authorise and send one request. The URL is built from the Doorkey's base with
    /// `set_path`, so no value can move it to another host, and the allowlist is checked against
    /// the path exactly as it will be sent.
    async fn send(&self, op_name: &str, op: &OpSpec, ctx: &Map<String, Value>, paging: &[(String, Value)]) -> Result<Reply, KeyholeError> {
        let bad = |param: String| KeyholeError::BadParam { op: op_name.to_string(), param };
        let method = op.request.method.to_uppercase();
        let path = format!("{}{}", self.base_path, render(&op.request.path, ctx, true).map_err(bad)?);

        let mut url = self.base.clone();
        url.set_path(&path);
        if url.path() != path {
            return Err(KeyholeError::UnsafePath(path));
        }
        if url.origin() != self.base.origin() {
            return Err(KeyholeError::OffHost(self.base.origin().ascii_serialization()));
        }
        let mut query = Vec::new();
        for (key, template) in &op.request.query {
            query.push((key.clone(), render(template, ctx, false).map_err(bad)?));
        }
        // A GraphQL op's paging goes in its variables; any other op's in the URL.
        let graphql = op.request.graphql.as_ref();
        if graphql.is_none() {
            query.extend(paging.iter().map(|(k, v)| (k.clone(), scalar_string(v).unwrap_or_else(|| v.to_string()))));
        }
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(&query);
        }
        let m = reqwest::Method::from_bytes(method.as_bytes()).map_err(|_| KeyholeError::NotAllowed(method.clone(), path.clone()))?;
        let sent_path = url.path().to_string();
        let query_names: Vec<String> = url.query_pairs().map(|(k, _)| k.into_owned()).collect();
        let mut req = self.http.request(m, url);
        if !self.doorkey.headers.keys().any(|k| k.eq_ignore_ascii_case("accept")) {
            req = req.header("Accept", "application/json");
        }
        for (name, value) in &self.doorkey.headers {
            req = req.header(name.as_str(), value.as_str());
        }

        // Authentication: the only place the credential is used.
        match &self.doorkey.auth {
            AuthSpec::Bearer => req = req.bearer_auth(self.secret.as_str()),
            AuthSpec::OauthClientCredentials { .. } => req = req.bearer_auth(self.access_token().await?.as_str()),
            AuthSpec::Header { name } => req = req.header(name.as_str(), self.secret.as_str()),
        }

        // Every request, reads included, must be on the allowlist with the parameters it carries.
        let params: Vec<String> = query_names;
        // A GraphQL request is checked by the root fields its signed document selects.
        let allowed = match graphql {
            Some(g) => graphql::parse(&g.query).is_ok_and(|o| self.allowed_graphql(&method, &sent_path, &params, &o.root_fields)),
            None => self.allowed(&method, &sent_path, &params),
        };
        if !allowed {
            return Err(KeyholeError::NotAllowed(method, path));
        }

        if let Some(g) = graphql {
            let mut variables = render_map(&g.variables, ctx).map_err(bad)?;
            variables.extend(paging.iter().cloned());
            let body = json!({ "query": g.query, "variables": variables });
            req = req.header("Content-Type", "application/json").body(body.to_string());
        } else if let Some(template) = &op.request.body {
            let body = render_value(template, ctx).map_err(bad)?;
            req = req.header("Content-Type", "application/json").body(body.to_string());
        }

        let resp = send_with_retry(req, &self.doorkey.retry_statuses).await?;
        let status = resp.status().as_u16();
        let text = resp.text().await.map_err(|e| KeyholeError::Transport(e.to_string()))?;
        // A successful answer must be JSON, or empty as a 204 is. Anything else, such as the login
        // page an expired session gets, is an error and never "no data".
        let body = if text.trim().is_empty() {
            Value::Null
        } else {
            match serde_json::from_str(&text) {
                Ok(v) => v,
                Err(_) if (200..300).contains(&status) => return Err(KeyholeError::NotJson(op_name.to_string())),
                Err(_) => Value::Null,
            }
        };
        // APIs that answer 200 with a success flag fail closed when it is not true.
        if let Some(ok_path) = &self.doorkey.ok_field {
            if (200..300).contains(&status) && lookup(&body, ok_path).and_then(Value::as_bool) != Some(true) {
                let error = lookup(&body, "error").and_then(Value::as_str).map(str::to_string).or_else(|| app_message(&body)).unwrap_or_else(|| "not ok".into());
                return Err(KeyholeError::NotOk { op: op_name.to_string(), error });
            }
        }
        if let Some(g) = graphql.filter(|_| (200..300).contains(&status)) {
            graphql_succeeded(op_name, g, &body)?;
        }
        Ok(Reply { status, body, method, path })
    }

    /// Is a request with `method`, `path` (as it will be sent) and these parameter names on the
    /// allowlist?
    fn allowed(&self, method: &str, path: &str, params: &[String]) -> bool {
        path.strip_prefix(&self.base_path)
            .filter(|rest| rest.starts_with('/'))
            .is_some_and(|rest| self.doorkey.allow.iter().any(|r| r.covers(method, rest, params)))
    }

    /// Is a GraphQL request selecting `root_fields`, with `method`, `path` and these parameter names,
    /// on the allowlist?
    fn allowed_graphql(&self, method: &str, path: &str, params: &[String], root_fields: &[String]) -> bool {
        path.strip_prefix(&self.base_path)
            .filter(|rest| rest.starts_with('/'))
            .is_some_and(|rest| self.doorkey.allow.iter().any(|r| r.covers_graphql(method, rest, params, root_fields)))
    }

    fn fingerprint_guard(&self, op_name: &str, op: &OpSpec, response: &Value) -> Result<(), KeyholeError> {
        if let Some(expected) = &op.shape {
            if &shape_fingerprint(response) != expected {
                return Err(KeyholeError::ShapeChanged {
                    doorkey: self.doorkey.doorkey.clone(),
                    version: self.doorkey.version,
                    op: op_name.to_string(),
                });
            }
        }
        Ok(())
    }
}

/// Read only the `param` query value of the next-page URL at `path` in the answer, never the URL.
fn next_url_cursor(body: &Value, path: &str, param: &str) -> Result<Option<String>, String> {
    // OData's key has a dot in it (`@odata.nextLink`), so the literal key is tried before a path.
    let Some(next) = body.get(path).or_else(|| lookup(body, path)).filter(|v| !v.is_null()) else {
        return Ok(None);
    };
    let url = next.as_str().and_then(|u| Url::parse(u).ok()).ok_or_else(|| "the next-page URL is not a URL".to_string())?;
    let cursors: Vec<String> = url.query_pairs().filter(|(key, _)| key == param).map(|(_, value)| value.into_owned()).collect();
    match cursors.as_slice() {
        [cursor] if !cursor.is_empty() => Ok(Some(cursor.clone())),
        _ => Err(format!("the next-page URL must have exactly one non-empty {param} parameter")),
    }
}

/// Send a request, again after the wait the app asks for while it answers 429, up to
/// [`RATE_LIMIT_TRIES`] times. A 429 means the app did not act on the request.
async fn send_with_retry(req: reqwest::RequestBuilder, busy: &[u16]) -> Result<reqwest::Response, KeyholeError> {
    let transport = |e: reqwest::Error| KeyholeError::Transport(e.to_string());
    for _ in 1..RATE_LIMIT_TRIES {
        let attempt = req.try_clone().ok_or_else(|| KeyholeError::Transport("the request cannot be repeated".into()))?;
        let resp = attempt.send().await.map_err(transport)?;
        let status = resp.status();
        if status != reqwest::StatusCode::TOO_MANY_REQUESTS && !busy.contains(&status.as_u16()) {
            return Ok(resp);
        }
        // A busy answer without Retry-After waits a little longer than a bare rate limit.
        let fallback = if status == reqwest::StatusCode::TOO_MANY_REQUESTS { 1 } else { 2 };
        let wait = resp.headers().get(reqwest::header::RETRY_AFTER).and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse::<u64>().ok()).unwrap_or(fallback);
        tokio::time::sleep(std::time::Duration::from_secs(wait.min(RATE_LIMIT_MAX_WAIT_SECS))).await;
    }
    req.send().await.map_err(transport)
}

/// A GraphQL API answers HTTP 200 even when the operation failed, so a 2xx counts only with `data`,
/// no `errors`, and nothing at any of the op's `errors_at` paths. Partial data with errors is a
/// failure too: a member list missing a field is not a member list.
fn graphql_succeeded(op_name: &str, g: &GraphqlSpec, body: &Value) -> Result<(), KeyholeError> {
    let not_ok = |error: String| KeyholeError::NotOk { op: op_name.to_string(), error };
    // `CODE: message`, one line, at most 300 characters.
    let failure = |e: &Value| -> String {
        let code = ["extensions.code", "code", "error_code"].iter().find_map(|p| lookup(e, p).and_then(Value::as_str));
        let message = e.get("message").and_then(Value::as_str).unwrap_or("no message");
        code.map_or(message.to_string(), |c| format!("{c}: {message}")).chars().map(|c| if c.is_control() { ' ' } else { c }).take(300).collect()
    };
    let reported = |found: Option<&Value>| match found {
        None | Some(Value::Null) => None,
        Some(Value::Array(errors)) => errors.first().map(failure),
        Some(other) => Some(failure(other)),
    };
    if let Some(error) = reported(body.get("errors")) {
        return Err(not_ok(error));
    }
    if body.get("data").is_none_or(Value::is_null) {
        return Err(not_ok("the answer has no data".into()));
    }
    match g.errors_at.iter().find_map(|path| reported(lookup(body, path))) {
        Some(error) => Err(not_ok(error)),
        None => Ok(()),
    }
}



/// ": why", when the app said why.
fn explained(message: &Option<String>) -> String {
    message.as_deref().map(|m| format!(": {m}")).unwrap_or_default()
}

/// The explanation in an app's error answer (`message`, `error.message`, `errors[0].message`, …),
/// so a failed change says why. One line, at most 300 characters.
fn app_message(body: &Value) -> Option<String> {
    let found = ["message", "error.message", "error_description", "detail", "error"]
        .iter()
        .find_map(|path| lookup(body, path).and_then(Value::as_str))
        .or_else(|| body.get("errors")?.get(0)?.get("message")?.as_str())?;
    let line: String = found.chars().map(|c| if c.is_control() { ' ' } else { c }).take(300).collect();
    Some(line.trim().to_string()).filter(|l| !l.is_empty())
}

/// A read must answer with data; an empty 2xx is as unusable as a login page.
fn require_json(op: &str, body: Value) -> Result<Value, KeyholeError> {
    if body.is_null() {
        return Err(KeyholeError::NotJson(op.to_string()));
    }
    Ok(body)
}

fn extract_of<'a>(op_name: &str, op: &'a OpSpec) -> Result<&'a Extract, KeyholeError> {
    op.extract.as_ref().ok_or_else(|| missing(op_name, "extract"))
}

/// Is this list item one of the non-people the extract's `skip` names?
fn is_skipped(ex: &Extract, item: &Value) -> bool {
    ex.skip.iter().any(|rule| rule.iter().all(|(path, want)| lookup(item, path) == Some(want)))
        || ex.skip_when_set.iter().any(|path| lookup(item, path).is_some_and(|v| !v.is_null()))
}

/// Is `user` the one this op is about? By id when the context has one, else by user name.
fn is_subject(ex: &Extract, user: &Value, ctx: &Map<String, Value>) -> bool {
    match (ctx_string(ctx, "id"), ctx_string(ctx, "user_name")) {
        (Some(id), _) => field_string(user, &ex.id) == Some(id),
        (None, Some(name)) => field_string(user, &ex.user_name).is_some_and(|n| n.eq_ignore_ascii_case(&name)),
        (None, None) => false,
    }
}

/// Compare a user's fields against an expectation map. `id`, `user_name` and `active` go through
/// the op's extract paths; any other key is a dotted path into the user.
fn matches(ex: &Extract, user: &Value, expect: &Map<String, Value>) -> bool {
    expect.iter().all(|(key, want)| match key.as_str() {
        // `active` goes through the extract's path and inversion, so an expectation written in
        // logical terms (`"active": false`) is compared against the real meaning of the field.
        "active" => extracted_active(ex, user) == want.as_bool(),
        "id" => lookup(user, &ex.id) == Some(want),
        // User names are email addresses, which apps store in their own case; the subject lookup
        // ignores case too.
        "user_name" => match (field_string(user, &ex.user_name), want.as_str()) {
            (Some(have), Some(want)) => have.eq_ignore_ascii_case(want),
            _ => false,
        },
        other => lookup(user, other) == Some(want),
    })
}

/// The logical active flag for a user: the extract's field, negated when `active_inverted`, or
/// compared with `active_when` for a status field. In an app without one, a listed user is an
/// active member.
fn extracted_active(ex: &Extract, user: &Value) -> Option<bool> {
    let Some(path) = &ex.active else {
        return Some(true);
    };
    let raw = lookup(user, path)?;
    if let Some(want) = &ex.active_when {
        let same_type = std::mem::discriminant(raw) == std::mem::discriminant(want);
        return same_type.then(|| raw == want);
    }
    Some(raw.as_bool()? != ex.active_inverted)
}

/// A [`TargetUser`] from one user object. Every field is required: a default would let a renamed
/// field pass as an empty id or an "active" user.
fn user_from(op: &str, ex: &Extract, user: &Value) -> Result<TargetUser, KeyholeError> {
    Ok(TargetUser {
        id: field_string(user, &ex.id).ok_or_else(|| missing(op, &ex.id))?,
        user_name: field_string(user, &ex.user_name).ok_or_else(|| missing(op, &ex.user_name))?,
        active: extracted_active(ex, user).ok_or_else(|| missing(op, ex.active.as_deref().unwrap_or("active")))?,
    })
}

/// Follow a dotted path (`profile.email`) into a JSON value.
fn lookup<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.').try_fold(v, |v, key| v.get(key))
}

/// A string or number as text (some apps use numeric ids). Empty counts as missing.
fn scalar_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn field_string(v: &Value, path: &str) -> Option<String> {
    lookup(v, path).and_then(scalar_string)
}

fn ctx_string(ctx: &Map<String, Value>, key: &str) -> Option<String> {
    ctx.get(key).and_then(scalar_string)
}

// ---------------------------------------------------------------------------
// Target: one lifecycle interface over SCIM and Doorkeys
// ---------------------------------------------------------------------------

/// The minimum a provisioning target must do, independent of transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetUser {
    pub id: String,
    pub user_name: String,
    pub active: bool,
}

/// A group in the app, as its group list shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetGroup {
    pub id: String,
    pub name: String,
    /// Seats in a seat-pool group (a license): how many there are and how many are taken.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seats: Option<(u64, u64)>,
}

fn group_from(op: &str, ex: &GroupExtract, g: &Value) -> Result<TargetGroup, KeyholeError> {
    let count = |path: &Option<String>| path.as_deref().and_then(|p| lookup(g, p)).and_then(Value::as_u64);
    let seats = match (count(&ex.seats_total), count(&ex.seats_used)) {
        (Some(total), Some(used)) => Some((total, used)),
        _ => None,
    };
    Ok(TargetGroup { id: field_string(g, &ex.id).ok_or_else(|| missing(op, &ex.id))?, name: field_string(g, &ex.name).ok_or_else(|| missing(op, &ex.name))?, seats })
}

/// Does a group have every expected field? `id` and `name` go through the extract's paths.
fn group_matches(ex: &GroupExtract, g: &Value, want: &Map<String, Value>) -> bool {
    want.iter().all(|(key, value)| match key.as_str() {
        "id" => lookup(g, &ex.id) == Some(value),
        "name" => lookup(g, &ex.name) == Some(value),
        other => lookup(g, other) == Some(value),
    })
}

/// The result of a create.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Created {
    /// A separate read saw the new user, active.
    Confirmed(TargetUser, Evidence),
    /// The app accepted the request but does not list the user yet (an invite waiting to be
    /// accepted). The caller keeps it and settles it from a later member list instead of creating
    /// the user again, which would send a second invite.
    Pending(PendingCreate),
}

/// A create the app accepted but does not show yet. Serialisable, so a sync run can keep it
/// between runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingCreate {
    pub user_name: String,
    pub given: String,
    pub family: String,
    pub email: String,
    /// When the app accepted the request (RFC 3339), so the caller can alert when it waits too long.
    pub since: String,
    pub evidence: Evidence,
}

fn create_ctx(user_name: &str, given: &str, family: &str, email: &str) -> Map<String, Value> {
    Map::from_iter([
        ("user_name".into(), json!(user_name)),
        // The part before the `@`, for an app that wants a mail alias (Microsoft's mailNickname).
        ("user_name_local".into(), json!(user_name.split('@').next().unwrap_or(user_name))),
        ("given".into(), json!(given)),
        ("family".into(), json!(family)),
        ("email".into(), json!(email)),
    ])
}

/// A provisioning target, reached the same way whether it speaks SCIM or a Doorkey. New variants
/// (e.g. a browser-run Doorkey, or an extension) slot in here without touching the planner. Every
/// change is confirmed by a separate read and returns sealed [`Evidence`].
pub enum Target {
    Scim(ScimClient, Sealer),
    /// A Doorkey run here, holding the credential: inside the Keyhole, and in tests.
    Doorkey(Keyhole),
    /// A Doorkey app reached through the Keyhole, which holds its credential; this side never does.
    Keyhole(service::KeyholeApp),
}

impl Target {
    /// A SCIM app, when this target is one, for the group-push and lookup paths that are SCIM-only.
    pub fn as_scim(&self) -> Option<&ScimClient> {
        match self {
            Target::Scim(c, _) => Some(c),
            Target::Doorkey(_) | Target::Keyhole(_) => None,
        }
    }

    /// Whether a hard delete is possible. SCIM always deletes; a Doorkey only when its spec has a
    /// `delete_user` op (Linear, for one, has none, so a leaver is suspended instead).
    pub fn supports_delete(&self) -> bool {
        match self {
            Target::Scim(..) => true,
            Target::Doorkey(k) => k.doorkey().ops.contains_key("delete_user"),
            Target::Keyhole(k) => k.supports_delete(),
        }
    }

    /// Whether a pending invite can be withdrawn. SCIM has no invites; a Doorkey can when its spec
    /// has a `withdraw_invite` op.
    pub fn supports_withdraw(&self) -> bool {
        match self {
            Target::Scim(..) => false,
            Target::Doorkey(k) => k.doorkey().ops.contains_key("withdraw_invite"),
            Target::Keyhole(k) => k.supports_withdraw(),
        }
    }

    /// Whether an account can be suspended. SCIM always can; a Doorkey only when its spec has a
    /// `deactivate_user` op (an app that only lists members, such as Cloudflare, removes a leaver).
    pub fn supports_suspend(&self) -> bool {
        match self {
            Target::Scim(..) => true,
            Target::Doorkey(k) => k.doorkey().can_suspend(),
            Target::Keyhole(k) => k.supports_suspend(),
        }
    }

    /// Whether a Doorkey can push groups. SCIM group push goes through [`Target::as_scim`].
    pub fn supports_doorkey_groups(&self) -> bool {
        match self {
            Target::Scim(..) => false,
            Target::Doorkey(k) => k.doorkey().supports_groups(),
            Target::Keyhole(k) => k.supports_groups(),
        }
    }

    /// Whether a Doorkey can create a group, rather than only keep an existing one in step.
    pub fn supports_create_group(&self) -> bool {
        match self {
            Target::Scim(..) => true,
            Target::Doorkey(k) => k.doorkey().ops.contains_key("create_group"),
            Target::Keyhole(k) => k.supports_create_group(),
        }
    }

    pub async fn list_groups(&self) -> Result<Vec<TargetGroup>> {
        match self {
            Target::Scim(..) => Err(anyhow::anyhow!("SCIM groups are read through the SCIM client")),
            Target::Doorkey(k) => Ok(k.list_groups().await?),
            Target::Keyhole(k) => k.list_groups().await,
        }
    }

    pub async fn group_members(&self, group_id: &str) -> Result<Vec<TargetUser>> {
        match self {
            Target::Scim(..) => Err(anyhow::anyhow!("SCIM groups are read through the SCIM client")),
            Target::Doorkey(k) => Ok(k.group_members(group_id).await?),
            Target::Keyhole(k) => k.group_members(group_id).await,
        }
    }

    pub async fn create_group(&self, name: &str) -> Result<(TargetGroup, Evidence)> {
        match self {
            Target::Scim(..) => Err(anyhow::anyhow!("SCIM groups are created through the SCIM client")),
            Target::Doorkey(k) => Ok(k.create_group(name).await?),
            Target::Keyhole(k) => k.create_group(name).await,
        }
    }

    pub async fn add_group_member(&self, group_id: &str, id: &str) -> Result<Evidence> {
        match self {
            Target::Scim(..) => Err(anyhow::anyhow!("SCIM groups are changed through the SCIM client")),
            Target::Doorkey(k) => Ok(k.add_group_member(group_id, id).await?),
            Target::Keyhole(k) => k.add_group_member(group_id, id).await,
        }
    }

    pub async fn remove_group_member(&self, group_id: &str, id: &str) -> Result<Evidence> {
        match self {
            Target::Scim(..) => Err(anyhow::anyhow!("SCIM groups are changed through the SCIM client")),
            Target::Doorkey(k) => Ok(k.remove_group_member(group_id, id).await?),
            Target::Keyhole(k) => k.remove_group_member(group_id, id).await,
        }
    }

    pub async fn list_users(&self) -> Result<Vec<TargetUser>> {
        match self {
            Target::Scim(c, _) => c.list_users().await?.iter().map(scim_user).collect(),
            Target::Doorkey(k) => Ok(k.list_users().await?),
            Target::Keyhole(k) => k.list_users().await,
        }
    }

    /// Create a user. Confirmed only once a separate read sees the new user, active; pending when
    /// the app takes the request but only lists the user later (see [`Created::Pending`]).
    pub async fn create_user(&self, user_name: &str, given: &str, family: &str, email: &str) -> Result<Created> {
        match self {
            Target::Scim(c, sealer) => {
                let payload = json!({
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                    "userName": user_name, "active": true,
                    "name": { "givenName": given, "familyName": family },
                    "emails": [{ "type": "work", "value": email, "primary": true }],
                });
                let created = c.create_user(&payload).await?;
                // The SCIM client refuses a create answer without an id.
                let id = created.get("id").and_then(Value::as_str).unwrap_or_default();
                let user = scim_read_back(c, "create_user", id).await?;
                if !user.active {
                    return Err(KeyholeError::VerifyFailed("create_user".into()).into());
                }
                let evidence = sealer.seal(scim_evidence("create_user", "POST", "/Users", &user, Some(&payload)));
                Ok(Created::Confirmed(user, evidence))
            }
            Target::Doorkey(k) => Ok(k.create_user(user_name, given, family, email).await?),
            Target::Keyhole(k) => k.create_user(user_name, given, family, email).await,
        }
    }

    pub async fn set_active(&self, id: &str, active: bool) -> Result<Evidence> {
        let op = if active { "reactivate_user" } else { "deactivate_user" };
        match self {
            Target::Scim(c, sealer) => {
                let ops = vec![json!({ "op": "replace", "path": "active", "value": active })];
                c.patch_user(id, ops.clone()).await?;
                let user = scim_read_back(c, op, id).await?;
                if user.active != active {
                    return Err(KeyholeError::VerifyFailed(op.into()).into());
                }
                Ok(sealer.seal(scim_evidence(op, "PATCH", "/Users/{id}", &user, Some(&json!({ "Operations": ops })))))
            }
            Target::Doorkey(k) => Ok(k.set_active(id, active).await?),
            Target::Keyhole(k) => k.set_active(id, active).await,
        }
    }

    pub async fn delete_user(&self, id: &str) -> Result<Evidence> {
        match self {
            Target::Scim(c, sealer) => {
                c.delete_user(id).await?;
                if c.get_user(id).await?.is_some() {
                    return Err(KeyholeError::VerifyFailed("delete_user".into()).into());
                }
                let gone = TargetUser { id: id.into(), user_name: String::new(), active: false };
                Ok(sealer.seal(scim_evidence("delete_user", "DELETE", "/Users/{id}", &gone, None)))
            }
            Target::Doorkey(k) => Ok(k.delete_user(id).await?),
            Target::Keyhole(k) => k.delete_user(id).await,
        }
    }

    pub async fn withdraw_invite(&self, user_name: &str, email: &str) -> Result<Evidence> {
        match self {
            Target::Scim(..) => Err(KeyholeError::UnknownOp("withdraw_invite".into()).into()),
            Target::Doorkey(k) => Ok(k.withdraw_invite(user_name, email).await?),
            Target::Keyhole(k) => k.withdraw_invite(user_name, email).await,
        }
    }
}

/// SCIM's `active` is optional and absent means active; the id and userName are required.
fn scim_user(v: &Value) -> Result<TargetUser> {
    Ok(TargetUser {
        id: field_string(v, "id").context("the app returned a user without an id")?,
        user_name: field_string(v, "userName").context("the app returned a user without a userName")?,
        active: v.get("active").and_then(Value::as_bool).unwrap_or(true),
    })
}

/// Read a SCIM user back after a change; a user the app cannot find fails the change.
async fn scim_read_back(c: &ScimClient, op: &str, id: &str) -> Result<TargetUser> {
    match c.get_user(id).await? {
        Some(v) => scim_user(&v),
        None => Err(KeyholeError::VerifyFailed(op.into()).into()),
    }
}

fn scim_evidence(op: &str, method: &str, path: &str, user: &TargetUser, body: Option<&Value>) -> Evidence {
    Evidence {
        doorkey: "scim".into(),
        version: 0,
        op: op.into(),
        method: method.into(),
        path: path.replace("{id}", &urlencoding::encode(&user.id)),
        subject_id: user.id.clone(),
        subject_user_name: user.user_name.clone(),
        request_fingerprint: request_fingerprint(method, path, body),
        status: None,
        verified_by: "get_user".into(),
        pending: false,
        at: chrono::Utc::now().to_rfc3339(),
        tenant: String::new(),
        app: String::new(),
        prev: String::new(),
        key: String::new(),
        signature: String::new(),
    }
}

// ---------------------------------------------------------------------------
// Templating and fingerprints (pure helpers)
// ---------------------------------------------------------------------------

/// Fill `{param}` placeholders from `ctx` in one pass, so a value that itself contains `{other}`
/// is never expanded. A placeholder without a value is an error, never sent as literal text. In a
/// path each value is percent-encoded, and empty, `.` and `..` values are refused: URL
/// normalisation would turn `/Users/..` into a different endpoint from the one the allowlist saw.
fn render(template: &str, ctx: &Map<String, Value>, in_path: bool) -> Result<String, String> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let Some(key) = after.find('}').map(|close| &after[..close]).filter(|k| is_param(k)) else {
            out.push('{');
            rest = after;
            continue;
        };
        let value = match ctx.get(key) {
            Some(Value::String(s)) => s.clone(),
            Some(other) => other.to_string(),
            None => return Err(key.to_string()),
        };
        if in_path {
            if value.is_empty() || value == "." || value == ".." {
                return Err(key.to_string());
            }
            out.push_str(&urlencoding::encode(&value));
        } else {
            out.push_str(&value);
        }
        rest = &after[key.len() + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

fn is_param(key: &str) -> bool {
    !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Fill a JSON template: a string that is exactly `"{param}"` takes the context value with its type
/// preserved (so `{active}` becomes a real boolean); `{param}` inside a longer string is spliced in
/// as text.
fn render_value(template: &Value, ctx: &Map<String, Value>) -> Result<Value, String> {
    Ok(match template {
        Value::String(s) => match s.strip_prefix('{').and_then(|s| s.strip_suffix('}')).filter(|k| is_param(k)) {
            Some(key) => ctx.get(key).cloned().ok_or_else(|| key.to_string())?,
            None => Value::String(render(s, ctx, false)?),
        },
        Value::Array(a) => Value::Array(a.iter().map(|v| render_value(v, ctx)).collect::<Result<_, _>>()?),
        Value::Object(o) => Value::Object(render_map(o, ctx)?),
        other => other.clone(),
    })
}

fn render_map(map: &Map<String, Value>, ctx: &Map<String, Value>) -> Result<Map<String, Value>, String> {
    map.iter().map(|(k, v)| Ok((k.clone(), render_value(v, ctx)?))).collect()
}

/// Does a concrete request path match an allow-rule pattern? Segment counts must match; a `{param}`
/// segment matches any single non-empty segment.
fn path_matches(pattern: &str, actual: &str) -> bool {
    let p: Vec<&str> = pattern.trim_matches('/').split('/').collect();
    let a: Vec<&str> = actual.trim_matches('/').split('/').collect();
    p.len() == a.len()
        && p.iter().zip(&a).all(|(pat, act)| (pat.starts_with('{') && pat.ends_with('}') && !act.is_empty()) || pat == act)
}

/// A hash of a request's structure (method, path template, body shape), not its values, for the
/// audit record.
fn request_fingerprint(method: &str, path: &str, body: Option<&Value>) -> String {
    let shape = body.map(shape_fingerprint).unwrap_or_default();
    format!("sha256:{:x}", Sha256::digest(format!("{} {} {}", method.to_uppercase(), path, shape).as_bytes()))
}

/// A hash of a JSON value's *shape* (its keys and types, recursively), ignoring values. Used to
/// detect when an app has changed its response format.
fn shape_fingerprint(v: &Value) -> String {
    format!("sha256:{:x}", Sha256::digest(shape_sig(v).as_bytes()))
}

fn shape_sig(v: &Value) -> String {
    match v {
        Value::Null => "null".into(),
        Value::Bool(_) => "bool".into(),
        Value::Number(_) => "num".into(),
        Value::String(_) => "str".into(),
        Value::Array(a) => format!("[{}]", a.first().map(shape_sig).unwrap_or_default()),
        Value::Object(o) => {
            let mut keys: Vec<_> = o.iter().collect();
            keys.sort_by(|a, b| a.0.cmp(b.0));
            let inner: Vec<String> = keys.into_iter().map(|(k, val)| format!("{k}:{}", shape_sig(val))).collect();
            format!("{{{}}}", inner.join(","))
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(any(test, feature = "fakes"))]
pub mod fakes;
