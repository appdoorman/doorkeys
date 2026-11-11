//! A canary for a Doorkey: run the signed spec against a sandbox workspace of the app, on the plan a
//! customer would have, to find out that the app changed before a customer needs a change made.
//!
//! It reads the whole member list (every page, failing closed and checking the recorded response
//! shapes) and, given a test account, deactivates and reactivates it, each confirmed by the
//! Doorkey's own read-back. AppDoorman's server binary runs it as `doorkey canary canary.json`, on
//! a schedule, from a machine that holds the sandbox credential.
//!
//! `canary.json` is `{"doorkey", "base_url", "credential", "test_user_id"?}`, where `credential` is
//! the token, or for an OAuth client the JSON object of its fields. Keep the file out of the
//! repository.

use std::io::Write;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use serde_json::Value;
use zeroize::Zeroizing;

use super::{load_bundled, Keyhole, Sealer, Target};
use crate::crypto::Key;

pub struct Canary {
    doorkey: String,
    base_url: String,
    credential: Zeroizing<String>,
    /// A disposable account to deactivate and reactivate; never the owner.
    test_user_id: Option<String>,
}

impl Canary {
    pub fn parse(raw: &str) -> Result<Self> {
        let v: Value = serde_json::from_str(raw).context("the canary file is not JSON")?;
        let field = |k: &str| v.get(k).and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string);
        let test_user_id = field("test_user_id");
        let credential = match v.get("credential") {
            Some(Value::String(s)) => s.clone(),
            Some(o @ Value::Object(_)) => o.to_string(),
            _ => bail!("`credential` is missing"),
        };
        Ok(Self {
            doorkey: field("doorkey").context("`doorkey` is missing")?,
            base_url: field("base_url").context("`base_url` is missing")?,
            credential: Zeroizing::new(credential),
            test_user_id,
        })
    }

    /// Run the canary, writing what it did to `out`. Any failure is an error: the Doorkey needs
    /// looking at before a customer's next change goes through it.
    pub async fn run(&self, dev_mode: bool, out: &mut impl Write) -> Result<()> {
        let spec = load_bundled(&self.doorkey, &self.base_url)?;
        writeln!(out, "Doorkey {} v{} (signature checked) at {}", spec.doorkey, spec.version, self.base_url)?;
        // Evidence from a canary is not kept, so a throwaway key signs it.
        let target = Target::Doorkey(Keyhole::new(spec, self.credential.as_str(), Sealer::new(&Key::generate()), dev_mode)?);

        let started = Instant::now();
        let users = target.list_users().await.context("reading the member list")?;
        writeln!(out, "  listed {} members in full in {} ms", users.len(), started.elapsed().as_millis())?;

        let Some(id) = &self.test_user_id else {
            writeln!(out, "  no test_user_id, so no change was tried")?;
            return Ok(());
        };
        let user = users.iter().find(|u| &u.id == id).with_context(|| format!("the test account {id} is not in the member list"))?;
        if !target.supports_suspend() {
            // Removing and adding back would send a fresh invite every run; the read is the check.
            writeln!(out, "  this app only lists members and has no suspend, so no change was tried")?;
            return Ok(());
        }
        if !user.active {
            bail!("the test account {id} is deactivated already; reactivate it by hand first");
        }
        let ev = target.set_active(id, false).await.context("deactivating the test account")?;
        writeln!(out, "  deactivated {id}, confirmed by a fresh {} read", ev.verified_by)?;
        let ev = target.set_active(id, true).await.context("reactivating the test account (it is deactivated now; reactivate it by hand)")?;
        writeln!(out, "  reactivated {id}, confirmed by a fresh {} read", ev.verified_by)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    async fn mock_app() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, crate::mock::mock_router::<()>().into_make_service()).await.unwrap() });
        format!("http://127.0.0.1:{port}/canary-{}/v2", crate::crypto::random_token(8))
    }

    #[test]
    fn both_file_formats_are_read() {
        let c = Canary::parse(r#"{ "doorkey": "microsoft365", "base_url": "https://graph.microsoft.com/v1.0", "credential": { "client_id": "a", "client_secret": "b" }, "test_user_id": "" }"#).unwrap();
        assert_eq!((c.doorkey.as_str(), c.test_user_id), ("microsoft365", None));
        assert_eq!(serde_json::from_str::<Value>(&c.credential).unwrap(), json!({ "client_id": "a", "client_secret": "b" }));
        let c = Canary::parse(r#"{ "doorkey": "mock", "base_url": "http://x", "credential": "dev-token", "test_user_id": "u1" }"#).unwrap();
        assert_eq!((c.credential.as_str(), c.test_user_id.as_deref()), ("dev-token", Some("u1")));
        assert!(Canary::parse(r#"{ "doorkey": "mock", "base_url": "http://x" }"#).is_err());
    }

    #[tokio::test]
    async fn the_canary_lists_and_round_trips_a_test_account() {
        let base = mock_app().await;
        let mut out = Vec::new();
        let listing = Canary::parse(&json!({ "doorkey": "mock", "base_url": base, "credential": "dev-token" }).to_string()).unwrap();
        listing.run(true, &mut out).await.unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("listed 3 members") && !text.contains("dev-token"), "{text}");

        let first = Target::Doorkey(Keyhole::new(load_bundled("mock", &base).unwrap(), "dev-token", Sealer::new(&Key::generate()), true).unwrap()).list_users().await.unwrap()[0].id.clone();
        let round_trip = Canary::parse(&json!({ "doorkey": "mock", "base_url": base, "credential": "dev-token", "test_user_id": first }).to_string()).unwrap();
        let mut out = Vec::new();
        round_trip.run(true, &mut out).await.unwrap();
        assert!(String::from_utf8(out).unwrap().contains("reactivated"));

        // A refused token fails the canary rather than reporting an empty workspace.
        let refused = Canary::parse(&json!({ "doorkey": "mock", "base_url": base, "credential": "wrong-token" }).to_string()).unwrap();
        assert!(refused.run(true, &mut Vec::new()).await.is_err());
    }
}
