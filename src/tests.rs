//! End-to-end tests for the Doorkey interpreter and the Keyhole boundary.
//!
//! Most run against the real built-in mock SCIM app ([`crate::mock::mock_router`]) bound to an
//! ephemeral port, so the interpreter drives an actual HTTP server, not a stub. The same app is
//! driven both through a Doorkey and through native SCIM, proving the [`Target`] enum reaches an
//! app the same way whichever transport it has. Answers the mock cannot give (login pages,
//! redirects, cursors, an app that lies about a change) come from a small scripted app that
//! records every request it receives.

use super::*;
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

async fn serve(app: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service()).await.unwrap();
    });
    format!("http://127.0.0.1:{port}")
}

/// Serve the mock SCIM app on a loopback port; returns its origin.
async fn spawn_mock() -> String {
    serve(crate::mock::mock_router::<()>()).await
}

type Hits = Arc<Mutex<Vec<String>>>;

/// Serve an app whose answers come from `reply`. Every request is recorded as `METHOD /path?query`.
async fn scripted<F>(reply: F) -> (String, Hits)
where
    F: Fn(&Method, &Uri) -> Response + Clone + Send + Sync + 'static,
{
    let hits: Hits = Arc::default();
    let log = hits.clone();
    let app = axum::Router::new().fallback(move |req: Request| {
        let reply = reply.clone();
        let log = log.clone();
        async move {
            log.lock().unwrap().push(format!("{} {}", req.method(), req.uri()));
            reply(req.method(), req.uri())
        }
    });
    (serve(app).await, hits)
}

fn ok(body: Value) -> Response {
    axum::Json(body).into_response()
}

fn not_found() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

fn sealer() -> Sealer {
    Sealer::new(&Key::generate())
}

/// A Doorkey for the mock SCIM app as JSON, so tests can tweak it. `key` isolates each test in the
/// mock's per-app store; scripted apps reuse it with their own origin.
fn mock_json(origin: &str, key: &str) -> Value {
    json!({
        "doorkey": "mock",
        "version": 1,
        "base_url": format!("{origin}/{key}/v2"),
        "hosts": ["*"],
        "auth": { "scheme": "bearer" },
        "allow": [
            { "method": "GET",    "path": "/Users" },
            { "method": "GET",    "path": "/Users/{id}" },
            { "method": "POST",   "path": "/Users" },
            { "method": "PATCH",  "path": "/Users/{id}" },
            { "method": "DELETE", "path": "/Users/{id}" }
        ],
        "ops": {
            "list_users": {
                "request": { "method": "GET", "path": "/Users" },
                "paginate": { "style": "offset", "param": "startIndex", "size_param": "count", "size": 100, "first": 1, "total": "totalResults" },
                "extract": { "list": "Resources", "id": "id", "user_name": "userName", "active": "active" }
            },
            "find_user": {
                "request": { "method": "GET", "path": "/Users/{id}" },
                "extract": { "id": "id", "user_name": "userName", "active": "active" }
            },
            "create_user": {
                "request": {
                    "method": "POST", "path": "/Users",
                    "body": {
                        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                        "userName": "{user_name}", "active": true,
                        "name": { "givenName": "{given}", "familyName": "{family}" },
                        "emails": [{ "type": "work", "value": "{email}", "primary": true }]
                    }
                },
                "extract": { "id": "id", "user_name": "userName", "active": "active" },
                "verify": { "present": { "op": "find_user", "expect": { "active": true, "user_name": "{user_name}" } } }
            },
            "deactivate_user": {
                "request": {
                    "method": "PATCH", "path": "/Users/{id}",
                    "body": {
                        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                        "Operations": [{ "op": "replace", "path": "active", "value": "{active}" }]
                    }
                },
                "verify": { "present": { "op": "find_user", "expect": { "active": false } } }
            },
            "reactivate_user": {
                "request": {
                    "method": "PATCH", "path": "/Users/{id}",
                    "body": {
                        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                        "Operations": [{ "op": "replace", "path": "active", "value": "{active}" }]
                    }
                },
                "verify": { "present": { "op": "find_user", "expect": { "active": true } } }
            },
            "delete_user": {
                "request": { "method": "DELETE", "path": "/Users/{id}" },
                "verify": { "absent": { "op": "find_user" } }
            }
        }
    })
}

fn parse(v: Value) -> Doorkey {
    serde_json::from_value(v).expect("doorkey parses")
}

fn keyhole_from(v: Value) -> Keyhole {
    Keyhole::new(parse(v), "dev-token", sealer(), true).unwrap()
}

fn keyhole(origin: &str, key: &str) -> Keyhole {
    keyhole_from(mock_json(origin, key))
}

/// The error a `Target` call failed with, as a Keyhole error.
fn keyhole_err(e: anyhow::Error) -> KeyholeError {
    e.downcast::<KeyholeError>().expect("a Keyhole error")
}

fn deactivate_ctx(id: &str) -> Map<String, Value> {
    Map::from_iter([("id".into(), json!(id)), ("active".into(), json!(false))])
}

/// The user and evidence of a create the app confirmed at once, as an app that lists a new user at once does.
fn confirmed(created: Created) -> (TargetUser, Evidence) {
    match created {
        Created::Confirmed(user, evidence) => (user, evidence),
        Created::Pending(p) => panic!("expected a confirmed create, got a pending one: {p:?}"),
    }
}

#[tokio::test]
async fn doorkey_full_lifecycle_with_readback() {
    let origin = spawn_mock().await;
    let target = Target::Doorkey(keyhole(&origin, "t-lifecycle"));

    // List: the mock seeds three users.
    let before = target.list_users().await.unwrap();
    assert!(before.len() >= 3, "seeded users should be listed");
    assert!(before.iter().any(|u| u.user_name.starts_with("service-bot")));

    // Create: a separate read must see the new user, active, before we get it back.
    let (created, ev) = confirmed(target.create_user("new.hire@demo.example", "New", "Hire", "new.hire@demo.example").await.unwrap());
    assert!(!created.id.is_empty());
    assert!(created.active);
    assert_eq!(created.user_name, "new.hire@demo.example");
    assert_eq!(ev.verified_by, "find_user");

    // Deactivate: an independent GET must confirm active == false before this counts as done.
    let ev = target.set_active(&created.id, false).await.unwrap();
    assert_eq!(ev.op, "deactivate_user");
    assert_eq!(ev.verified_by, "find_user");
    assert!(ev.signature.starts_with("ed25519:"));
    let after = target.list_users().await.unwrap();
    assert!(!after.iter().find(|u| u.id == created.id).unwrap().active);

    // Delete: the absent read-back must confirm the user is gone.
    target.delete_user(&created.id).await.unwrap();
    let gone = target.list_users().await.unwrap();
    assert!(!gone.iter().any(|u| u.id == created.id));
}

// --- reads fail closed ------------------------------------------------------------------------

#[tokio::test]
async fn unreadable_member_lists_are_errors_not_empty_lists() {
    let (origin, _) = scripted(|_, uri| match uri.path() {
        "/notfound/v2/Users" => not_found(),
        "/login/v2/Users" => ([(header::CONTENT_TYPE, "text/html")], "<html>Sign in</html>").into_response(),
        "/renamed/v2/Users" => ok(json!({ "users": [] })),
        "/noid/v2/Users" => ok(json!({ "Resources": [{ "userName": "a@x.eu", "active": true }], "totalResults": 1 })),
        "/noactive/v2/Users" => ok(json!({ "Resources": [{ "id": "u1", "userName": "a@x.eu" }], "totalResults": 1 })),
        _ => not_found(),
    })
    .await;
    let list = |key: &str| Target::Doorkey(keyhole(&origin, key));

    let err = keyhole_err(list("notfound").list_users().await.unwrap_err());
    assert!(matches!(err, KeyholeError::Http(404, ..)), "got {err:?}");
    let err = keyhole_err(list("login").list_users().await.unwrap_err());
    assert!(matches!(err, KeyholeError::NotJson(_)), "got {err:?}");
    let err = keyhole_err(list("renamed").list_users().await.unwrap_err());
    assert!(matches!(&err, KeyholeError::MissingField { field, .. } if field == "Resources"), "got {err:?}");
    let err = keyhole_err(list("noid").list_users().await.unwrap_err());
    assert!(matches!(&err, KeyholeError::MissingField { field, .. } if field == "id"), "got {err:?}");
    let err = keyhole_err(list("noactive").list_users().await.unwrap_err());
    assert!(matches!(&err, KeyholeError::MissingField { field, .. } if field == "active"), "got {err:?}");
}

// --- pagination -------------------------------------------------------------------------------

#[tokio::test]
async fn offset_pagination_reads_every_page() {
    let origin = spawn_mock().await;
    let mut dk = mock_json(&origin, "t-pages");
    dk["ops"]["list_users"]["paginate"]["size"] = json!(2);
    let target = Target::Doorkey(keyhole_from(dk));
    for i in 0..4 {
        let name = format!("page.{i}@demo.example");
        confirmed(target.create_user(&name, "Page", "Test", &name).await.unwrap());
    }

    // 3 seeded + 4 created, read two at a time.
    let users = target.list_users().await.unwrap();
    assert_eq!(users.len(), 7);
    let ids: HashSet<_> = users.iter().map(|u| u.id.clone()).collect();
    assert_eq!(ids.len(), 7, "no user is listed twice");
}

/// A Doorkey with only a `list_users` op, for scripted list servers.
fn list_only(origin: &str, list_users: Value) -> Keyhole {
    let read = json!({ "method": "GET", "path": list_users["request"]["path"] });
    keyhole_from(json!({
        "doorkey": "scripted", "version": 1, "base_url": format!("{origin}/c/v2"), "hosts": ["*"],
        "auth": { "scheme": "bearer" }, "allow": [read],
        "ops": { "list_users": list_users }
    }))
}

/// A cursor-paged member list, for scripted list servers.
fn cursor_list(origin: &str) -> Target {
    Target::Doorkey(list_only(
        origin,
        json!({
            "request": { "method": "GET", "path": "/members" },
            "paginate": { "style": "cursor", "param": "cursor", "next": "meta.next", "size_param": "limit", "size": 2 },
            "extract": { "list": "members", "id": "id", "user_name": "profile.email", "active": "enabled" }
        }),
    ))
}

/// An offset-paged SCIM user list, for scripted list servers.
fn offset_list(origin: &str) -> Target {
    Target::Doorkey(list_only(
        origin,
        json!({
            "request": { "method": "GET", "path": "/Users" },
            "paginate": { "style": "offset", "param": "startIndex", "size_param": "count", "size": 2, "first": 1, "total": "totalResults" },
            "extract": { "list": "Resources", "id": "id", "user_name": "userName", "active": "active" }
        }),
    ))
}

fn member(id: &str) -> Value {
    json!({ "id": id, "profile": { "email": format!("{id}@x.eu") }, "enabled": true })
}

#[tokio::test]
async fn cursor_pagination_follows_the_cursor_until_it_ends() {
    let (origin, hits) = scripted(|_, uri| match uri.query().unwrap_or_default() {
        q if q.contains("cursor=p3") => ok(json!({ "members": [member("u3")], "meta": { "next": "" } })),
        // An empty page with a fresh cursor is not the end: some apps filter after paging.
        q if q.contains("cursor=p2") => ok(json!({ "members": [], "meta": { "next": "p3" } })),
        _ => ok(json!({ "members": [member("u1"), member("u2")], "meta": { "next": "p2" } })),
    })
    .await;

    let users = cursor_list(&origin).list_users().await.unwrap();
    assert_eq!(users.iter().map(|u| u.user_name.as_str()).collect::<Vec<_>>(), ["u1@x.eu", "u2@x.eu", "u3@x.eu"]);
    assert_eq!(hits.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn a_cursor_that_does_not_move_on_is_an_error_not_a_short_list() {
    // The second page is empty but hands back the cursor it was asked with.
    let (origin, hits) = scripted(|_, uri| match uri.query().unwrap_or_default() {
        q if q.contains("cursor=c1") => ok(json!({ "members": [], "meta": { "next": "c1" } })),
        _ => ok(json!({ "members": [member("u1")], "meta": { "next": "c1" } })),
    })
    .await;
    let err = keyhole_err(cursor_list(&origin).list_users().await.unwrap_err());
    assert!(matches!(err, KeyholeError::Incomplete { .. }), "got {err:?}");
    assert_eq!(hits.lock().unwrap().len(), 2, "gave up at once instead of walking to the page limit");
}

#[tokio::test]
async fn a_server_that_ignores_paging_is_an_error_not_a_short_list() {
    // Every request gets the same page, so there is no telling how many users are missing.
    let (origin, hits) = scripted(|_, _| {
        ok(json!({ "Resources": [
            { "id": "u1", "userName": "a@x.eu", "active": true },
            { "id": "u2", "userName": "b@x.eu", "active": true }
        ] }))
    })
    .await;
    let err = keyhole_err(offset_list(&origin).list_users().await.unwrap_err());
    assert!(matches!(err, KeyholeError::Incomplete { .. }), "got {err:?}");
    assert_eq!(hits.lock().unwrap().len(), 2, "does not loop");
}

#[tokio::test]
async fn a_list_short_of_its_reported_total_is_an_error() {
    // The app says five users, then runs out after two.
    let (origin, _) = scripted(|_, uri| match uri.query().unwrap_or_default() {
        q if q.starts_with("startIndex=1&") => ok(json!({ "totalResults": 5, "Resources": [
            { "id": "u1", "userName": "a@x.eu", "active": true },
            { "id": "u2", "userName": "b@x.eu", "active": true }
        ] })),
        _ => ok(json!({ "totalResults": 5, "Resources": [] })),
    })
    .await;
    let err = keyhole_err(offset_list(&origin).list_users().await.unwrap_err());
    assert!(matches!(&err, KeyholeError::Incomplete { why, .. } if why.contains("reported 5 users but listed 2")), "got {err:?}");
}

// --- the read-back --------------------------------------------------------------------------

#[tokio::test]
async fn list_readback_finds_the_user_on_any_page() {
    let origin = spawn_mock().await;
    let mut dk = mock_json(&origin, "t-listverify");
    // Verify through the paginated list (two per page), as an app without a get-one-user call would.
    dk["ops"]["list_users"]["paginate"]["size"] = json!(2);
    dk["ops"]["deactivate_user"]["verify"] = json!({ "present": { "op": "list_users", "expect": { "active": false } } });
    dk["ops"]["delete_user"]["verify"] = json!({ "absent": { "op": "list_users" } });
    let target = Target::Doorkey(keyhole_from(dk));

    // The new user is fourth, so on page two and not the first item of any page.
    let (u, _) = confirmed(target.create_user("late@demo.example", "Late", "Page", "late@demo.example").await.unwrap());
    let ev = target.set_active(&u.id, false).await.unwrap();
    assert_eq!(ev.verified_by, "list_users");
    assert_eq!(ev.subject_id, u.id);
    // Other users are still listed, and the read-back still sees this one gone.
    target.delete_user(&u.id).await.unwrap();
}

#[tokio::test]
async fn list_readback_fails_when_the_user_is_still_listed() {
    let (origin, _) = scripted(|method, _| match *method {
        Method::DELETE => StatusCode::NO_CONTENT.into_response(),
        _ => ok(json!({ "totalResults": 2, "Resources": [
            { "id": "u1", "userName": "a@x.eu", "active": true },
            { "id": "u2", "userName": "b@x.eu", "active": true }
        ] })),
    })
    .await;
    let mut dk = mock_json(&origin, "k");
    dk["ops"]["delete_user"]["verify"] = json!({ "absent": { "op": "list_users" } });
    let err = keyhole_err(Target::Doorkey(keyhole_from(dk)).delete_user("u2").await.unwrap_err());
    assert!(matches!(err, KeyholeError::VerifyFailed(_)), "got {err:?}");
}

#[tokio::test]
async fn create_is_confirmed_by_a_separate_read_not_its_own_answer() {
    // The app says the user was created, but a fresh read cannot find it.
    let (origin, _) = scripted(|method, _| match *method {
        Method::POST => (StatusCode::CREATED, axum::Json(json!({ "id": "u9", "userName": "a@x.eu", "active": true }))).into_response(),
        _ => not_found(),
    })
    .await;
    let target = Target::Doorkey(keyhole(&origin, "k"));
    let err = keyhole_err(target.create_user("a@x.eu", "A", "X", "a@x.eu").await.unwrap_err());
    assert!(matches!(err, KeyholeError::VerifyFailed(_)), "got {err:?}");
}

#[tokio::test]
async fn keyhole_fails_when_readback_cannot_confirm() {
    let origin = spawn_mock().await;
    // A change the app rejects (404 on the mutation) fails rather than reporting success.
    let k = keyhole(&origin, "t-verify");
    let err = k.run("deactivate_user", &deactivate_ctx("mock-does-not-exist")).await.unwrap_err();
    assert!(matches!(err, KeyholeError::Http(404, ..)), "got {err:?}");

    // And when the mutation "succeeds" but the read-back disagrees, we also fail: force the verify
    // to expect active==true right after deactivating.
    let mut dk = mock_json(&origin, "t-verify");
    dk["ops"]["deactivate_user"]["verify"]["present"]["expect"] = json!({ "active": true });
    let k = keyhole_from(dk);
    let target = Target::Doorkey(keyhole(&origin, "t-verify"));
    let (u, _) = confirmed(target.create_user("verify.test@demo.example", "V", "T", "verify.test@demo.example").await.unwrap());
    let err = k.run("deactivate_user", &deactivate_ctx(&u.id)).await.unwrap_err();
    assert!(matches!(err, KeyholeError::VerifyFailed(_)), "got {err:?}");
}

#[test]
fn every_mutating_op_needs_a_readback_through_a_get() {
    let load = |dk: Value| Keyhole::new(parse(dk), "t", sealer(), true);
    let base = mock_json("http://127.0.0.1:1", "k");

    let mut dk = base.clone();
    dk["ops"]["deactivate_user"].as_object_mut().unwrap().remove("verify");
    assert!(load(dk).is_err(), "a change without a read-back");

    let mut dk = base.clone();
    dk["ops"]["deactivate_user"]["verify"] = json!({ "absent": { "op": "delete_user" } });
    assert!(load(dk).is_err(), "a read-back through a mutating op");

    let mut dk = base.clone();
    dk["ops"]["deactivate_user"]["verify"] = json!({ "absent": { "op": "nope" } });
    assert!(load(dk).is_err(), "a read-back through an unknown op");

    assert!(load(base).is_ok());
}

#[tokio::test]
async fn scim_changes_are_read_back_too() {
    // The app accepts the PATCH but the user stays active.
    let (origin, _) = scripted(|method, _| match *method {
        Method::PATCH => ok(json!({})),
        _ => ok(json!({ "id": "u1", "userName": "a@x.eu", "active": true })),
    })
    .await;
    let scim = ScimClient::new(net::outbound_client(true), &format!("{origin}/s/v2"), crate::scim::Auth::from_parts("bearer", None, "t"));
    let err = keyhole_err(Target::Scim(scim, sealer()).set_active("u1", false).await.unwrap_err());
    assert!(matches!(err, KeyholeError::VerifyFailed(_)), "got {err:?}");
}

// --- the allowlist and the host ------------------------------------------------------------

#[tokio::test]
async fn keyhole_refuses_requests_outside_the_allowlist() {
    let load = |dk: Value| Keyhole::new(parse(dk), "t", sealer(), true);
    let base = mock_json("http://127.0.0.1:1", "t-deny");

    // An op the allowlist does not cover is refused when the Doorkey loads, reads included.
    let mut dk = base.clone();
    dk["ops"]["delete_group"] = json!({
        "request": { "method": "DELETE", "path": "/Groups/{id}" },
        "verify": { "absent": { "op": "find_user" } }
    });
    assert!(load(dk).is_err(), "DELETE /Groups/{{id}} is not allowlisted");
    let mut dk = base.clone();
    dk["ops"]["list_groups"] = json!({ "request": { "method": "GET", "path": "/Groups" }, "extract": { "list": "Resources", "id": "id", "user_name": "displayName", "active": "active" } });
    assert!(load(dk).is_err(), "an export is a read, and still not allowed");
    // A rule naming its parameters refuses an op that sends another one.
    let mut dk = base.clone();
    dk["allow"][1]["params"] = json!([]);
    dk["ops"]["find_user"]["request"]["query"] = json!({ "attributes": "password" });
    assert!(load(dk).is_err(), "an extra parameter");
    assert!(load(base).is_ok());
}

#[test]
fn an_rpc_style_change_over_get_is_refused_before_it_is_sent() {
    // An RPC-style admin API acts on the method and the parameters, not only the path.
    let mut dk = mock_json("https://app.example.com", "k");
    dk["allow"].as_array_mut().unwrap().extend([
        json!({ "method": "GET", "path": "/users.list", "params": [] }),
        json!({ "method": "GET", "path": "/users.info", "params": ["user"] }),
        json!({ "method": "POST", "path": "/users.admin.setInactive", "params": ["user"] }),
    ]);
    let k = keyhole_from(dk);
    let base = &k.base_path;
    // The app would act on these: the method or the parameter makes them a different call.
    assert!(!k.allowed("GET", &format!("{base}/users.admin.setInactive"), &["user".into()]));
    assert!(!k.allowed("GET", &format!("{base}/users.info"), &["user".into(), "include_locale".into()]));
    assert!(!k.allowed("POST", &format!("{base}/users.admin.setOwner"), &["user".into()]));
    assert!(!k.allowed("GET", &format!("{base}x/users.list"), &[]), "a path outside the base");
    assert!(k.allowed("GET", &format!("{base}/users.info"), &["user".into()]));
    assert!(k.allowed("POST", &format!("{base}/users.admin.setInactive"), &["user".into()]));
}

#[tokio::test]
async fn a_rate_limited_request_is_sent_again_after_the_wait() {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let limited = |times: usize| {
        let calls = calls.clone();
        move |_: &Method, _: &Uri| {
            if calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < times {
                (StatusCode::TOO_MANY_REQUESTS, [(header::RETRY_AFTER, "0")]).into_response()
            } else {
                ok(json!({ "totalResults": 1, "Resources": [{ "id": "u1", "userName": "a@x.eu", "active": true }] }))
            }
        }
    };
    let (origin, hits) = scripted(limited(2)).await;
    let users = Target::Doorkey(keyhole(&origin, "k")).list_users().await.unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(hits.lock().unwrap().len(), 3, "two 429s, then the answer");

    // An app that keeps refusing is an error after the last try, not an endless wait.
    calls.store(0, std::sync::atomic::Ordering::SeqCst);
    let (origin, hits) = scripted(limited(usize::MAX)).await;
    let err = keyhole_err(Target::Doorkey(keyhole(&origin, "k")).list_users().await.unwrap_err());
    assert!(matches!(err, KeyholeError::Http(429, ..)), "got {err:?}");
    assert_eq!(hits.lock().unwrap().len(), RATE_LIMIT_TRIES as usize);
}

#[tokio::test]
async fn dot_segment_ids_are_refused_before_anything_is_sent() {
    let (origin, hits) = scripted(|_, _| not_found()).await;
    let k = keyhole(&origin, "k");

    // `/v2/Users/..` would be sent as `/v2/`, past an allowlist that approved `/Users/{id}`.
    for id in ["..", ".", ""] {
        let err = k.run("deactivate_user", &deactivate_ctx(id)).await.unwrap_err();
        assert!(matches!(&err, KeyholeError::BadParam { param, .. } if param == "id"), "id {id:?}: got {err:?}");
    }
    assert!(hits.lock().unwrap().is_empty(), "nothing reached the app: {hits:?}");

    // A value aimed at another host stays an encoded path segment on this one.
    let err = k.run("deactivate_user", &deactivate_ctx("@evil.example")).await.unwrap_err();
    assert!(matches!(err, KeyholeError::Http(404, ..)), "got {err:?}");
    assert_eq!(hits.lock().unwrap().as_slice(), ["PATCH /k/v2/Users/%40evil.example"]);
}

#[test]
fn templates_that_could_leave_the_endpoint_are_rejected_at_load() {
    let load = |path: &str, method: &str| {
        let mut dk = mock_json("http://127.0.0.1:1", "k");
        dk["ops"]["find_user"]["request"] = json!({ "method": method, "path": path });
        Keyhole::new(parse(dk), "t", sealer(), true)
    };
    assert!(load("@evil.example/Users/{id}", "GET").is_err());
    assert!(load("/Users/../Groups/{id}", "GET").is_err());
    assert!(load("/Users/{id}?expand=all", "GET").is_err());
    assert!(load("/Users/{id}", "PROPFIND").is_err(), "unknown methods would skip the allowlist");
    assert!(load("/Users/{id}", "get").is_ok());
}

#[test]
fn misspelled_keys_are_refused_at_load() {
    let parses = |dk: &Value| serde_json::from_value::<Doorkey>(dk.clone()).is_ok();
    let base = mock_json("http://127.0.0.1:1", "k");
    let typo = |edit: &dyn Fn(&mut Value)| {
        let mut dk = base.clone();
        edit(&mut dk);
        dk
    };

    // Each of these would otherwise load and quietly turn a protection off.
    let paging = typo(&|dk| {
        let p = dk["ops"]["list_users"].as_object_mut().unwrap().remove("paginate").unwrap();
        dk["ops"]["list_users"]["pagination"] = p;
    });
    assert!(!parses(&paging), "a misspelled `paginate` would read only the first page");
    assert!(!parses(&typo(&|dk| dk["okfield"] = json!("ok"))), "a misspelled `ok_field` would take ok:false as success");
    assert!(!parses(&typo(&|dk| dk["ops"]["list_users"]["paginate"]["sise"] = json!(2))), "inside a tagged `paginate`");
    assert!(!parses(&typo(&|dk| dk["ops"]["list_users"]["extract"]["activ"] = json!("enabled"))), "inside `extract`");
    assert!(!parses(&typo(&|dk| dk["ops"]["deactivate_user"]["verify"]["present"]["expct"] = json!({}))), "inside `verify`");
    assert!(!parses(&typo(&|dk| dk["auth"] = json!({ "scheme": "header", "name": "X-Key", "prefix": "Token" }))), "inside `auth`");
    assert!(!parses(&typo(&|dk| dk["ops"]["find_user"]["request"]["querry"] = json!({}))), "inside `request`");

    // Notes for humans are fine where the spec has a `_comment`.
    let noted = typo(&|dk| {
        dk["_comment"] = json!({ "allow": "why these calls" });
        dk["ops"]["list_users"]["_comment"] = json!("why this read");
    });
    assert!(parses(&noted));
    assert!(parses(&base));
}

#[test]
fn only_a_create_with_a_present_readback_may_be_pending() {
    let load = |dk: Value| Keyhole::new(parse(dk), "t", sealer(), true);
    let base = mock_json("http://127.0.0.1:1", "k");

    let mut dk = base.clone();
    dk["ops"]["create_user"]["allow_pending"] = json!(true);
    assert!(load(dk.clone()).is_ok());
    dk["ops"]["create_user"]["verify"] = json!({ "absent": { "op": "find_user" } });
    assert!(load(dk).is_err(), "pending needs a user to wait for");

    let mut dk = base;
    dk["ops"]["deactivate_user"]["allow_pending"] = json!(true);
    assert!(load(dk).is_err(), "a deactivation is confirmed or failed, never left waiting");
}

#[tokio::test]
async fn a_pending_create_that_shows_up_wrong_is_a_failure() {
    // The app takes the create but lists the user deactivated: a failed change, not one waiting.
    let (origin, _) = scripted(|method, _| match *method {
        Method::POST => (StatusCode::CREATED, axum::Json(json!({}))).into_response(),
        _ => ok(json!({ "totalResults": 1, "Resources": [{ "id": "u1", "userName": "a@x.eu", "active": false }] })),
    })
    .await;
    let mut dk = mock_json(&origin, "k");
    dk["ops"]["create_user"]["allow_pending"] = json!(true);
    dk["ops"]["create_user"]["verify"] = json!({ "present": { "op": "list_users", "expect": { "user_name": "{user_name}", "active": true } } });
    let err = keyhole_err(Target::Doorkey(keyhole_from(dk)).create_user("a@x.eu", "A", "X", "a@x.eu").await.unwrap_err());
    assert!(matches!(err, KeyholeError::VerifyFailed(_)), "got {err:?}");
}

#[test]
fn production_keyholes_only_reach_public_https() {
    let load = |base: &str| {
        let mut dk = mock_json("x", "k");
        dk["base_url"] = json!(base);
        // Every host here is a Doorkey host, so only the outbound rules can refuse one.
        dk["hosts"] = json!(["127.0.0.1", "10.1.2.3", "localhost", "app.example.com"]);
        Keyhole::new(parse(dk), "t", sealer(), false)
    };
    assert!(load("http://127.0.0.1:8080/v2").is_err());
    assert!(load("https://10.1.2.3/v2").is_err());
    assert!(load("https://localhost/v2").is_err());
    assert!(load("http://app.example.com/v2").is_err());
    assert!(load("https://app.example.com/v2").is_ok());
}

#[tokio::test]
async fn redirects_are_not_followed() {
    // A 307 would make the HTTP client replay the PATCH to a path the allowlist never saw.
    let (origin, hits) = scripted(|_, _| (StatusCode::TEMPORARY_REDIRECT, [(header::LOCATION, "/k/v2/Groups/g1")]).into_response()).await;
    let err = keyhole(&origin, "k").run("deactivate_user", &deactivate_ctx("u1")).await.unwrap_err();
    assert!(matches!(err, KeyholeError::Http(307, ..)), "got {err:?}");
    assert!(!hits.lock().unwrap().iter().any(|h| h.contains("/Groups")), "redirect was followed: {hits:?}");
}

// --- shape and transports -------------------------------------------------------------------

#[tokio::test]
async fn keyhole_flags_a_changed_response_shape() {
    let origin = spawn_mock().await;
    let mut dk = mock_json(&origin, "t-shape");
    // Pin find_user to a wrong shape, as if the app had changed its response format.
    dk["ops"]["find_user"]["shape"] = json!("sha256:deadbeef");
    let k = keyhole_from(dk);

    // Create a user through a clean Keyhole so there is something to read.
    let target = Target::Doorkey(keyhole(&origin, "t-shape"));
    let (u, _) = confirmed(target.create_user("shape.test@demo.example", "Shape", "Test", "shape.test@demo.example").await.unwrap());

    let ctx = Map::from_iter([("id".into(), json!(u.id))]);
    let err = k.find_subject("find_user", &ctx).await.unwrap_err();
    assert!(matches!(err, KeyholeError::ShapeChanged { .. }), "got {err:?}");
}

#[tokio::test]
async fn scim_and_doorkey_reach_the_same_app_alike() {
    let origin = spawn_mock().await;
    let scim = Target::Scim(
        ScimClient::new(net::outbound_client(true), &format!("{origin}/t-parity/v2"), crate::scim::Auth::from_parts("bearer", None, "dev-token")),
        sealer(),
    );
    let door = Target::Doorkey(keyhole(&origin, "t-parity"));

    // Create via SCIM, then deactivate the very same user via the Doorkey: one app, two transports.
    let (u, ev) = confirmed(scim.create_user("parity@demo.example", "Par", "Ity", "parity@demo.example").await.unwrap());
    assert!(u.active);
    assert_eq!((ev.doorkey.as_str(), ev.verified_by.as_str()), ("scim", "get_user"));
    door.set_active(&u.id, false).await.unwrap();
    assert!(!door.list_users().await.unwrap().iter().find(|x| x.id == u.id).unwrap().active);
    // And back through SCIM, which reads the change back as well.
    scim.set_active(&u.id, true).await.unwrap();
    scim.delete_user(&u.id).await.unwrap();
}

// --- evidence ---------------------------------------------------------------------------------

#[tokio::test]
async fn evidence_names_the_user_and_is_signed() {
    let origin = spawn_mock().await;
    let key = sealer();
    let trusted = [key.public_key().to_string()];
    let keyhole = Keyhole::new(parse(mock_json(&origin, "t-evidence")), "dev-token", key.clone(), true).unwrap().stamped("tenant-1", "app-1", "prev-hash");
    let target = Target::Doorkey(keyhole);
    let (u, _) = confirmed(target.create_user("leaver@demo.example", "Lea", "Ver", "leaver@demo.example").await.unwrap());
    let ev = target.set_active(&u.id, false).await.unwrap();

    assert_eq!(ev.subject_id, u.id);
    assert_eq!(ev.subject_user_name, "leaver@demo.example");
    assert_eq!(ev.status, Some(200));
    assert_eq!((ev.tenant.as_str(), ev.app.as_str(), ev.prev.as_str()), ("tenant-1", "app-1", "prev-hash"));
    assert_eq!(ev.key, trusted[0]);
    assert!(verify_evidence(&ev, &trusted));

    let mut edited = ev.clone();
    edited.subject_id = "someone-else".into();
    assert!(!verify_evidence(&edited, &trusted), "an edited record fails the check");
    let mut moved = ev.clone();
    moved.app = "app-2".into();
    assert!(!verify_evidence(&moved, &trusted), "the app and the chain link are signed too");
    let other = sealer();
    assert!(!verify_evidence(&ev, &[other.public_key().to_string()]), "another key cannot vouch for it");
    // Re-signing with another key does not help unless that key is trusted.
    let forged = other.seal(edited);
    assert!(!verify_evidence(&forged, &trusted));
    // The chain hash covers the signature, so it changes with any byte of the record.
    assert_ne!(evidence_hash(&ev), evidence_hash(&forged));
}

#[test]
fn bundled_doorkeys_only_load_with_their_signature() {
    // Every shipped spec is signed with the offline key; CI fails if a spec changes unsigned.
    for id in ["mock", "cloudflare", "asana", "anthropic", "openai", "atlassian", "github", "github-copilot", "linear", "microsoft365"] {
        load_bundled(id, "https://api.example.com/v1").unwrap_or_else(|e| panic!("{id}: {e:#}"));
    }
    let (spec, signature) = bundled("github").unwrap();
    let key = bundled_signing_key();
    assert!(verify_signature(spec.as_bytes(), signature, key).is_ok());

    // One changed byte (an extra allow rule, a different host) and the signature fails.
    let tampered = spec.replace("\"api.github.com\"", "\"*\"");
    assert_ne!(tampered, spec);
    assert!(verify_signature(tampered.as_bytes(), signature, key).is_err());
    // A key other than AppDoorman's cannot sign a spec this binary accepts.
    let other = Key::generate().bytes();
    assert!(verify_signature(spec.as_bytes(), &sign_spec(&other, spec.as_bytes()), key).is_err());
    assert!(verify_signature(spec.as_bytes(), &sign_spec(&other, spec.as_bytes()), &signing_public_key(&other)).is_ok());
    assert!(verify_signature(spec.as_bytes(), "not base64!", key).is_err());
}

#[test]
fn the_reference_doorkey_loads() {
    let raw = include_str!("../doorkeys/mock.doorkey.json").replace("REPLACE-WITH-APP-HOST", "app.example.com");
    let dk: Doorkey = serde_json::from_str(&raw).unwrap();
    Keyhole::new(dk.clone(), "t", sealer(), true).unwrap();
    // It names `*` for its hosts, which is for the built-in mock and never works in production.
    assert!(Keyhole::new(dk, "t", sealer(), false).is_err());
}

#[test]
fn the_credential_only_goes_to_the_doorkeys_own_hosts() {
    let at = |origin: &str| {
        let mut dk = mock_json(origin, "k");
        dk["hosts"] = json!(["*.example.com"]);
        Keyhole::new(parse(dk), "t", sealer(), false)
    };
    assert!(at("https://acme.example.com").is_ok());
    assert!(at("https://acme.enterprise.example.com").is_ok());
    assert!(at("https://ACME.Example.com").is_ok(), "host names are not case-sensitive");
    // A workspace URL edited to another server would hand it the admin credential.
    let err = at("https://attacker.test").err().expect("refused").to_string();
    assert!(err.contains("*.example.com") && err.contains("attacker.test"), "got {err}");
    assert!(at("https://evilexample.com").is_err(), "a suffix match needs a dot");
    assert!(at("https://example.com.attacker.test").is_err());
    assert!(at("https://example.com").is_err(), "`*.example.com` is a subdomain, not example.com itself");

    // A Doorkey must name its hosts, and a pattern cannot cover a whole top-level domain.
    let mock = |hosts: Value| {
        let mut dk = mock_json("https://app.example.com", "k");
        dk["hosts"] = hosts;
        Keyhole::new(parse(dk), "t", sealer(), false)
    };
    assert!(mock(json!(["app.example.com"])).is_ok());
    assert!(mock(json!(["*.example.com"])).is_ok());
    for bad in [json!([]), json!(["*.com"]), json!(["App.example.com"]), json!(["app.example.com/v2"]), json!(["*"])] {
        assert!(mock(bad.clone()).is_err(), "hosts {bad} must be refused in production");
    }
    assert!(serde_json::from_value::<Doorkey>({
        let mut dk = mock_json("https://app.example.com", "k");
        dk.as_object_mut().unwrap().remove("hosts");
        dk
    })
    .is_err(), "`hosts` is required, so a Doorkey cannot forget it");
}

#[test]
fn a_credential_that_cannot_be_sent_intact_is_refused_up_front() {
    // A bearer token is sent as one header value.
    let bearer = |t: &str| Keyhole::new(parse(mock_json("http://127.0.0.1:1", "k")), t, sealer(), true);
    assert!(bearer("dev-token").is_ok());
    assert!(bearer("").is_err());
    assert!(bearer("t\nX-Evil: 1").is_err());
}

// --- pure helpers -------------------------------------------------------------------------------

#[test]
fn body_templating_preserves_types() {
    let ctx = Map::from_iter([("active".into(), json!(false)), ("user_name".into(), json!("a@b.com"))]);
    let out = render_value(&json!({ "value": "{active}", "who": "user {user_name}" }), &ctx).unwrap();
    assert_eq!(out["value"], json!(false)); // a lone {active} keeps its boolean type
    assert_eq!(out["who"], json!("user a@b.com")); // spliced into a string
}

#[test]
fn templating_is_single_pass_and_strict() {
    // A value containing a placeholder is never expanded a second time.
    let ctx = Map::from_iter([("given".into(), json!("{email}")), ("email".into(), json!("x@y.eu"))]);
    assert_eq!(render("hi {given}", &ctx, false).unwrap(), "hi {email}");
    // A missing value is an error, not literal text; braces that are not a placeholder pass.
    assert_eq!(render("/Users/{id}", &ctx, true).unwrap_err(), "id");
    assert_eq!(render("{ not a param }", &ctx, false).unwrap(), "{ not a param }");
    // Path values are encoded, so they stay one segment.
    let ctx = Map::from_iter([("id".into(), json!("a/b?c"))]);
    assert_eq!(render("/Users/{id}", &ctx, true).unwrap(), "/Users/a%2Fb%3Fc");
}

#[test]
fn path_matching_respects_segments() {
    assert!(path_matches("/v2/Users/{id}", "/v2/Users/mock-3"));
    assert!(!path_matches("/v2/Users/{id}", "/v2/Users"));
    assert!(!path_matches("/v2/Users/{id}", "/v2/Groups/mock-3"));
    assert!(!path_matches("/v2/Users/{id}", "/v2/Users/a/b"));
}

#[test]
fn shape_fingerprint_ignores_values_but_not_structure() {
    let a = json!({ "id": "1", "active": true });
    let b = json!({ "id": "2", "active": false }); // same shape, different values
    let c = json!({ "id": "3", "active": "yes" }); // active changed type
    assert_eq!(shape_fingerprint(&a), shape_fingerprint(&b));
    assert_ne!(shape_fingerprint(&a), shape_fingerprint(&c));
}

// --- An inverted active flag ----------------------------------------------------------------------

#[test]
fn active_inverted_reads_a_deleted_flag_as_the_opposite() {
    let ex = Extract { list: None, id: "id".into(), user_name: "name".into(), active: Some("deleted".into()), active_inverted: true, active_when: None, skip: vec![], skip_when_set: vec![] };
    assert_eq!(extracted_active(&ex, &json!({ "id": "u", "name": "n", "deleted": false })), Some(true));
    assert_eq!(extracted_active(&ex, &json!({ "id": "u", "name": "n", "deleted": true })), Some(false));
    assert!(matches(&ex, &json!({ "deleted": true }), &Map::from_iter([("active".into(), json!(false))])));
}

// --- An app with a member list and no suspend ---------------------------------------------------

#[test]
fn an_app_without_an_active_flag_can_only_add_and_remove() {
    let membership = || {
        let mut dk = mock_json("https://app.example.com", "k");
        for op in ["list_users", "find_user", "create_user"] {
            dk["ops"][op]["extract"].as_object_mut().unwrap().remove("active");
        }
        dk["ops"]["create_user"]["verify"]["present"]["expect"] = json!({ "user_name": "{user_name}" });
        for op in ["deactivate_user", "reactivate_user"] {
            dk["ops"].as_object_mut().unwrap().remove(op);
        }
        dk
    };
    let load = |dk: Value| Keyhole::new(parse(dk), "t", sealer(), true).map(|_| ()).map_err(|e| format!("{e:#}"));
    load(membership()).unwrap();
    assert!(!parse(membership()).can_suspend() && !parse(membership()).has_active_flag());
    assert!(parse(mock_json("https://app.example.com", "k")).can_suspend());

    // A suspend could never be confirmed without the flag.
    let mut dk = membership();
    dk["ops"]["deactivate_user"] = mock_json("https://app.example.com", "k")["ops"]["deactivate_user"].clone();
    assert!(load(dk).unwrap_err().contains("deactivate_user"));
    // Without a delete there would be no way to take access away.
    let mut dk = membership();
    dk["ops"].as_object_mut().unwrap().remove("delete_user");
    assert!(load(dk).unwrap_err().contains("delete_user"));
    // A read-back expecting an active value it cannot read would fail every change.
    let mut dk = membership();
    dk["ops"]["create_user"]["verify"]["present"]["expect"]["active"] = json!(true);
    assert!(load(dk).unwrap_err().contains("expects an `active`"));
    // Every read agrees on whether there is a flag, and an inversion needs a flag to invert.
    let mut dk = membership();
    dk["ops"]["find_user"]["extract"]["active"] = json!("active");
    assert!(load(dk).unwrap_err().contains("disagrees"));
    let mut dk = membership();
    dk["ops"]["list_users"]["extract"]["active_inverted"] = json!(true);
    assert!(load(dk).unwrap_err().contains("active_inverted"));
}

// --- Cloudflare: account members, roles looked up by name ---------------------------------------

/// Cloudflare's account members API as its documentation describes it: every answer wrapped in
/// `{ success, errors, messages, result }`, page paging with `result_info.total_count`, invites
/// listed at once as `pending` members, roles with per-account ids, and a 404 for a member who is
/// gone.
#[derive(Clone, Default)]
struct CloudflareState {
    members: Arc<Mutex<Vec<Value>>>,
    roles: Arc<Mutex<Vec<Value>>>,
    invited: Arc<Mutex<Vec<Value>>>,
    next: Arc<Mutex<u32>>,
}

impl CloudflareState {
    fn has(&self, id: &str) -> bool {
        self.members.lock().unwrap().iter().any(|m| m["id"] == id)
    }
}

fn cf_member(id: &str, email: &str, status: &str, role: &str) -> Value {
    json!({ "id": id, "status": status, "user": { "email": email }, "roles": [{ "id": role, "name": role }], "policies": [] })
}

fn cf_ok(result: Value) -> Response {
    ok(json!({ "success": true, "errors": [], "messages": [], "result": result }))
}

fn cf_err(status: StatusCode, code: u32, message: &str) -> Response {
    (status, axum::Json(json!({ "success": false, "errors": [{ "code": code, "message": message }], "messages": [], "result": null }))).into_response()
}

fn cf_authed(headers: &HeaderMap) -> Option<Response> {
    (headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) != Some("Bearer cf-test")).then(|| cf_err(StatusCode::FORBIDDEN, 10000, "Authentication error"))
}

async fn cf_list(State(s): State<CloudflareState>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if let Some(denied) = cf_authed(&headers) {
        return denied;
    }
    let members = s.members.lock().unwrap().clone();
    let page: usize = q.get("page").and_then(|p| p.parse().ok()).unwrap_or(1);
    let per_page: usize = q.get("per_page").and_then(|p| p.parse().ok()).unwrap_or(20);
    let start = ((page - 1) * per_page).min(members.len());
    let end = (start + per_page).min(members.len());
    let result = members[start..end].to_vec();
    ok(json!({ "success": true, "errors": [], "messages": [], "result": result,
        "result_info": { "page": page, "per_page": per_page, "count": end - start, "total_count": members.len() } }))
}

async fn cf_get(State(s): State<CloudflareState>, headers: HeaderMap, axum::extract::Path((_, id)): axum::extract::Path<(String, String)>) -> Response {
    if let Some(denied) = cf_authed(&headers) {
        return denied;
    }
    match s.members.lock().unwrap().iter().find(|m| m["id"] == id.as_str()) {
        Some(m) => cf_ok(m.clone()),
        None => cf_err(StatusCode::NOT_FOUND, 1003, "Member not found"),
    }
}

async fn cf_roles(State(s): State<CloudflareState>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if let Some(denied) = cf_authed(&headers) {
        return denied;
    }
    // Paged like members: Cloudflare has dozens of roles, and Administrator is not on page one.
    let roles = s.roles.lock().unwrap().clone();
    let page: usize = q.get("page").and_then(|p| p.parse().ok()).unwrap_or(1);
    let per_page: usize = q.get("per_page").and_then(|p| p.parse().ok()).unwrap_or(20);
    let start = ((page - 1) * per_page).min(roles.len());
    let end = (start + per_page).min(roles.len());
    ok(json!({ "success": true, "errors": [], "messages": [], "result": roles[start..end],
        "result_info": { "page": page, "per_page": per_page, "count": end - start, "total_count": roles.len() } }))
}

async fn cf_create(State(s): State<CloudflareState>, headers: HeaderMap, axum::Json(body): axum::Json<Value>) -> Response {
    if let Some(denied) = cf_authed(&headers) {
        return denied;
    }
    s.invited.lock().unwrap().push(body.clone());
    let email = body["email"].as_str().unwrap_or_default().to_string();
    let roles = s.roles.lock().unwrap().clone();
    let Some(role) = body["roles"].get(0).and_then(Value::as_str).filter(|r| roles.iter().any(|x| x["id"] == *r)) else {
        return cf_err(StatusCode::BAD_REQUEST, 1001, "Invalid role");
    };
    if s.members.lock().unwrap().iter().any(|m| m["user"]["email"].as_str().is_some_and(|e| e.eq_ignore_ascii_case(&email))) {
        return cf_err(StatusCode::BAD_REQUEST, 1004, "User is already a member of this account");
    }
    let id = {
        let mut n = s.next.lock().unwrap();
        *n += 1;
        format!("{:032x}", *n)
    };
    let member = cf_member(&id, &email, "pending", role);
    s.members.lock().unwrap().push(member.clone());
    cf_ok(member)
}

async fn cf_delete(State(s): State<CloudflareState>, headers: HeaderMap, axum::extract::Path((_, id)): axum::extract::Path<(String, String)>) -> Response {
    if let Some(denied) = cf_authed(&headers) {
        return denied;
    }
    let mut members = s.members.lock().unwrap();
    let before = members.len();
    members.retain(|m| m["id"] != id.as_str());
    if members.len() == before {
        return cf_err(StatusCode::NOT_FOUND, 1003, "Member not found");
    }
    cf_ok(json!({ "id": id }))
}

async fn spawn_cloudflare() -> (String, CloudflareState) {
    let state = CloudflareState::default();
    *state.members.lock().unwrap() = vec![
        cf_member("a0", "Owner@Acme.example", "accepted", "r-super"),
        cf_member("a1", "ops@acme.example", "accepted", "r-admin"),
        cf_member("a2", "invited@acme.example", "pending", "r-admin"),
    ];
    let mut roles: Vec<Value> = (0..60).map(|n| json!({ "id": format!("r-{n}"), "name": format!("Fine-grained role {n}") })).collect();
    roles.extend([
        json!({ "id": "r-super", "name": "Super Administrator - All Privileges" }),
        json!({ "id": "r-admin", "name": "Administrator" }),
        json!({ "id": "r-ro", "name": "Administrator Read Only" }),
    ]);
    *state.roles.lock().unwrap() = roles;
    let app = axum::Router::new()
        .route("/client/v4/accounts/{account}/members", axum::routing::get(cf_list).post(cf_create))
        .route("/client/v4/accounts/{account}/members/{id}", axum::routing::get(cf_get).delete(cf_delete))
        .route("/client/v4/accounts/{account}/roles", axum::routing::get(cf_roles))
        .with_state(state.clone());
    (serve(app).await, state)
}

/// The shipped Cloudflare Doorkey as JSON, pointed at the fake's account.
fn cloudflare_json(origin: &str) -> Value {
    let mut dk: Value = serde_json::from_str(include_str!("../doorkeys/cloudflare.doorkey.json")).unwrap();
    dk["base_url"] = json!(format!("{origin}/client/v4/accounts/acct1"));
    dk["hosts"] = json!(["127.0.0.1"]);
    dk
}

fn cloudflare_target(dk: Value) -> Target {
    Target::Doorkey(Keyhole::new(parse(dk), "cf-test", sealer(), true).unwrap())
}

#[tokio::test]
async fn cloudflare_lists_members_and_waiting_invites_across_pages() {
    let (origin, _) = spawn_cloudflare().await;
    let mut dk = cloudflare_json(&origin);
    dk["ops"]["list_users"]["paginate"]["size"] = json!(2);
    let users = cloudflare_target(dk).list_users().await.unwrap();
    let names: Vec<_> = users.iter().map(|u| u.user_name.as_str()).collect();
    // A pending invite is a member too, so a leaver who never accepted can still be removed.
    assert_eq!(names, ["Owner@Acme.example", "ops@acme.example", "invited@acme.example"]);
    assert!(users.iter().all(|u| u.active));
}

#[tokio::test]
async fn cloudflare_invites_as_the_administrator_role_it_looks_up_and_removes() {
    let (origin, state) = spawn_cloudflare().await;
    let target = cloudflare_target(cloudflare_json(&origin));
    assert!(target.supports_delete() && !target.supports_suspend());

    let (user, ev) = confirmed(target.create_user("new.hire@acme.example", "New", "Hire", "New.Hire@acme.example").await.unwrap());
    assert_eq!((user.user_name.as_str(), user.active), ("New.Hire@acme.example", true));
    assert_eq!((ev.op.as_str(), ev.verified_by.as_str(), ev.status), ("create_user", "find_user", Some(200)));
    // The role id came from this account's role list, by name.
    let sent = state.invited.lock().unwrap()[0].clone();
    assert_eq!(sent, json!({ "email": "New.Hire@acme.example", "roles": ["r-admin"], "status": "pending" }));

    let ev = target.delete_user(&user.id).await.unwrap();
    assert_eq!((ev.op.as_str(), ev.verified_by.as_str()), ("delete_user", "find_user"));
    // The record names who was removed, as Cloudflare listed them just before.
    assert_eq!((ev.subject_id.as_str(), ev.subject_user_name.as_str()), (user.id.as_str(), "New.Hire@acme.example"));
    assert!(!state.has(&user.id));
    // An invite nobody accepted is removed the same way.
    target.delete_user("a2").await.unwrap();
    assert!(!state.has("a2"));
}

#[tokio::test]
async fn cloudflare_sends_no_invite_unless_exactly_one_role_matches() {
    let (origin, state) = spawn_cloudflare().await;
    let target = cloudflare_target(cloudflare_json(&origin));
    let invite = || target.create_user("x@acme.example", "X", "Y", "x@acme.example");

    state.roles.lock().unwrap().retain(|r| r["name"] != "Administrator");
    let err = keyhole_err(invite().await.unwrap_err());
    assert!(matches!(&err, KeyholeError::LookupFailed { key, found: 0, .. } if key == "role_id"), "got {err:?}");
    assert!(err.to_string().contains("(it has: Fine-grained role 0, Fine-grained role 1,"), "got {err}");

    state.roles.lock().unwrap().extend([json!({ "id": "r-a", "name": "Administrator" }), json!({ "id": "r-b", "name": "Administrator" })]);
    let err = keyhole_err(invite().await.unwrap_err());
    assert!(matches!(&err, KeyholeError::LookupFailed { found: 2, .. }), "got {err:?}");
    assert!(state.invited.lock().unwrap().is_empty(), "nothing was sent");
}

#[tokio::test]
async fn cloudflare_failures_say_why() {
    let (origin, _) = spawn_cloudflare().await;
    let target = cloudflare_target(cloudflare_json(&origin));
    let err = keyhole_err(target.create_user("ops@acme.example", "O", "P", "ops@acme.example").await.unwrap_err());
    assert_eq!(err.to_string(), "the app returned HTTP 400 for `/client/v4/accounts/acct1/members`: User is already a member of this account");
    let err = keyhole_err(target.delete_user("ffff").await.unwrap_err());
    assert!(matches!(err, KeyholeError::Http(404, ..)), "got {err:?}");
    // A wrong token is an error, never an empty member list.
    let k = Keyhole::new(parse(cloudflare_json(&origin)), "cf-wrong", sealer(), true).unwrap();
    let err = keyhole_err(Target::Doorkey(k).list_users().await.unwrap_err());
    assert!(matches!(err, KeyholeError::Http(403, ..)) && err.to_string().ends_with("Authentication error"), "got {err}");
}

#[test]
fn the_cloudflare_doorkey_only_reaches_cloudflare() {
    let at = |base: &str| {
        let mut dk: Value = serde_json::from_str(include_str!("../doorkeys/cloudflare.doorkey.json")).unwrap();
        dk["base_url"] = json!(base);
        Keyhole::new(parse(dk), "cf-x", sealer(), false)
    };
    assert!(at("https://api.cloudflare.com/client/v4/accounts/0123456789abcdef0123456789abcdef").is_ok());
    assert!(at("https://api.cloudflare.com.attacker.example/client/v4/accounts/x").is_err());
    assert!(at("https://dash.cloudflare.com/client/v4/accounts/x").is_err(), "only the API host");
}

#[test]
fn lookups_are_checked_when_the_doorkey_loads() {
    let with = |l: Value| {
        let mut dk = cloudflare_json("http://127.0.0.1:1");
        dk["ops"]["create_user"]["lookup"] = l;
        Keyhole::new(parse(dk), "t", sealer(), true).map(|_| ()).map_err(|e| format!("{e:#}"))
    };
    let role = |op: &str| json!({ "role_id": { "op": op, "list": "result", "where": { "name": "Administrator" }, "take": "id" } });
    with(role("list_roles")).unwrap();
    // Only a read may be used, and only one the Doorkey has.
    assert!(with(role("delete_user")).unwrap_err().contains("must be a read"));
    assert!(with(role("nope")).unwrap_err().contains("unknown op"));
    // A lookup without `where` would take whatever came first.
    assert!(with(json!({ "role_id": { "op": "list_roles", "list": "result", "where": {}, "take": "id" } })).unwrap_err().contains("without a `where`"));
    // A lookup cannot replace the address an invite goes to.
    assert!(with(json!({ "email": { "op": "list_roles", "list": "result", "where": { "name": "x" }, "take": "id" } })).unwrap_err().contains("not a free parameter"));
}

// --- Asana: organization memberships, invited and removed by email --------------------------------

/// Asana's organization API as a live Advanced organization answered it: every answer wrapped in
/// `{ data }`, compact records unless `opt_fields` names more, memberships paged with an opaque
/// `next_page.offset` (null on the last page), an invite listed at once as an active member, a
/// removed member gone from the list, and failures as `{ errors: [{ message }] }`.
#[derive(Clone, Default)]
struct AsanaState {
    memberships: Arc<Mutex<Vec<Value>>>,
    added: Arc<Mutex<Vec<Value>>>,
    next: Arc<Mutex<u32>>,
}

impl AsanaState {
    fn is_member(&self, gid: &str) -> bool {
        self.memberships.lock().unwrap().iter().any(|m| m["user"]["gid"] == gid)
    }
}

fn asana_membership(gid: &str, email: &str, active: bool) -> Value {
    json!({ "gid": format!("m{gid}"), "user": { "gid": gid, "email": email, "name": email }, "is_active": active })
}

fn asana_err(status: StatusCode, message: &str) -> Response {
    (status, axum::Json(json!({ "errors": [{ "message": message, "help": "For more information on API status codes and how to handle them, read the docs on errors: https://developers.asana.com/docs/errors" }] }))).into_response()
}

fn asana_authed(headers: &HeaderMap) -> Option<Response> {
    (headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) != Some("Bearer as-test")).then(|| asana_err(StatusCode::UNAUTHORIZED, "Not Authorized"))
}

/// Keep only the fields `opt_fields` asks for (dotted, comma-separated), as Asana does; `gid` always.
fn asana_fields(item: &Value, opt_fields: Option<&String>) -> Value {
    let mut out = json!({ "gid": item["gid"] });
    for field in opt_fields.map(|f| f.split(',').collect::<Vec<_>>()).unwrap_or_default() {
        let mut path = field.split('.').peekable();
        let (mut from, mut to) = (item, &mut out);
        while let Some(key) = path.next() {
            if path.peek().is_none() {
                to[key] = from[key].clone();
            } else {
                from = &from[key];
                if to.get(key).is_none() {
                    to[key] = json!({ "gid": from["gid"] });
                }
                to = &mut to[key];
            }
        }
    }
    out
}

async fn as_memberships(State(s): State<AsanaState>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if let Some(denied) = asana_authed(&headers) {
        return denied;
    }
    let all = s.memberships.lock().unwrap().clone();
    let start: usize = q.get("offset").and_then(|o| o.strip_prefix("cursor-")?.parse().ok()).unwrap_or(0).min(all.len());
    let limit: usize = q.get("limit").and_then(|l| l.parse().ok()).unwrap_or(all.len().max(1));
    let end = (start + limit).min(all.len());
    let data: Vec<Value> = all[start..end].iter().map(|m| asana_fields(m, q.get("opt_fields"))).collect();
    let next_page = (end < all.len()).then(|| json!({ "offset": format!("cursor-{end}"), "path": "", "uri": "" }));
    ok(json!({ "data": data, "next_page": next_page }))
}

async fn as_add_user(State(s): State<AsanaState>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>, axum::Json(body): axum::Json<Value>) -> Response {
    if let Some(denied) = asana_authed(&headers) {
        return denied;
    }
    s.added.lock().unwrap().push(body.clone());
    let Some(email) = body["data"]["user"].as_str().filter(|e| e.contains('@')) else {
        return asana_err(StatusCode::BAD_REQUEST, "user: Not an email address or ID");
    };
    // Asana keeps addresses in lower case.
    let email = email.to_ascii_lowercase();
    let gid = {
        let mut n = s.next.lock().unwrap();
        *n += 1;
        format!("12198{:010}", *n)
    };
    let member = asana_membership(&gid, &email, true);
    s.memberships.lock().unwrap().push(member.clone());
    ok(json!({ "data": asana_fields(&member["user"], q.get("opt_fields")) }))
}

async fn as_remove_user(State(s): State<AsanaState>, headers: HeaderMap, axum::Json(body): axum::Json<Value>) -> Response {
    if let Some(denied) = asana_authed(&headers) {
        return denied;
    }
    let gid = body["data"]["user"].as_str().unwrap_or_default().to_string();
    let mut members = s.memberships.lock().unwrap();
    let before = members.len();
    members.retain(|m| m["user"]["gid"] != gid.as_str());
    if members.len() == before {
        return asana_err(StatusCode::NOT_FOUND, &format!("user: Not a recognized ID: {gid}"));
    }
    ok(json!({ "data": {} }))
}

async fn spawn_asana() -> (String, AsanaState) {
    let state = AsanaState::default();
    *state.memberships.lock().unwrap() = vec![
        asana_membership("1001", "owner@acme.example", true),
        asana_membership("1002", "ops@acme.example", true),
        asana_membership("1003", "gone@acme.example", false),
        asana_membership("1004", "guest@partner.example", true),
    ];
    let app = axum::Router::new()
        .route("/api/1.0/workspaces/{ws}/workspace_memberships", axum::routing::get(as_memberships))
        .route("/api/1.0/workspaces/{ws}/addUser", axum::routing::post(as_add_user))
        .route("/api/1.0/workspaces/{ws}/removeUser", axum::routing::post(as_remove_user))
        .with_state(state.clone());
    (serve(app).await, state)
}

/// The shipped Asana Doorkey as JSON, pointed at the fake's organization.
fn asana_json(origin: &str) -> Value {
    let mut dk: Value = serde_json::from_str(include_str!("../doorkeys/asana.doorkey.json")).unwrap();
    dk["base_url"] = json!(format!("{origin}/api/1.0/workspaces/1219840155648564"));
    dk["hosts"] = json!(["127.0.0.1"]);
    dk
}

fn asana_target(dk: Value) -> Target {
    Target::Doorkey(Keyhole::new(parse(dk), "as-test", sealer(), true).unwrap())
}

#[tokio::test]
async fn asana_lists_active_members_across_cursor_pages() {
    let (origin, _) = spawn_asana().await;
    let mut dk = asana_json(&origin);
    dk["ops"]["list_users"]["paginate"]["size"] = json!(1);
    let users = asana_target(dk).list_users().await.unwrap();
    let names: Vec<_> = users.iter().map(|u| (u.id.as_str(), u.user_name.as_str())).collect();
    // The inactive membership has no access and is left out; guests are people like anyone else.
    assert_eq!(names, [("1001", "owner@acme.example"), ("1002", "ops@acme.example"), ("1004", "guest@partner.example")]);
    assert!(users.iter().all(|u| u.active));
}

#[tokio::test]
async fn asana_invites_by_email_and_removes_by_id() {
    let (origin, state) = spawn_asana().await;
    let target = asana_target(asana_json(&origin));
    assert!(target.supports_delete() && !target.supports_suspend());

    let (user, ev) = confirmed(target.create_user("New.Hire@acme.example", "New", "Hire", "New.Hire@acme.example").await.unwrap());
    // Asana lower-cases the address; the read-back still recognises the person.
    assert_eq!((user.user_name.as_str(), user.active), ("new.hire@acme.example", true));
    assert_eq!((ev.op.as_str(), ev.verified_by.as_str(), ev.status), ("create_user", "list_users", Some(200)));
    assert_eq!(state.added.lock().unwrap()[0], json!({ "data": { "user": "New.Hire@acme.example" } }));

    let ev = target.delete_user(&user.id).await.unwrap();
    assert_eq!((ev.op.as_str(), ev.verified_by.as_str()), ("delete_user", "list_users"));
    assert_eq!((ev.subject_id.as_str(), ev.subject_user_name.as_str()), (user.id.as_str(), "new.hire@acme.example"));
    assert!(!state.is_member(&user.id));
}

#[tokio::test]
async fn asana_failures_say_why() {
    let (origin, _) = spawn_asana().await;
    let target = asana_target(asana_json(&origin));
    let err = keyhole_err(target.delete_user("999").await.unwrap_err());
    assert!(matches!(err, KeyholeError::Http(404, ..)) && err.to_string().ends_with("user: Not a recognized ID: 999"), "got {err}");
    // A wrong token is an error, never an empty member list.
    let k = Keyhole::new(parse(asana_json(&origin)), "as-wrong", sealer(), true).unwrap();
    let err = keyhole_err(Target::Doorkey(k).list_users().await.unwrap_err());
    assert!(matches!(err, KeyholeError::Http(401, ..)) && err.to_string().ends_with("Not Authorized"), "got {err}");
}

#[test]
fn the_asana_doorkey_only_reaches_asana() {
    let at = |base: &str| {
        let mut dk: Value = serde_json::from_str(include_str!("../doorkeys/asana.doorkey.json")).unwrap();
        dk["base_url"] = json!(base);
        Keyhole::new(parse(dk), "as-x", sealer(), false)
    };
    assert!(at("https://app.asana.com/api/1.0/workspaces/1219840155648564").is_ok());
    assert!(at("https://app.asana.com.attacker.example/api/1.0/workspaces/1").is_err());
    assert!(at("https://asana.com/api/1.0/workspaces/1").is_err(), "only the API host");
}

// --- Organization Admin APIs (Anthropic, OpenAI): constant headers, invites, withdrawal ----------

use super::fakes::{self, Vendor};

fn admin_target(vendor: Vendor, origin: &str, page: u32) -> Target {
    let mut dk = fakes::doorkey(vendor, origin);
    for op in ["list_users", "list_invites"] {
        if let Some(Paginate::Cursor { size, .. }) = &mut dk.ops.get_mut(op).unwrap().paginate {
            *size = Some(page);
        }
    }
    Target::Doorkey(Keyhole::new(dk, vendor.token(), sealer(), true).unwrap())
}

#[tokio::test]
async fn admin_apis_invite_settle_remove_and_withdraw_a_leavers_invite() {
    for vendor in [Vendor::Anthropic, Vendor::OpenAi] {
        let (origin, api) = fakes::spawn(vendor).await;
        for n in 0..3 {
            api.add_user(&format!("p{n}@acme.example"), false);
        }
        // Pages of one: every member is read, and the empty page after the last one ends the walk.
        let target = admin_target(vendor, &origin, 1);
        assert!(target.supports_delete() && target.supports_withdraw() && !target.supports_suspend());
        assert_eq!(target.list_users().await.unwrap().len(), 3);

        // An invite is pending until accepted; once accepted, the member is listed and removable.
        let created = target.create_user("new@acme.example", "N", "H", "New@acme.example").await.unwrap();
        assert!(matches!(created, Created::Pending(_)), "an invite is pending until accepted");
        let id = api.accept("New@acme.example");
        assert!(target.list_users().await.unwrap().iter().any(|u| u.id == id));
        let ev = target.delete_user(&id).await.unwrap();
        assert_eq!((ev.op.as_str(), ev.verified_by.as_str()), ("delete_user", "find_user"));

        // A leaver who never accepted: the pending invite is found by email, in any case, and withdrawn.
        target.create_user("leaver@acme.example", "L", "V", "Leaver@Acme.example").await.unwrap();
        let ev = target.withdraw_invite("leaver@acme.example", "Leaver@Acme.example").await.unwrap();
        assert_eq!((ev.op.as_str(), ev.verified_by.as_str(), ev.subject_user_name.as_str()), ("withdraw_invite", "list_invites", "Leaver@Acme.example"));
        assert!(ev.subject_id.starts_with("invite_"), "the record names the invite it withdrew");
        assert!(api.status_of_invite("Leaver@Acme.example").is_empty());
        // Nothing pending for them any more (accepted, expired or withdrawn): nothing is sent.
        let err = keyhole_err(target.withdraw_invite("new@acme.example", "New@acme.example").await.unwrap_err());
        assert!(matches!(err, KeyholeError::LookupFailed { found: 0, .. }), "got {err:?}");
    }
}

#[tokio::test]
async fn anthropic_sends_its_version_header_and_openai_leaves_service_accounts_out() {
    let (origin, api) = fakes::spawn(Vendor::Anthropic).await;
    api.add_user("a@acme.example", false);
    // The fake refuses a request without anthropic-version; the Doorkey's constant header carries it.
    assert_eq!(admin_target(Vendor::Anthropic, &origin, 20).list_users().await.unwrap().len(), 1);
    let mut bare = fakes::doorkey(Vendor::Anthropic, &origin);
    bare.headers.clear();
    let err = keyhole_err(Target::Doorkey(Keyhole::new(bare, Vendor::Anthropic.token(), sealer(), true).unwrap()).list_users().await.unwrap_err());
    assert!(matches!(err, KeyholeError::Http(401, ..)), "got {err:?}");

    let (origin, api) = fakes::spawn(Vendor::OpenAi).await;
    api.add_user("a@acme.example", false);
    api.add_user("", true);
    let users = admin_target(Vendor::OpenAi, &origin, 20).list_users().await.unwrap();
    assert_eq!(users.iter().map(|u| u.user_name.as_str()).collect::<Vec<_>>(), ["a@acme.example"], "service accounts are not people");
}

#[tokio::test]
async fn a_refusal_with_a_known_code_says_what_to_change() {
    let (origin, _api) = fakes::spawn(Vendor::OpenAi).await;
    let target = admin_target(Vendor::OpenAi, &origin, 20);
    let err = keyhole_err(target.create_user("x@blocked.example", "X", "Y", "x@blocked.example").await.unwrap_err());
    let text = err.to_string();
    assert!(matches!(err, KeyholeError::Http(400, ..)), "got {err:?}");
    assert!(text.contains("make someone on your company's domain the organization's owner"), "{text}");
    assert!(!text.contains("contact OpenAI Support"), "the hint replaces OpenAI's own wording: {text}");
}

#[test]
fn constant_headers_cannot_touch_auth_or_framing() {
    let with = |name: &str, value: &str| {
        let mut dk = mock_json("http://127.0.0.1:1", "k");
        dk["headers"] = json!({ name: value });
        serde_json::from_value::<Doorkey>(dk).map_err(|e| e.to_string()).and_then(|d| Keyhole::new(d, "t", sealer(), true).map(|_| ()).map_err(|e| format!("{e:#}")))
    };
    with("anthropic-version", "2023-06-01").unwrap();
    with("Accept", "application/vnd.heroku+json; version=3").unwrap();
    for reserved in ["Authorization", "cookie", "Host", "Content-Type", "Proxy-Authorization"] {
        assert!(with(reserved, "x").unwrap_err().contains("may not be set"), "{reserved}");
    }
    assert!(with("x-version", "{id}").unwrap_err().contains("constant"), "never templated");
    assert!(with("x-version", "a\r\nInjected: 1").unwrap_err().contains("constant"));
    assert!(with("bad header", "x").unwrap_err().contains("may not be set"));
    // The header a credential is sent in can't be overwritten with a constant either.
    let mut dk: Value = serde_json::from_str(include_str!("../doorkeys/anthropic.doorkey.json")).unwrap();
    dk["headers"]["X-Api-Key"] = json!("constant");
    assert!(Keyhole::new(parse(dk), "t", sealer(), true).is_err());
}

#[test]
fn a_withdrawal_must_confirm_the_invite_is_gone() {
    let mut dk: Value = serde_json::from_str(include_str!("../doorkeys/anthropic.doorkey.json")).unwrap();
    dk["base_url"] = json!("http://127.0.0.1:1/v1/organizations");
    dk["ops"]["withdraw_invite"]["verify"] = json!({ "present": { "op": "list_invites", "expect": {} } });
    let err = Keyhole::new(parse(dk), "t", sealer(), true).map(|_| ()).unwrap_err();
    assert!(format!("{err:#}").contains("absent"), "{err:#}");
}

// --- GraphQL ops: one signed document per op, read or change by its kind ------------------------

#[test]
fn graphql_documents_are_read_strictly() {
    use super::graphql::{parse, Kind};
    let op = parse("query List($page: Int!, $limit: Int = 50) { users(page: $page, limit: $limit, status: [ACTIVE]) { id email } }").unwrap();
    assert_eq!(
        (op.kind, op.root_fields, op.variables),
        (
            Kind::Query,
            vec!["users".to_string()],
            vec!["page".to_string(), "limit".to_string()]
        )
    );
    // An alias names the real field; strings, comments and commas are skipped.
    let op = parse("# note\nmutation { gone: deactivate_users(user_ids: [\"1\", \"2\"]) { errors { message } }, me { id } }").unwrap();
    assert_eq!(
        (op.kind, op.root_fields),
        (
            Kind::Mutation,
            vec!["deactivate_users".to_string(), "me".to_string()]
        )
    );
    let op =
        parse("query { users(name: \"a } { b\", note: \"\"\"x \\\"\"\" y\"\"\") { id } }").unwrap();
    assert_eq!(op.root_fields, ["users"]);

    for (bad, why) in [
        ("{ users { id } }", "shorthand"),
        ("subscription { users { id } }", "subscription"),
        ("query A { users { id } } mutation B { deactivate_users(user_ids: [1]) { errors { message } } }", "two operations"),
        ("query { users { ...F } } fragment F on User { id }", "fragments"),
        ("query { ... on Query { users { id } } }", "inline fragment"),
        ("query { users @include(if: true) { id } }", "directive"),
        ("query { users(ids: [$id]) { id } }", "undeclared variable"),
        ("query ($a: Int, $a: Int) { users { id } }", "declared twice"),
        ("query { users(name: \"open) { id } }", "unterminated string"),
        ("query { users { id }", "unclosed"),
        ("query { }", "empty"),
        ("query { \"users\" }", "a value at the top"),
    ] {
        assert!(parse(bad).is_err(), "{why}: {bad}");
    }
}

/// A small GraphQL Doorkey against `origin`, for checking what loads.
fn graphql_json(origin: &str) -> Value {
    json!({
        "doorkey": "gql", "version": 1, "base_url": origin, "hosts": ["127.0.0.1"],
        "auth": { "scheme": "bearer" },
        "allow": [{ "method": "POST", "path": "/graphql", "params": [], "graphql": ["users", "deactivate_users", "activate_users"] }],
        "ops": {
            "list_users": {
                "request": { "method": "POST", "path": "/graphql", "graphql": { "query": "query ($page: Int!, $limit: Int!) { users(page: $page, limit: $limit) { id email status } }" } },
                "paginate": { "style": "page", "param": "page", "size_param": "limit", "size": 2, "first": 1 },
                "extract": { "list": "data.users", "id": "id", "user_name": "email", "active": "status", "active_when": "ACTIVE" }
            },
            "deactivate_user": {
                "request": { "method": "POST", "path": "/graphql", "graphql": { "query": "mutation ($id: ID!) { deactivate_users(user_ids: [$id]) { errors { message } } }", "variables": { "id": "{id}" }, "errors_at": ["data.deactivate_users.errors"] } },
                "verify": { "present": { "op": "list_users", "expect": { "active": false } } }
            }
        }
    })
}

fn load_err(v: Value) -> String {
    match serde_json::from_value::<Doorkey>(v) {
        Ok(dk) => Keyhole::new(dk, "t", sealer(), true)
            .map(|_| String::new())
            .unwrap_or_else(|e| format!("{e:#}")),
        Err(e) => e.to_string(),
    }
}

#[test]
fn a_graphql_doorkey_is_capped_by_its_documents_and_root_fields() {
    assert_eq!(
        load_err(graphql_json("http://127.0.0.1:1")),
        "",
        "the reference shape loads"
    );
    let with = |edit: &dyn Fn(&mut Value)| {
        let mut dk = graphql_json("http://127.0.0.1:1");
        edit(&mut dk);
        load_err(dk)
    };
    // A mutation is a change whatever the method says, so it needs a read-back.
    let e = with(&|dk| {
        dk["ops"]["deactivate_user"]
            .as_object_mut()
            .unwrap()
            .remove("verify")
            .map(|_| ())
            .unwrap()
    });
    assert!(e.contains("no `verify`"), "{e}");
    // A mutation cannot be the read that confirms a change.
    let e = with(&|dk| {
        dk["ops"]["deactivate_user"]["verify"] =
            json!({ "present": { "op": "deactivate_user", "expect": {} } })
    });
    assert!(e.contains("must be a read"), "{e}");
    // A root field the allowlist does not name is refused when the Doorkey loads.
    let e = with(&|dk| {
        dk["ops"]["deactivate_user"]["request"]["graphql"]["query"] =
            json!("mutation ($id: ID!) { delete_users(user_ids: [$id]) { errors { message } } }")
    });
    assert!(e.contains("not covered"), "{e}");
    let e = with(&|dk| {
        dk["ops"]["deactivate_user"]["request"]["graphql"]["query"] = json!("mutation ($id: ID!) { deactivate_users(user_ids: [$id]) { errors { message } } add_teams_to_workspace(workspace_id: 1, team_ids: [1]) { id } }")
    });
    assert!(
        e.contains("not covered"),
        "a second root field is checked too: {e}"
    );
    // A REST rule never covers a GraphQL op, and a GraphQL rule never covers a REST op.
    let e = with(&|dk| {
        dk["allow"][0]
            .as_object_mut()
            .unwrap()
            .remove("graphql")
            .map(|_| ())
            .unwrap()
    });
    assert!(e.contains("not covered"), "{e}");
    let e = with(&|dk| {
        dk["ops"]["list_users"]["request"] = json!({ "method": "GET", "path": "/graphql" })
    });
    assert!(e.contains("not covered"), "{e}");
    // Only declared variables are filled in, paging included.
    let e = with(&|dk| {
        dk["ops"]["deactivate_user"]["request"]["graphql"]["variables"]["role"] = json!("ADMIN")
    });
    assert!(e.contains("does not declare"), "{e}");
    let e = with(&|dk| dk["ops"]["list_users"]["paginate"]["param"] = json!("offset"));
    assert!(e.contains("does not declare"), "{e}");
    let e = with(&|dk| {
        dk["ops"]["list_users"]["paginate"] = json!({ "style": "next_url", "path": "next", "param": "cursor" })
    });
    assert!(e.contains("cannot page by a next URL"), "{e}");
    // The document is the whole request: no method but POST, no body, form or URL query beside it.
    let e = with(&|dk| dk["ops"]["deactivate_user"]["request"]["body"] = json!({ "x": 1 }));
    assert!(e.contains("must be a POST"), "{e}");
    let e = with(&|dk| dk["ops"]["deactivate_user"]["request"]["query"] = json!({ "x": "1" }));
    assert!(e.contains("must be a POST"), "{e}");
    let e = with(&|dk| {
        dk["ops"]["deactivate_user"]["request"]["graphql"]["query"] =
            json!("{ deactivate_users(user_ids: [1]) { errors { message } } }")
    });
    assert!(e.contains("shorthand"), "{e}");
    let e =
        with(&|dk| dk["ops"]["deactivate_user"]["request"]["graphql"]["errors_at"] = json!([""]));
    assert!(e.contains("errors_at"), "{e}");
    let e = with(&|dk| dk["ops"]["deactivate_user"]["request"]["graphql"]["extra"] = json!(1));
    assert!(e.contains("unknown field"), "{e}");
}

#[tokio::test]
async fn a_graphql_answer_with_errors_fails_closed_even_on_http_200() {
    let answer: Arc<Mutex<Value>> = Arc::new(Mutex::new(json!({ "data": { "users": [] } })));
    let seen = answer.clone();
    let bodies: Arc<Mutex<Vec<Value>>> = Arc::default();
    let log = bodies.clone();
    let app = axum::Router::new().route(
        "/graphql",
        axum::routing::post(move |axum::Json(body): axum::Json<Value>| {
            let (seen, log) = (seen.clone(), log.clone());
            async move {
                // Only the first page holds anything, as a real list ends.
                let later = body["variables"]["page"].as_u64().is_some_and(|p| p > 1);
                log.lock().unwrap().push(body);
                ok(if later { json!({ "data": { "users": [] } }) } else { seen.lock().unwrap().clone() })
            }
        }),
    );
    let origin = serve(app).await;
    let target = Target::Doorkey(keyhole_from(graphql_json(&origin)));
    assert!(target.list_users().await.unwrap().is_empty());
    // The signed document goes out verbatim, with the paging values as typed variables.
    let sent = bodies.lock().unwrap()[0].clone();
    assert_eq!(sent["variables"], json!({ "page": 1, "limit": 2 }));
    assert_eq!(
        sent["query"],
        graphql_json(&origin)["ops"]["list_users"]["request"]["graphql"]["query"]
    );

    for (body, why) in [
        (
            json!({ "errors": [{ "message": "Daily limit exceeded", "extensions": { "code": "DAILY_LIMIT_EXCEEDED" } }] }),
            "DAILY_LIMIT_EXCEEDED: Daily limit exceeded",
        ),
        (
            json!({ "data": { "users": [] }, "errors": [{ "message": "partial", "extensions": { "code": "ASSET_UNAVAILABLE" } }] }),
            "ASSET_UNAVAILABLE: partial",
        ),
        (json!({ "data": null }), "no data"),
        (json!({ "account_id": 1 }), "no data"),
    ] {
        *answer.lock().unwrap() = body;
        let err = keyhole_err(target.list_users().await.unwrap_err());
        assert!(
            matches!(&err, KeyholeError::NotOk { error, .. } if error.contains(why)),
            "{why}: got {err:?}"
        );
    }
    // A status of another type is an error, never inactive.
    *answer.lock().unwrap() = json!({ "data": { "users": [{ "id": "1", "email": "a@acme.example", "status": 1 }] } });
    let err = keyhole_err(target.list_users().await.unwrap_err());
    assert!(
        matches!(err, KeyholeError::MissingField { .. }),
        "got {err:?}"
    );

    // A mutation whose own `errors` list is not empty failed, whatever else it says.
    *answer.lock().unwrap() = json!({ "data": { "deactivate_users": { "errors": [{ "code": "USER_NOT_FOUND", "message": "nope" }] } } });
    let err = keyhole_err(target.set_active("1", false).await.unwrap_err());
    assert!(
        matches!(&err, KeyholeError::NotOk { error, .. } if error == "USER_NOT_FOUND: nope"),
        "got {err:?}"
    );
}

// --- Atlassian: organization admin API v2, invite into a group, suspend and restore ------------

/// Atlassian's organization admin API v2 as its OpenAPI spec describes it: answers in `{ data }`,
/// lists paged by an opaque `links.next` cursor, a user's access as the composite `status`
/// (`active`, `suspended`, `not_invited`, `deactivated`, `for_deletion`), suspend and restore and
/// removal as bodiless 204s, and errors as `{ errors: [{ code, title }] }`. As the live org did on
/// 2026-11-04: reads take the directory `-`, changes need the user's own directory and answer 404
/// under `-`, a removed user is gone (404), and the single-user read shows a change `lag` reads late.
/// `list_invites` off makes an invited user show up only later.
#[derive(Clone)]
struct AtlassianState {
    users: Arc<Mutex<Vec<Value>>>,
    groups: Arc<Mutex<Vec<Value>>>,
    invited: Arc<Mutex<Vec<Value>>>,
    hits: Hits,
    list_invites: Arc<Mutex<bool>>,
    next: Arc<Mutex<u32>>,
    /// The directories each account is in (`a9` is in two).
    memberships: Arc<Mutex<HashMap<String, Vec<String>>>>,
    /// How many single-user reads still show each account's previous status.
    lag: Arc<Mutex<u32>>,
    stale: Arc<Mutex<HashMap<String, (String, u32)>>>,
    /// Each group's members, by group id.
    group_members: Arc<Mutex<HashMap<String, Vec<String>>>>,
    /// Answer an invite as Atlassian's 206 does: the account is made, its groups are not assigned.
    partial: Arc<Mutex<bool>>,
}

impl AtlassianState {
    fn status(&self, id: &str) -> Option<String> {
        self.users.lock().unwrap().iter().find(|u| u["accountId"] == id).and_then(|u| u["status"].as_str().map(str::to_string))
    }
    fn set_status(&self, id: &str, status: &str) -> bool {
        let mut users = self.users.lock().unwrap();
        let Some(u) = users.iter_mut().find(|u| u["accountId"] == id) else { return false };
        let lag = *self.lag.lock().unwrap();
        if lag > 0 {
            self.stale.lock().unwrap().insert(id.to_string(), (u["status"].as_str().unwrap_or_default().to_string(), lag));
        }
        u["status"] = json!(status);
        true
    }
    fn dir_of(&self, id: &str) -> Vec<String> {
        self.memberships.lock().unwrap().get(id).cloned().unwrap_or_else(|| vec!["d1".into()])
    }
}

fn atl_user(id: &str, email: &str, status: &str) -> Value {
    json!({ "accountId": id, "accountType": "atlassian", "status": status, "accountStatus": "active", "name": email, "email": email, "claimStatus": "managed" })
}

fn atl_err(status: StatusCode, code: &str, title: &str) -> Response {
    (status, axum::Json(json!({ "errors": [{ "id": "e1", "code": code, "status": status.as_u16().to_string(), "title": title }] }))).into_response()
}

fn atl_denied(headers: &HeaderMap) -> Option<Response> {
    (headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) != Some("Bearer atl-test")).then(|| atl_err(StatusCode::UNAUTHORIZED, "ADMIN-UAM-401-1", "Unauthenticated"))
}

/// One page of `items` after the opaque cursor `c<offset>`, with `links.next` while more remain.
fn atl_page(items: &[Value], q: &HashMap<String, String>) -> Response {
    let limit: usize = q.get("limit").and_then(|l| l.parse().ok()).unwrap_or(20).min(100);
    let start: usize = q.get("cursor").and_then(|c| c.strip_prefix('c')).and_then(|n| n.parse().ok()).unwrap_or(0);
    let page: Vec<Value> = items.iter().skip(start).take(limit).cloned().collect();
    let next = (start + limit < items.len()).then(|| format!("c{}", start + limit));
    ok(json!({ "data": page, "links": { "self": format!("c{start}"), "next": next } }))
}

async fn atl_list_users(State(s): State<AtlassianState>, headers: HeaderMap, Path((_, dir)): Path<(String, String)>, Query(q): Query<HashMap<String, String>>) -> Response {
    if let Some(denied) = atl_denied(&headers) {
        return denied;
    }
    s.hits.lock().unwrap().push(format!("GET users dir={dir}"));
    let mut users = s.users.lock().unwrap().clone();
    if let Some(gid) = q.get("groupIds") {
        let members = s.group_members.lock().unwrap().get(gid).cloned().unwrap_or_default();
        users.retain(|u| members.iter().any(|m| u["accountId"] == m.as_str()));
    }
    atl_page(&users, &q)
}

async fn atl_get_user(State(s): State<AtlassianState>, headers: HeaderMap, Path((_, _, id)): Path<(String, String, String)>) -> Response {
    if let Some(denied) = atl_denied(&headers) {
        return denied;
    }
    let user = s.users.lock().unwrap().iter().find(|u| u["accountId"] == id.as_str()).cloned();
    match user {
        Some(mut u) => {
            if let Some((old, left)) = s.stale.lock().unwrap().get_mut(&id) {
                if *left > 0 {
                    *left -= 1;
                    u["status"] = json!(old.clone());
                }
            }
            ok(json!({ "data": u }))
        }
        None => atl_err(StatusCode::NOT_FOUND, "ADMIN-UAM-404-1", "Unknown Resource"),
    }
}

async fn atl_list_groups(State(s): State<AtlassianState>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if let Some(denied) = atl_denied(&headers) {
        return denied;
    }
    let groups = s.groups.lock().unwrap().clone();
    atl_page(&groups, &q)
}

async fn atl_invite(State(s): State<AtlassianState>, headers: HeaderMap, axum::Json(body): axum::Json<Value>) -> Response {
    if let Some(denied) = atl_denied(&headers) {
        return denied;
    }
    s.invited.lock().unwrap().push(body.clone());
    let groups = s.groups.lock().unwrap().clone();
    let wanted: Vec<&str> = body["additionalGroups"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
    if wanted.iter().any(|g| !groups.iter().any(|have| have["id"] == *g)) {
        return atl_err(StatusCode::NOT_FOUND, "ADMIN-UAM-404-3", "Group Not Found");
    }
    let mut data = vec![];
    for email in body["emails"].as_array().into_iter().flatten().filter_map(Value::as_str) {
        let id = {
            let mut n = s.next.lock().unwrap();
            *n += 1;
            format!("acc-{:03}", *n)
        };
        if *s.list_invites.lock().unwrap() {
            s.users.lock().unwrap().push(atl_user(&id, email, "active"));
            if !*s.partial.lock().unwrap() {
                for g in &wanted {
                    s.group_members.lock().unwrap().entry(g.to_string()).or_default().push(id.clone());
                }
            }
        }
        data.push(json!({ "id": id, "email": email, "results": [] }));
    }
    if *s.partial.lock().unwrap() {
        return (StatusCode::PARTIAL_CONTENT, axum::Json(json!({ "data": data }))).into_response();
    }
    ok(json!({ "data": data }))
}

async fn atl_list_dirs(State(s): State<AtlassianState>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if let Some(denied) = atl_denied(&headers) {
        return denied;
    }
    let all = ["d1", "d2"];
    let dirs: Vec<Value> = match q.get("accountId") {
        Some(id) => s.dir_of(id).iter().map(|d| json!({ "directoryId": d, "name": d })).collect(),
        None => all.iter().map(|d| json!({ "directoryId": d, "name": d })).collect(),
    };
    atl_page(&dirs, &q)
}

async fn atl_create_group(State(s): State<AtlassianState>, headers: HeaderMap, Path((_, dir)): Path<(String, String)>, axum::Json(body): axum::Json<Value>) -> Response {
    if let Some(denied) = atl_denied(&headers) {
        return denied;
    }
    s.hits.lock().unwrap().push(format!("create group dir={dir}"));
    if dir != "d1" && dir != "d2" {
        return atl_err(StatusCode::NOT_FOUND, "ADMIN-UAM-404-1", "Unknown Resource");
    }
    let id = {
        let mut n = s.next.lock().unwrap();
        *n += 1;
        format!("g-new-{:03}", *n)
    };
    s.groups.lock().unwrap().push(json!({ "id": id, "name": body["name"], "directoryId": dir }));
    StatusCode::CREATED.into_response()
}

/// A member is added in the user's own directory, which must be the group's.
async fn atl_membership(s: &AtlassianState, headers: &HeaderMap, dir: &str, gid: &str, account: &str, add: bool) -> Response {
    if let Some(denied) = atl_denied(headers) {
        return denied;
    }
    s.hits.lock().unwrap().push(format!("{} {account} {gid} dir={dir}", if add { "join" } else { "leave" }));
    let group_dir = s.groups.lock().unwrap().iter().find(|g| g["id"] == gid).and_then(|g| g["directoryId"].as_str().map(str::to_string));
    if group_dir.as_deref() != Some(dir) || !s.dir_of(account).iter().any(|d| d == dir) {
        return atl_err(StatusCode::NOT_FOUND, "ADMIN-UAM-404-1", "Unknown Resource");
    }
    let mut members = s.group_members.lock().unwrap();
    let list = members.entry(gid.to_string()).or_default();
    if add {
        if !list.iter().any(|m| m == account) {
            list.push(account.to_string());
        }
    } else if list.iter().any(|m| m == account) {
        list.retain(|m| m != account);
    } else {
        return atl_err(StatusCode::NOT_FOUND, "ADMIN-UAM-404-1", "Unknown Resource");
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn atl_join(State(s): State<AtlassianState>, headers: HeaderMap, Path((_, dir, gid)): Path<(String, String, String)>, axum::Json(body): axum::Json<Value>) -> Response {
    let account = body["accountId"].as_str().unwrap_or_default().to_string();
    atl_membership(&s, &headers, &dir, &gid, &account, true).await
}

async fn atl_leave(State(s): State<AtlassianState>, headers: HeaderMap, Path((_, dir, gid, account)): Path<(String, String, String, String)>) -> Response {
    atl_membership(&s, &headers, &dir, &gid, &account, false).await
}

async fn atl_change(s: &AtlassianState, headers: &HeaderMap, dir: &str, id: &str, status: &str) -> Response {
    if let Some(denied) = atl_denied(headers) {
        return denied;
    }
    s.hits.lock().unwrap().push(format!("{status} {id} dir={dir}"));
    // Changes are made in the user's own directory; `-` is only for reads.
    if !s.dir_of(id).iter().any(|d| d == dir) {
        return atl_err(StatusCode::NOT_FOUND, "ADMIN-UAM-404-1", "Unknown Resource");
    }
    if status == "removed" {
        let mut users = s.users.lock().unwrap();
        let before = users.len();
        users.retain(|u| u["accountId"] != id);
        return if users.len() < before { StatusCode::NO_CONTENT.into_response() } else { atl_err(StatusCode::NOT_FOUND, "ADMIN-UAM-404-1", "Unknown Resource") };
    }
    if s.set_status(id, status) {
        StatusCode::NO_CONTENT.into_response()
    } else {
        atl_err(StatusCode::NOT_FOUND, "ADMIN-UAM-404-1", "Unknown Resource")
    }
}

async fn atl_suspend(State(s): State<AtlassianState>, headers: HeaderMap, Path((_, dir, id)): Path<(String, String, String)>) -> Response {
    atl_change(&s, &headers, &dir, &id, "suspended").await
}

async fn atl_restore(State(s): State<AtlassianState>, headers: HeaderMap, Path((_, dir, id)): Path<(String, String, String)>) -> Response {
    atl_change(&s, &headers, &dir, &id, "active").await
}

async fn atl_remove(State(s): State<AtlassianState>, headers: HeaderMap, Path((_, dir, id)): Path<(String, String, String)>) -> Response {
    atl_change(&s, &headers, &dir, &id, "removed").await
}

async fn spawn_atlassian() -> (String, AtlassianState) {
    let state = AtlassianState {
        users: Arc::new(Mutex::new(vec![
            atl_user("a0", "Admin@Acme.example", "active"),
            atl_user("a1", "dev@acme.example", "active"),
            atl_user("a2", "away@acme.example", "suspended"),
            atl_user("a3", "former@acme.example", "not_invited"),
            atl_user("a4", "doomed@acme.example", "for_deletion"),
            atl_user("a5", "closed@acme.example", "deactivated"),
            atl_user("a9", "twice@acme.example", "active"),
        ])),
        groups: Arc::new(Mutex::new(vec![
            json!({ "id": "g-jira", "name": "jira-software-users", "directoryId": "d1" }),
            json!({ "id": "g-ad", "name": "appdoorman-users", "directoryId": "d1" }),
            json!({ "id": "g-ad2", "name": "appdoorman-users-old", "directoryId": "d1" }),
        ])),
        invited: Arc::default(),
        hits: Arc::default(),
        list_invites: Arc::new(Mutex::new(true)),
        next: Arc::default(),
        memberships: Arc::new(Mutex::new(HashMap::from([("a9".to_string(), vec!["d1".to_string(), "d2".to_string()])]))),
        lag: Arc::default(),
        stale: Arc::default(),
        group_members: Arc::new(Mutex::new(HashMap::from([("g-jira".to_string(), vec!["a0".to_string(), "a1".to_string()])]))),
        partial: Arc::default(),
    };
    let base = "/admin/v2/orgs/{org}";
    let app = axum::Router::new()
        .route(&format!("{base}/directories/{{dir}}/users"), axum::routing::get(atl_list_users))
        .route(&format!("{base}/directories/{{dir}}/users/{{id}}"), axum::routing::get(atl_get_user).delete(atl_remove))
        .route(&format!("{base}/directories/{{dir}}/users/{{id}}/suspend"), axum::routing::post(atl_suspend))
        .route(&format!("{base}/directories/{{dir}}/users/{{id}}/restore"), axum::routing::post(atl_restore))
        .route(&format!("{base}/directories/{{dir}}/groups"), axum::routing::get(atl_list_groups).post(atl_create_group))
        .route(&format!("{base}/directories/{{dir}}/groups/{{gid}}/memberships"), axum::routing::post(atl_join))
        .route(&format!("{base}/directories/{{dir}}/groups/{{gid}}/memberships/{{account}}"), axum::routing::delete(atl_leave))
        .route(&format!("{base}/directories"), axum::routing::get(atl_list_dirs))
        .route(&format!("{base}/users/invite"), axum::routing::post(atl_invite))
        .with_state(state.clone());
    (serve(app).await, state)
}

fn atlassian_json(origin: &str) -> Value {
    let mut dk: Value = serde_json::from_str(include_str!("../doorkeys/atlassian.doorkey.json")).unwrap();
    dk["base_url"] = json!(format!("{origin}/admin/v2/orgs/org1"));
    dk["hosts"] = json!(["127.0.0.1"]);
    dk
}

fn atlassian_target(dk: Value) -> Target {
    Target::Doorkey(Keyhole::new(parse(dk), "atl-test", sealer(), true).unwrap())
}

#[tokio::test]
async fn atlassian_lists_members_by_status_across_every_directory_and_page() {
    let (origin, state) = spawn_atlassian().await;
    let mut dk = atlassian_json(&origin);
    dk["ops"]["list_users"]["paginate"]["size"] = json!(2);
    let users = atlassian_target(dk).list_users().await.unwrap();
    let seen: Vec<_> = users.iter().map(|u| (u.user_name.as_str(), u.active)).collect();
    // No membership left and scheduled for deletion are not people with access; suspended and
    // deactivated accounts are, without it.
    assert_eq!(seen, [("Admin@Acme.example", true), ("dev@acme.example", true), ("away@acme.example", false), ("closed@acme.example", false), ("twice@acme.example", true)]);
    assert!(state.hits.lock().unwrap().iter().all(|h| h == "GET users dir=-"), "every directory at once");
}

#[tokio::test]
async fn atlassian_invites_into_the_appdoorman_group_suspends_restores_and_removes() {
    let (origin, state) = spawn_atlassian().await;
    let target = atlassian_target(atlassian_json(&origin));
    assert!(target.supports_delete() && target.supports_suspend());

    let (user, ev) = confirmed(target.create_user("new.hire@acme.example", "New", "Hire", "new.hire@acme.example").await.unwrap());
    assert_eq!((user.user_name.as_str(), user.active), ("new.hire@acme.example", true));
    assert_eq!((ev.op.as_str(), ev.verified_by.as_str()), ("create_user", "list_joiner_members"));
    assert_eq!(state.group_members.lock().unwrap()["g-ad"], [user.id.clone()]);
    // The group id came from the org's groups, by its exact name.
    let sent = state.invited.lock().unwrap()[0].clone();
    assert_eq!(sent["emails"], json!(["new.hire@acme.example"]));
    assert_eq!(sent["additionalGroups"], json!(["g-ad"]));
    assert_eq!(sent["sendNotification"], json!(true));

    let ev = target.set_active(&user.id, false).await.unwrap();
    assert_eq!((ev.op.as_str(), ev.verified_by.as_str()), ("deactivate_user", "find_user"));
    assert_eq!(state.status(&user.id).as_deref(), Some("suspended"));
    target.set_active(&user.id, true).await.unwrap();
    assert_eq!(state.status(&user.id).as_deref(), Some("active"));

    let ev = target.delete_user(&user.id).await.unwrap();
    assert_eq!((ev.subject_id.as_str(), ev.subject_user_name.as_str()), (user.id.as_str(), "new.hire@acme.example"));
    assert_eq!(state.status(&user.id), None);
    // Every change went to the user's own directory, looked up first.
    let hits = state.hits.lock().unwrap().clone();
    assert!(hits.contains(&format!("suspended {} dir=d1", user.id)) && hits.contains(&format!("removed {} dir=d1", user.id)), "got {hits:?}");
}

#[tokio::test]
async fn atlassian_counts_an_invite_only_once_the_person_is_in_the_joiner_group() {
    let (origin, state) = spawn_atlassian().await;
    let mut dk = atlassian_json(&origin);
    dk["settle"]["wait_ms"] = json!(1);
    let target = atlassian_target(dk);
    // Atlassian's 206: the account is made, the group is not assigned. Not a joiner with access.
    *state.partial.lock().unwrap() = true;
    let err = keyhole_err(target.create_user("half@acme.example", "H", "Alf", "half@acme.example").await.unwrap_err());
    assert!(matches!(err, KeyholeError::VerifyFailed(ref op) if op == "create_user"), "got {err:?}");
    // Listed in the org, but the read-back that counts is the group's.
    assert!(target.list_users().await.unwrap().iter().any(|u| u.user_name == "half@acme.example"));
    // An invite Atlassian has not listed yet is a failed change too, never one left waiting.
    *state.partial.lock().unwrap() = false;
    *state.list_invites.lock().unwrap() = false;
    let err = keyhole_err(target.create_user("late@acme.example", "L", "Ate", "late@acme.example").await.unwrap_err());
    assert!(matches!(err, KeyholeError::VerifyFailed(_)), "got {err:?}");
}

#[tokio::test]
async fn atlassian_sends_no_invite_unless_exactly_one_appdoorman_group_exists() {
    let (origin, state) = spawn_atlassian().await;
    let target = atlassian_target(atlassian_json(&origin));
    let invite = || target.create_user("x@acme.example", "X", "Y", "x@acme.example");

    state.groups.lock().unwrap().retain(|g| g["name"] != "appdoorman-users");
    let err = keyhole_err(invite().await.unwrap_err());
    assert!(matches!(&err, KeyholeError::LookupFailed { key, found: 0, .. } if key == "joiner_group"), "got {err:?}");

    // Two directories may each hold a group by that name; picking one would be a guess.
    state.groups.lock().unwrap().extend([json!({ "id": "g-x", "name": "appdoorman-users", "directoryId": "d1" }), json!({ "id": "g-y", "name": "appdoorman-users", "directoryId": "d2" })]);
    let err = keyhole_err(invite().await.unwrap_err());
    assert!(matches!(&err, KeyholeError::LookupFailed { found: 2, .. }), "got {err:?}");
    assert!(state.invited.lock().unwrap().is_empty(), "nothing was sent");
}

#[tokio::test]
async fn atlassian_failures_are_errors_not_empty_lists() {
    let (origin, state) = spawn_atlassian().await;
    let k = Keyhole::new(parse(atlassian_json(&origin)), "atl-wrong", sealer(), true).unwrap();
    let err = keyhole_err(Target::Doorkey(k).list_users().await.unwrap_err());
    assert!(matches!(err, KeyholeError::Http(401, ..)), "got {err:?}");
    let target = atlassian_target(atlassian_json(&origin));
    assert!(matches!(keyhole_err(target.set_active("nobody", false).await.unwrap_err()), KeyholeError::Http(404, ..)));
    // A user whose status went missing or changed type is an error, never an inactive user.
    state.users.lock().unwrap()[1]["status"] = json!(true);
    assert!(target.list_users().await.is_err());
    state.users.lock().unwrap()[1].as_object_mut().unwrap().remove("status");
    assert!(target.list_users().await.is_err());
}

#[test]
fn the_atlassian_doorkey_only_reaches_the_atlassian_api() {
    let at = |base: &str| {
        let mut dk: Value = serde_json::from_str(include_str!("../doorkeys/atlassian.doorkey.json")).unwrap();
        dk["base_url"] = json!(base);
        Keyhole::new(parse(dk), "atl-x", sealer(), false)
    };
    assert!(at("https://api.atlassian.com/admin/v2/orgs/0a1b2c3d-0000-4000-8000-000000000000").is_ok());
    assert!(at("https://api.atlassian.com.attacker.example/admin/v2/orgs/x").is_err());
    assert!(at("https://acme.atlassian.net/admin/v2/orgs/x").is_err(), "only the admin API host");
}

#[test]
fn active_when_is_checked_when_the_doorkey_loads() {
    let with = |f: &dyn Fn(&mut Value)| {
        let mut dk = atlassian_json("http://127.0.0.1:1");
        f(&mut dk);
        Keyhole::new(parse(dk), "t", sealer(), true).map(|_| ()).map_err(|e| format!("{e:#}"))
    };
    with(&|_| {}).unwrap();
    assert!(with(&|dk| dk["ops"]["find_user"]["extract"]["active_inverted"] = json!(true)).unwrap_err().contains("both `active_inverted` and `active_when`"));
    assert!(with(&|dk| dk["ops"]["find_user"]["extract"]["active_when"] = json!({ "s": 1 })).unwrap_err().contains("string, number or boolean"));
    let no_active = with(&|dk| {
        for op in ["list_users", "find_user"] {
            dk["ops"][op]["extract"].as_object_mut().unwrap().remove("active");
        }
    });
    assert!(no_active.unwrap_err().contains("`active_when` without an `active` field"));
}


#[tokio::test]
async fn atlassian_changes_nobody_whose_directory_is_ambiguous() {
    let (origin, state) = spawn_atlassian().await;
    let target = atlassian_target(atlassian_json(&origin));
    // In two directories: which one to suspend in would be a guess.
    let err = keyhole_err(target.set_active("a9", false).await.unwrap_err());
    assert!(matches!(&err, KeyholeError::LookupFailed { key, found: 2, .. } if key == "directory_id"), "got {err:?}");
    // In none: nothing to change.
    state.memberships.lock().unwrap().insert("a1".into(), vec![]);
    let err = keyhole_err(target.delete_user("a1").await.unwrap_err());
    assert!(matches!(&err, KeyholeError::LookupFailed { found: 0, .. }), "got {err:?}");
    assert!(state.hits.lock().unwrap().iter().all(|h| h.starts_with("GET")), "nothing was changed");
}

#[tokio::test]
async fn atlassian_read_backs_wait_for_a_lagging_read() {
    let (origin, state) = spawn_atlassian().await;
    *state.lag.lock().unwrap() = 2;
    let mut dk = atlassian_json(&origin);
    dk["settle"]["wait_ms"] = json!(1);
    let target = atlassian_target(dk.clone());
    // Two stale reads, then the suspend shows: confirmed, not failed.
    target.set_active("a1", false).await.unwrap();
    // Without settle the first stale read fails the change.
    dk.as_object_mut().unwrap().remove("settle");
    *state.lag.lock().unwrap() = 1;
    let err = keyhole_err(atlassian_target(dk).set_active("a1", true).await.unwrap_err());
    assert!(matches!(err, KeyholeError::VerifyFailed(_)), "got {err:?}");
}

#[test]
fn settle_and_single_lookups_are_checked_when_the_doorkey_loads() {
    let with = |f: &dyn Fn(&mut Value)| {
        let mut dk = atlassian_json("http://127.0.0.1:1");
        f(&mut dk);
        Keyhole::new(parse(dk), "t", sealer(), true).map(|_| ()).map_err(|e| format!("{e:#}"))
    };
    assert!(with(&|dk| dk["settle"] = json!({ "tries": 11, "wait_ms": 100 })).unwrap_err().contains("`settle`"));
    assert!(with(&|dk| dk["settle"] = json!({ "tries": 3, "wait_ms": 60000 })).unwrap_err().contains("`settle`"));
    assert!(with(&|dk| dk["ops"]["delete_user"]["lookup"]["directory_id"]["where"] = json!({ "name": "x" })).unwrap_err().contains("both `single` and a `where`"));
    assert!(with(&|dk| dk["ops"]["delete_user"]["lookup"]["directory_id"]["single"] = json!(false)).unwrap_err().contains("without a `where`"));
}

#[tokio::test]
async fn atlassian_pushes_groups_creating_them_and_changing_members_one_at_a_time() {
    let (origin, state) = spawn_atlassian().await;
    let target = atlassian_target(atlassian_json(&origin));
    assert!(target.supports_doorkey_groups() && target.supports_create_group());

    let groups = target.list_groups().await.unwrap();
    assert!(groups.contains(&TargetGroup { id: "g-jira".into(), name: "jira-software-users".into(), seats: None }));
    let members: Vec<String> = target.group_members("g-jira").await.unwrap().into_iter().map(|u| u.user_name).collect();
    assert_eq!(members, ["Admin@Acme.example", "dev@acme.example"]);

    // A new group goes into the org's one directory... and there are two here, so none is made.
    let err = target.create_group("eng").await.unwrap_err();
    assert!(format!("{err:#}").contains("directory_id"), "got {err:#}");
    assert!(!state.hits.lock().unwrap().iter().any(|h| h.starts_with("create group")), "nothing was sent");
    // With one directory it is created there and read back by name.
    let mut dk = atlassian_json(&origin);
    dk["ops"]["list_all_directories"]["request"]["query"] = json!({ "accountId": "a1" });
    dk["allow"].as_array_mut().unwrap().iter_mut().for_each(|r| if r["path"] == "/directories" { r["params"] = json!(["accountId", "cursor", "limit"]) });
    let target = atlassian_target(dk);
    let (eng, ev) = target.create_group("eng").await.unwrap();
    assert_eq!((eng.name.as_str(), ev.op.as_str(), ev.verified_by.as_str(), ev.subject_user_name.as_str()), ("eng", "create_group", "list_groups", "eng"));

    // Members join and leave in their own directory, each read back from the member list.
    let ev = target.add_group_member(&eng.id, "a1").await.unwrap();
    assert_eq!((ev.op.as_str(), ev.verified_by.as_str(), ev.subject_user_name.as_str()), ("add_group_member", "list_group_members", "dev@acme.example"));
    assert_eq!(state.group_members.lock().unwrap()[&eng.id], ["a1"]);
    target.remove_group_member(&eng.id, "a1").await.unwrap();
    assert!(state.group_members.lock().unwrap()[&eng.id].is_empty());
    let hits = state.hits.lock().unwrap().clone();
    assert!(hits.contains(&format!("join a1 {} dir=d1", eng.id)) && hits.contains(&format!("leave a1 {} dir=d1", eng.id)), "got {hits:?}");

    // Someone in two directories is not added anywhere.
    let err = keyhole_err(target.add_group_member(&eng.id, "a9").await.unwrap_err());
    assert!(matches!(&err, KeyholeError::LookupFailed { key, found: 2, .. } if key == "directory_id"), "got {err:?}");
}

#[tokio::test]
async fn a_new_group_is_not_confirmed_while_two_groups_share_its_name() {
    let (origin, state) = spawn_atlassian().await;
    let mut dk = atlassian_json(&origin);
    dk["ops"]["list_all_directories"]["request"]["query"] = json!({ "accountId": "a1" });
    dk["allow"].as_array_mut().unwrap().iter_mut().for_each(|r| if r["path"] == "/directories" { r["params"] = json!(["accountId", "cursor", "limit"]) });
    dk["settle"]["wait_ms"] = json!(1);
    state.groups.lock().unwrap().push(json!({ "id": "g-old", "name": "eng", "directoryId": "d1" }));
    let err = keyhole_err(atlassian_target(dk).create_group("eng").await.unwrap_err());
    assert!(matches!(err, KeyholeError::VerifyFailed(ref op) if op == "create_group"), "got {err:?}");
}

#[test]
fn group_ops_come_as_a_set_each_read_back_where_it_can_be_confirmed() {
    let with = |f: &dyn Fn(&mut Value)| {
        let mut dk = atlassian_json("http://127.0.0.1:1");
        f(&mut dk);
        Keyhole::new(parse(dk), "t", sealer(), true).map(|_| ()).map_err(|e| format!("{e:#}"))
    };
    with(&|_| {}).unwrap();
    assert!(with(&|dk| { dk["ops"].as_object_mut().unwrap().remove("remove_group_member"); }).unwrap_err().contains("group push needs"));
    let no_groups = with(&|dk| { dk["ops"]["list_groups"].as_object_mut().unwrap().remove("groups"); }).unwrap_err();
    assert!(no_groups.contains("group push needs") || no_groups.contains("`groups` block"), "got {no_groups}");
    assert!(with(&|dk| dk["ops"]["add_group_member"]["verify"] = json!({ "present": { "op": "list_users", "expect": {} } })).unwrap_err().contains("through `list_group_members`"));
    assert!(with(&|dk| dk["ops"]["create_group"]["verify"] = json!({ "present": { "op": "list_users", "expect": {} } })).unwrap_err().contains("`groups` block"));
    // Without `create_group`, only groups that already exist are kept in step.
    with(&|dk| { dk["ops"].as_object_mut().unwrap().remove("create_group"); }).unwrap();
}

mod linear;

// --- GitHub: organization members by username, invitations, teams -------------------------------

/// A team as the fake keeps it: slug, name and member logins.
type Team = (String, String, Vec<String>);

/// GitHub's organization API as its REST docs describe it: bare-array lists paged by `page` and
/// `per_page`, members as `{ login, id }` with no email, an invitation visible only on the
/// membership read as `state: pending`, removal through the membership (which cancels an
/// invitation too), and teams by slug. The token's owner, `boss`, maintains every team they make.
#[derive(Clone, Default)]
struct GitHubState {
    members: Arc<Mutex<Vec<String>>>,
    pending: Arc<Mutex<Vec<String>>>,
    /// GitHub accounts that exist, so an invite to anyone else is a 404.
    accounts: Arc<Mutex<Vec<String>>>,
    teams: Arc<Mutex<Vec<Team>>>,
    hits: Hits,
}

impl GitHubState {
    fn accept(&self, login: &str) {
        self.pending.lock().unwrap().retain(|p| p != login);
        self.members.lock().unwrap().push(login.to_string());
    }
    fn team(&self, slug: &str) -> Option<Vec<String>> {
        self.teams.lock().unwrap().iter().find(|t| t.0 == slug).map(|t| t.2.clone())
    }
}

fn gh_denied(headers: &HeaderMap) -> Option<Response> {
    let h = |k: &str| headers.get(k).and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
    if h("authorization") != "Bearer gh-test" {
        return Some((StatusCode::UNAUTHORIZED, axum::Json(json!({ "message": "Bad credentials" }))).into_response());
    }
    if h("accept") != "application/vnd.github+json" || h("x-github-api-version") != "2022-11-28" {
        return Some((StatusCode::BAD_REQUEST, axum::Json(json!({ "message": "missing GitHub headers" }))).into_response());
    }
    None
}

fn gh_page(items: Vec<Value>, q: &HashMap<String, String>) -> Response {
    let per: usize = q.get("per_page").and_then(|v| v.parse().ok()).unwrap_or(30);
    let page: usize = q.get("page").and_then(|v| v.parse().ok()).unwrap_or(1);
    ok(json!(items.into_iter().skip((page - 1) * per).take(per).collect::<Vec<_>>()))
}

fn gh_user(login: &str) -> Value {
    json!({ "login": login, "id": login.len(), "type": "User" })
}

async fn gh_members(State(s): State<GitHubState>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if let Some(d) = gh_denied(&headers) {
        return d;
    }
    let members = s.members.lock().unwrap().clone();
    gh_page(members.iter().map(|m| gh_user(m)).collect(), &q)
}

async fn gh_membership(State(s): State<GitHubState>, headers: HeaderMap, method: Method, Path((_, login)): Path<(String, String)>) -> Response {
    if let Some(d) = gh_denied(&headers) {
        return d;
    }
    s.hits.lock().unwrap().push(format!("{method} membership {login}"));
    let member = s.members.lock().unwrap().contains(&login);
    let pending = s.pending.lock().unwrap().contains(&login);
    match method {
        Method::GET if member || pending => ok(json!({ "state": if member { "active" } else { "pending" }, "role": "member", "user": gh_user(&login) })),
        Method::PUT if member => ok(json!({ "state": "active", "role": "member", "user": gh_user(&login) })),
        Method::PUT if s.accounts.lock().unwrap().contains(&login) => {
            if !pending {
                s.pending.lock().unwrap().push(login.clone());
            }
            ok(json!({ "state": "pending", "role": "member", "user": gh_user(&login) }))
        }
        Method::DELETE if member || pending => {
            s.members.lock().unwrap().retain(|m| m != &login);
            s.pending.lock().unwrap().retain(|m| m != &login);
            for t in s.teams.lock().unwrap().iter_mut() {
                t.2.retain(|m| m != &login);
            }
            StatusCode::NO_CONTENT.into_response()
        }
        _ => (StatusCode::NOT_FOUND, axum::Json(json!({ "message": "Not Found" }))).into_response(),
    }
}

async fn gh_teams(State(s): State<GitHubState>, headers: HeaderMap, method: Method, Query(q): Query<HashMap<String, String>>, body: Option<axum::Json<Value>>) -> Response {
    if let Some(d) = gh_denied(&headers) {
        return d;
    }
    if method == Method::POST {
        let name = body.and_then(|b| b["name"].as_str().map(str::to_string)).unwrap_or_default();
        let slug = name.to_lowercase().replace(' ', "-");
        s.hits.lock().unwrap().push(format!("create team {name}"));
        s.teams.lock().unwrap().push((slug.clone(), name.clone(), vec!["boss".into()]));
        return (StatusCode::CREATED, axum::Json(json!({ "slug": slug, "name": name }))).into_response();
    }
    let teams = s.teams.lock().unwrap().clone();
    gh_page(teams.iter().map(|t| json!({ "slug": t.0, "name": t.1, "id": t.0.len() })).collect(), &q)
}

async fn gh_team_members(State(s): State<GitHubState>, headers: HeaderMap, Path((_, slug)): Path<(String, String)>, Query(q): Query<HashMap<String, String>>) -> Response {
    if let Some(d) = gh_denied(&headers) {
        return d;
    }
    match s.team(&slug) {
        Some(members) => gh_page(members.iter().map(|m| gh_user(m)).collect(), &q),
        None => (StatusCode::NOT_FOUND, axum::Json(json!({ "message": "Not Found" }))).into_response(),
    }
}

async fn gh_team_membership(State(s): State<GitHubState>, headers: HeaderMap, method: Method, Path((_, slug, login)): Path<(String, String, String)>) -> Response {
    if let Some(d) = gh_denied(&headers) {
        return d;
    }
    s.hits.lock().unwrap().push(format!("{method} team {slug} {login}"));
    let mut teams = s.teams.lock().unwrap();
    let Some(team) = teams.iter_mut().find(|t| t.0 == slug) else {
        return (StatusCode::NOT_FOUND, axum::Json(json!({ "message": "Not Found" }))).into_response();
    };
    if method == Method::PUT {
        if !team.2.contains(&login) {
            team.2.push(login.clone());
        }
        return ok(json!({ "state": "active", "role": "member" }));
    }
    if !team.2.contains(&login) {
        return (StatusCode::NOT_FOUND, axum::Json(json!({ "message": "Not Found" }))).into_response();
    }
    team.2.retain(|m| m != &login);
    StatusCode::NO_CONTENT.into_response()
}

async fn spawn_github() -> (String, GitHubState) {
    let state = GitHubState::default();
    *state.members.lock().unwrap() = vec!["boss".into(), "Octo-Cat".into(), "hubot".into()];
    *state.accounts.lock().unwrap() = vec!["newbie".into(), "late-joiner".into()];
    *state.teams.lock().unwrap() = vec![("platform".into(), "Platform".into(), vec!["boss".into(), "Octo-Cat".into()])];
    let app = axum::Router::new()
        .route("/orgs/{org}/members", axum::routing::get(gh_members))
        .route("/orgs/{org}/memberships/{login}", axum::routing::get(gh_membership).put(gh_membership).delete(gh_membership))
        .route("/orgs/{org}/teams", axum::routing::get(gh_teams).post(gh_teams))
        .route("/orgs/{org}/teams/{slug}/members", axum::routing::get(gh_team_members))
        .route("/orgs/{org}/teams/{slug}/memberships/{login}", axum::routing::put(gh_team_membership).delete(gh_team_membership))
        .with_state(state.clone());
    (serve(app).await, state)
}

fn github_target(origin: &str, f: impl Fn(&mut Value)) -> Target {
    let mut dk: Value = serde_json::from_str(include_str!("../doorkeys/github.doorkey.json")).unwrap();
    dk["base_url"] = json!(format!("{origin}/orgs/acme"));
    dk["hosts"] = json!(["127.0.0.1"]);
    dk["settle"]["wait_ms"] = json!(1);
    f(&mut dk);
    Target::Doorkey(Keyhole::new(parse(dk), "gh-test", sealer(), true).unwrap())
}

#[tokio::test]
async fn github_lists_members_by_username_across_pages() {
    let (origin, _) = spawn_github().await;
    let target = github_target(&origin, |dk| dk["ops"]["list_users"]["paginate"]["size"] = json!(2));
    let users = target.list_users().await.unwrap();
    let names: Vec<_> = users.iter().map(|u| (u.id.as_str(), u.user_name.as_str(), u.active)).collect();
    assert_eq!(names, [("boss", "boss", true), ("Octo-Cat", "Octo-Cat", true), ("hubot", "hubot", true)]);
    assert!(target.supports_delete() && !target.supports_suspend() && target.supports_withdraw());
}

#[tokio::test]
async fn github_invites_by_username_waits_for_acceptance_and_removes() {
    let (origin, state) = spawn_github().await;
    let target = github_target(&origin, |_| {});
    // An invitation shows only on the membership read, so it waits.
    let created = target.create_user("newbie", "New", "Bie", "new.bie@acme.example").await.unwrap();
    assert!(matches!(created, Created::Pending(ref p) if p.user_name == "newbie"), "got {created:?}");
    assert_eq!(*state.pending.lock().unwrap(), ["newbie"]);
    // Withdrawing it before they accept cancels the invitation, confirmed by the membership read.
    let ev = target.withdraw_invite("newbie", "new.bie@acme.example").await.unwrap();
    assert_eq!((ev.op.as_str(), ev.verified_by.as_str()), ("withdraw_invite", "find_invitee"));
    assert!(state.pending.lock().unwrap().is_empty());

    target.create_user("late-joiner", "Late", "Joiner", "late@acme.example").await.unwrap();
    state.accept("late-joiner");
    assert!(target.list_users().await.unwrap().iter().any(|u| u.user_name == "late-joiner"));
    let ev = target.delete_user("late-joiner").await.unwrap();
    assert_eq!((ev.op.as_str(), ev.verified_by.as_str(), ev.subject_user_name.as_str()), ("delete_user", "find_user", "late-joiner"));
    assert!(!state.members.lock().unwrap().contains(&"late-joiner".to_string()));
    // A username GitHub doesn't know is an error, never a pending invite.
    let err = keyhole_err(target.create_user("nobody-here", "N", "B", "n@acme.example").await.unwrap_err());
    assert!(matches!(err, KeyholeError::Http(404, ..)), "got {err:?}");
}

#[tokio::test]
async fn github_pushes_groups_as_teams() {
    let (origin, state) = spawn_github().await;
    let target = github_target(&origin, |_| {});
    assert!(target.supports_doorkey_groups() && target.supports_create_group());
    assert_eq!(target.list_groups().await.unwrap(), [TargetGroup { id: "platform".into(), name: "Platform".into(), seats: None }]);

    let (team, ev) = target.create_group("Data Science").await.unwrap();
    assert_eq!((team.id.as_str(), team.name.as_str(), ev.op.as_str()), ("data-science", "Data Science", "create_group"));
    target.add_group_member("data-science", "Octo-Cat").await.unwrap();
    let members: Vec<String> = target.group_members("data-science").await.unwrap().into_iter().map(|u| u.user_name).collect();
    // The token's owner maintains the team it made; AppDoorman manages only who it added.
    assert_eq!(members, ["boss", "Octo-Cat"]);
    target.remove_group_member("data-science", "Octo-Cat").await.unwrap();
    assert_eq!(state.team("data-science").unwrap(), ["boss"]);
}

#[tokio::test]
async fn github_failures_are_errors_not_empty_lists() {
    let (origin, _) = spawn_github().await;
    let mut dk: Value = serde_json::from_str(include_str!("../doorkeys/github.doorkey.json")).unwrap();
    dk["base_url"] = json!(format!("{origin}/orgs/acme"));
    dk["hosts"] = json!(["127.0.0.1"]);
    let wrong = Target::Doorkey(Keyhole::new(parse(dk), "gh-wrong", sealer(), true).unwrap());
    assert!(matches!(keyhole_err(wrong.list_users().await.unwrap_err()), KeyholeError::Http(401, ..)));
    let target = github_target(&origin, |_| {});
    assert!(matches!(keyhole_err(target.delete_user("ghost").await.unwrap_err()), KeyholeError::Http(404, ..)));
}

#[test]
fn the_github_doorkey_only_reaches_the_github_api() {
    let at = |base: &str| {
        let mut dk: Value = serde_json::from_str(include_str!("../doorkeys/github.doorkey.json")).unwrap();
        dk["base_url"] = json!(base);
        Keyhole::new(parse(dk), "gh-x", sealer(), false)
    };
    assert!(at("https://api.github.com/orgs/acme").is_ok());
    assert!(at("https://github.com/orgs/acme").is_err(), "only the API host");
    assert!(at("https://api.github.com.attacker.example/orgs/acme").is_err());
}

// --- GitHub Copilot: seats by username, cancelled to the end of the billing cycle --------------

/// Copilot's seat API as GitHub's docs describe it: `{ total_seats, seats }` paged by `page`, a seat
/// per assignee login, `selected_usernames` to add or cancel, a cancelled seat kept with a
/// `pending_cancellation_date`, team-assigned seats refused, and only organization members seated.
#[derive(Clone, Default)]
struct CopilotState {
    members: Arc<Mutex<Vec<String>>>,
    seats: Arc<Mutex<Vec<Value>>>,
}

fn seat(login: &str, team: Option<&str>) -> Value {
    json!({ "assignee": gh_user(login), "assigning_team": team.map(|t| json!({ "slug": t })), "pending_cancellation_date": null, "plan_type": "business" })
}

async fn cp_seats(State(s): State<CopilotState>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if let Some(d) = gh_denied(&headers) {
        return d;
    }
    let all = s.seats.lock().unwrap().clone();
    let per: usize = q.get("per_page").and_then(|v| v.parse().ok()).unwrap_or(50);
    let page: usize = q.get("page").and_then(|v| v.parse().ok()).unwrap_or(1);
    ok(json!({ "total_seats": all.len(), "seats": all.into_iter().skip((page - 1) * per).take(per).collect::<Vec<_>>() }))
}

async fn cp_selected(State(s): State<CopilotState>, headers: HeaderMap, method: Method, axum::Json(body): axum::Json<Value>) -> Response {
    if let Some(d) = gh_denied(&headers) {
        return d;
    }
    let names: Vec<String> = body["selected_usernames"].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(str::to_string)).collect();
    let mut seats = s.seats.lock().unwrap();
    let unprocessable = |m: &str| (StatusCode::UNPROCESSABLE_ENTITY, axum::Json(json!({ "message": m }))).into_response();
    let mut changed = 0;
    for name in &names {
        let at = seats.iter().position(|x| x["assignee"]["login"] == name.as_str());
        if method == Method::POST {
            if !s.members.lock().unwrap().contains(name) {
                return unprocessable("User is not a member of the organization");
            }
            match at {
                Some(i) => seats[i]["pending_cancellation_date"] = Value::Null,
                None => seats.push(seat(name, None)),
            }
            changed += 1;
        } else if let Some(i) = at {
            if !seats[i]["assigning_team"].is_null() {
                return unprocessable("Seat was assigned through a team");
            }
            seats[i]["pending_cancellation_date"] = json!("2026-12-01");
            changed += 1;
        }
    }
    if method == Method::POST {
        (StatusCode::CREATED, axum::Json(json!({ "seats_created": changed }))).into_response()
    } else {
        ok(json!({ "seats_cancelled": changed }))
    }
}

async fn spawn_copilot() -> (String, CopilotState) {
    let state = CopilotState::default();
    *state.members.lock().unwrap() = vec!["boss".into(), "Octo-Cat".into(), "hubot".into(), "newbie".into()];
    *state.seats.lock().unwrap() = vec![seat("boss", None), seat("Octo-Cat", None), seat("hubot", Some("platform"))];
    let mut leaving = seat("old-timer", None);
    leaving["pending_cancellation_date"] = json!("2026-12-01");
    state.seats.lock().unwrap().push(leaving);
    let app = axum::Router::new()
        .route("/orgs/{org}/copilot/billing/seats", axum::routing::get(cp_seats))
        .route("/orgs/{org}/copilot/billing/selected_users", axum::routing::post(cp_selected).delete(cp_selected))
        .with_state(state.clone());
    (serve(app).await, state)
}

fn copilot_target(origin: &str) -> Target {
    let mut dk: Value = serde_json::from_str(include_str!("../doorkeys/github-copilot.doorkey.json")).unwrap();
    dk["base_url"] = json!(format!("{origin}/orgs/acme"));
    dk["hosts"] = json!(["127.0.0.1"]);
    dk["settle"]["wait_ms"] = json!(1);
    dk["ops"]["list_users"]["paginate"]["size"] = json!(2);
    Target::Doorkey(Keyhole::new(parse(dk), "gh-test", sealer(), true).unwrap())
}

#[tokio::test]
async fn copilot_seats_are_assigned_and_cancelled_by_username() {
    let (origin, state) = spawn_copilot().await;
    let target = copilot_target(&origin);
    // Team seats are the team's, and a seat already pending cancellation is not access.
    let names = |t: Vec<TargetUser>| t.into_iter().map(|u| u.user_name).collect::<Vec<_>>();
    assert_eq!(names(target.list_users().await.unwrap()), ["boss", "Octo-Cat"]);
    assert!(target.supports_delete() && !target.supports_suspend());

    let created = target.create_user("newbie", "New", "Bie", "new.bie@acme.example").await.unwrap();
    assert!(matches!(created, Created::Confirmed(..)), "got {created:?}");
    assert!(names(target.list_users().await.unwrap()).contains(&"newbie".to_string()));

    let ev = target.delete_user("newbie").await.unwrap();
    assert_eq!((ev.op.as_str(), ev.verified_by.as_str()), ("delete_user", "list_users"));
    let seat = state.seats.lock().unwrap().iter().find(|s| s["assignee"]["login"] == "newbie").cloned().unwrap();
    assert!(!seat["pending_cancellation_date"].is_null(), "GitHub keeps the seat until the cycle ends");
    assert!(!names(target.list_users().await.unwrap()).contains(&"newbie".to_string()));

    // Someone who isn't in the organization yet can't get a seat: an error, never a pending one.
    let err = keyhole_err(target.create_user("stranger", "S", "T", "s@acme.example").await.unwrap_err());
    assert!(matches!(err, KeyholeError::Http(422, ..)), "got {err:?}");
}

// --- OAuth client credentials (Microsoft style) and OData next-URL paging ------------------------

/// A Microsoft-identity-shaped token endpoint at `/{tenant}/oauth2/v2.0/token` that wants the
/// client id and secret in the form body with a scope, and a Graph-shaped `/v1.0/users` that pages
/// by `@odata.nextLink` and wants the token it handed out.
#[derive(Clone, Default)]
struct GraphState {
    tokens: Arc<Mutex<u32>>,
    users: Arc<Mutex<Vec<Value>>>,
}

async fn ms_token(State(s): State<GraphState>, Path(tenant): Path<String>, axum::Form(f): axum::Form<HashMap<String, String>>) -> Response {
    let ok = tenant == "contoso.onmicrosoft.com"
        && f.get("grant_type").map(String::as_str) == Some("client_credentials")
        && f.get("scope").map(String::as_str) == Some("https://graph.microsoft.com/.default")
        && f.get("client_id").map(String::as_str) == Some("app-id")
        && f.get("client_secret").map(String::as_str) == Some("app-secret")
        && !f.contains_key("tenant_id");
    if !ok {
        return (StatusCode::UNAUTHORIZED, axum::Json(json!({ "error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret provided." }))).into_response();
    }
    *s.tokens.lock().unwrap() += 1;
    ok_json(json!({ "token_type": "Bearer", "expires_in": 3599, "access_token": "graph-token" }))
}

fn ok_json(v: Value) -> Response {
    axum::Json(v).into_response()
}

async fn graph_users(State(s): State<GraphState>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some("Bearer graph-token") {
        return (StatusCode::UNAUTHORIZED, axum::Json(json!({ "error": { "code": "InvalidAuthenticationToken" } }))).into_response();
    }
    let all = s.users.lock().unwrap().clone();
    let start: usize = q.get("$skiptoken").and_then(|t| t.parse().ok()).unwrap_or(0);
    let page: Vec<Value> = all.iter().skip(start).take(2).cloned().collect();
    let mut body = json!({ "value": page });
    if start + 2 < all.len() {
        body["@odata.nextLink"] = json!(format!("https://graph.microsoft.com/v1.0/users?$top=2&$skiptoken={}", start + 2));
    }
    ok_json(body)
}

async fn spawn_graph() -> (String, GraphState) {
    let state = GraphState::default();
    *state.users.lock().unwrap() = ["a", "b", "c", "d", "e"].iter().map(|n| json!({ "id": format!("id-{n}"), "userPrincipalName": format!("{n}@contoso.com"), "accountEnabled": true })).collect();
    let app = axum::Router::new()
        .route("/{tenant}/oauth2/v2.0/token", axum::routing::post(ms_token))
        .route("/v1.0/users", axum::routing::get(graph_users))
        .with_state(state.clone());
    (serve(app).await, state)
}

fn graph_doorkey(origin: &str) -> Value {
    json!({
        "doorkey": "graph-test", "version": 1,
        "base_url": format!("{origin}/v1.0"), "hosts": ["127.0.0.1"],
        "auth": { "scheme": "oauth_client_credentials", "token_url": format!("{origin}/{{tenant_id}}/oauth2/v2.0/token"), "fields": ["tenant_id"], "scope": "https://graph.microsoft.com/.default", "credentials_in_body": true },
        "allow": [{ "method": "GET", "path": "/users", "params": ["$top", "$skiptoken"] }],
        "ops": { "list_users": {
            "request": { "method": "GET", "path": "/users", "query": { "$top": "2" } },
            "paginate": { "style": "next_url", "path": "@odata.nextLink", "param": "$skiptoken" },
            "extract": { "list": "value", "id": "id", "user_name": "userPrincipalName", "active": "accountEnabled" }
        } }
    })
}

#[tokio::test]
async fn a_microsoft_token_is_fetched_once_and_odata_pages_are_followed_by_skiptoken() {
    let (origin, state) = spawn_graph().await;
    let cred = json!({ "tenant_id": "contoso.onmicrosoft.com", "client_id": "app-id", "client_secret": "app-secret" }).to_string();
    let target = Target::Doorkey(Keyhole::new(parse(graph_doorkey(&origin)), cred, sealer(), true).unwrap());
    let users = target.list_users().await.unwrap();
    assert_eq!(users.iter().map(|u| u.user_name.as_str()).collect::<Vec<_>>(), ["a@contoso.com", "b@contoso.com", "c@contoso.com", "d@contoso.com", "e@contoso.com"]);
    target.list_users().await.unwrap();
    assert_eq!(*state.tokens.lock().unwrap(), 1, "the token is kept until shortly before it expires");

    // A wrong secret stops with the identity platform's reason.
    let bad = json!({ "tenant_id": "contoso.onmicrosoft.com", "client_id": "app-id", "client_secret": "nope" }).to_string();
    let target = Target::Doorkey(Keyhole::new(parse(graph_doorkey(&origin)), bad, sealer(), true).unwrap());
    let err = keyhole_err(target.list_users().await.unwrap_err());
    assert!(matches!(err, KeyholeError::TokenRefused(401, Some(ref m)) if m.contains("AADSTS7000215")), "got {err:?}");

    // The tenant fills one path segment and can't move the token request anywhere else.
    for tenant in ["../evil", "contoso.com/x", "a?b=c", ""] {
        let cred = json!({ "tenant_id": tenant, "client_id": "app-id", "client_secret": "app-secret" }).to_string();
        assert!(Keyhole::new(parse(graph_doorkey(&origin)), cred, sealer(), true).is_err(), "{tenant:?}");
    }
    // A token URL may name a credential field in its path only, never in its host.
    let mut dk = graph_doorkey(&origin);
    dk["auth"]["token_url"] = json!("https://{tenant_id}.example.com/token");
    assert!(serde_json::from_value::<Doorkey>(dk).map_err(|e| e.to_string()).and_then(|d| d.validate().map_err(|e| e.to_string())).is_err());
}

// --- Microsoft 365 over Graph: users, licenses as seat-pool groups ------------------------------

/// Graph's users and licenses as Microsoft documents them: a federated domain needs
/// `onPremisesImmutableId`, a license needs a `usageLocation`, licenses come from `subscribedSkus`
/// with seats, and `assignLicense` adds or removes one.
#[derive(Clone, Default)]
struct M365State {
    users: Arc<Mutex<Vec<Value>>>,
    sku_total: u64,
}

const SKU: &str = "f245ecc8-75af-4f8e-b61f-27d8114de5f3";

fn m365_auth(headers: &HeaderMap) -> Option<Response> {
    (headers.get("authorization").and_then(|v| v.to_str().ok()) != Some("Bearer graph-token"))
        .then(|| (StatusCode::UNAUTHORIZED, axum::Json(json!({ "error": { "code": "InvalidAuthenticationToken", "message": "Access token is empty." } }))).into_response())
}

fn graph_err(status: StatusCode, code: &str, message: &str) -> Response {
    (status, axum::Json(json!({ "error": { "code": code, "message": message } }))).into_response()
}

fn has_sku(u: &Value) -> bool {
    u["assignedLicenses"].as_array().is_some_and(|l| l.iter().any(|x| x["skuId"] == SKU))
}

async fn m365_users(State(s): State<M365State>, headers: HeaderMap, method: Method, Query(q): Query<HashMap<String, String>>, body: Option<axum::Json<Value>>) -> Response {
    if let Some(d) = m365_auth(&headers) {
        return d;
    }
    if method == Method::POST {
        let b = body.map(|b| b.0).unwrap_or_default();
        if b["onPremisesImmutableId"].as_str().unwrap_or_default().is_empty() {
            return graph_err(StatusCode::BAD_REQUEST, "Request_BadRequest", "Property onPremisesImmutableId is required for a federated domain.");
        }
        let id = format!("u-{}", s.users.lock().unwrap().len() + 1);
        let mut user = b.clone();
        user["id"] = json!(id);
        user["userType"] = json!("Member");
        user["assignedLicenses"] = json!([]);
        s.users.lock().unwrap().push(user.clone());
        return (StatusCode::CREATED, axum::Json(user)).into_response();
    }
    let users = s.users.lock().unwrap().clone();
    let users: Vec<Value> = match q.get("$filter") {
        Some(f) if f == &format!("assignedLicenses/any(x:x/skuId eq {SKU})") => {
            if headers.get("consistencylevel").and_then(|v| v.to_str().ok()) != Some("eventual") {
                return graph_err(StatusCode::BAD_REQUEST, "Request_UnsupportedQuery", "Unsupported query.");
            }
            users.into_iter().filter(has_sku).collect()
        }
        Some(_) => return graph_err(StatusCode::BAD_REQUEST, "Request_UnsupportedQuery", "Unsupported query."),
        None => users,
    };
    ok_json(json!({ "value": users }))
}

async fn m365_user(State(s): State<M365State>, headers: HeaderMap, method: Method, Path(id): Path<String>, body: Option<axum::Json<Value>>) -> Response {
    if let Some(d) = m365_auth(&headers) {
        return d;
    }
    let mut users = s.users.lock().unwrap();
    let Some(at) = users.iter().position(|u| u["id"] == id.as_str()) else {
        return graph_err(StatusCode::NOT_FOUND, "Request_ResourceNotFound", "Resource does not exist.");
    };
    match method {
        Method::GET => ok_json(users[at].clone()),
        Method::PATCH => {
            if let Some(b) = body {
                for (k, v) in b.0.as_object().into_iter().flatten() {
                    users[at][k] = v.clone();
                }
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Method::DELETE => {
            users.remove(at);
            StatusCode::NO_CONTENT.into_response()
        }
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

async fn m365_assign(State(s): State<M365State>, headers: HeaderMap, Path(id): Path<String>, axum::Json(b): axum::Json<Value>) -> Response {
    if let Some(d) = m365_auth(&headers) {
        return d;
    }
    let used = s.users.lock().unwrap().iter().filter(|u| has_sku(u)).count() as u64;
    let mut users = s.users.lock().unwrap();
    let Some(user) = users.iter_mut().find(|u| u["id"] == id.as_str()) else {
        return graph_err(StatusCode::NOT_FOUND, "Request_ResourceNotFound", "Resource does not exist.");
    };
    let adding = b["addLicenses"].as_array().is_some_and(|a| a.iter().any(|x| x["skuId"] == SKU));
    if adding {
        if user["usageLocation"].as_str().unwrap_or_default().is_empty() {
            return graph_err(StatusCode::BAD_REQUEST, "Request_BadRequest", "License assignment cannot be done for user with invalid usage location.");
        }
        if used >= s.sku_total {
            return graph_err(StatusCode::BAD_REQUEST, "Request_BadRequest", "License assignment failed because service plans are not available.");
        }
        user["assignedLicenses"] = json!([{ "skuId": SKU, "disabledPlans": [] }]);
    }
    if b["removeLicenses"].as_array().is_some_and(|r| r.iter().any(|x| x == SKU)) {
        user["assignedLicenses"] = json!([]);
    }
    ok_json(user.clone())
}

async fn m365_skus(State(s): State<M365State>, headers: HeaderMap) -> Response {
    if let Some(d) = m365_auth(&headers) {
        return d;
    }
    let used = s.users.lock().unwrap().iter().filter(|u| has_sku(u)).count();
    ok_json(json!({ "value": [{ "skuId": SKU, "skuPartNumber": "O365_BUSINESS_PREMIUM", "consumedUnits": used, "prepaidUnits": { "enabled": s.sku_total } }] }))
}

async fn spawn_m365(sku_total: u64) -> (String, M365State) {
    let state = M365State { users: Arc::default(), sku_total };
    state.users.lock().unwrap().push(json!({ "id": "admin", "userPrincipalName": "admin@contoso.com", "accountEnabled": true, "userType": "Member", "assignedLicenses": [] }));
    state.users.lock().unwrap().push(json!({ "id": "guest", "userPrincipalName": "guest_x#EXT#@contoso.com", "accountEnabled": true, "userType": "Guest", "assignedLicenses": [] }));
    let app = axum::Router::new()
        .route("/{tenant}/oauth2/v2.0/token", axum::routing::post(ms_token))
        .with_state(GraphState::default())
        .merge(
            axum::Router::new()
                .route("/v1.0/users", axum::routing::get(m365_users).post(m365_users))
                .route("/v1.0/users/{id}", axum::routing::get(m365_user).patch(m365_user).delete(m365_user))
                .route("/v1.0/users/{id}/assignLicense", axum::routing::post(m365_assign))
                .route("/v1.0/subscribedSkus", axum::routing::get(m365_skus))
                .with_state(state.clone()),
        );
    (serve(app).await, state)
}

fn m365_target(origin: &str, usage: Option<&str>) -> Target {
    let mut dk: Value = serde_json::from_str(include_str!("../doorkeys/microsoft365.doorkey.json")).unwrap();
    dk["base_url"] = json!(format!("{origin}/v1.0"));
    dk["hosts"] = json!(["127.0.0.1"]);
    dk["auth"]["token_url"] = json!(format!("{origin}/{{tenant_id}}/oauth2/v2.0/token"));
    dk["settle"]["wait_ms"] = json!(1);
    let cred = json!({ "tenant_id": "contoso.onmicrosoft.com", "client_id": "app-id", "client_secret": "app-secret" }).to_string();
    let params: BTreeMap<String, String> = usage.map(|u| BTreeMap::from([("usage_location".to_string(), u.to_string())])).unwrap_or_default();
    Target::Doorkey(Keyhole::new(parse(dk), cred, sealer(), true).unwrap().with_params(&params).unwrap())
}

#[tokio::test]
async fn microsoft365_creates_federated_users_and_licenses_them_by_group() {
    let (origin, state) = spawn_m365(1).await;
    let target = m365_target(&origin, Some("DE"));
    // Guests are not people AppDoorman manages; the admin is listed but never touched.
    let names: Vec<String> = target.list_users().await.unwrap().into_iter().map(|u| u.user_name).collect();
    assert_eq!(names, ["admin@contoso.com"]);

    let Created::Confirmed(user, _) = target.create_user("ada.lovelace@contoso.com", "Ada", "Lovelace", "ada.lovelace@contoso.com").await.unwrap() else { panic!("not confirmed") };
    let made = state.users.lock().unwrap().iter().find(|u| u["id"] == user.id.as_str()).cloned().unwrap();
    assert_eq!((made["mailNickname"].as_str(), made["usageLocation"].as_str(), made["onPremisesImmutableId"].as_str(), made["displayName"].as_str()), (Some("ada.lovelace"), Some("DE"), Some("ada.lovelace@contoso.com"), Some("Ada Lovelace")));

    // The license is a seat-pool group: seats read, assigned, then the pool is full.
    let groups = target.list_groups().await.unwrap();
    assert_eq!((groups[0].id.as_str(), groups[0].seats), (SKU, Some((1, 0))));
    target.add_group_member(SKU, &user.id).await.unwrap();
    assert_eq!(target.list_groups().await.unwrap()[0].seats, Some((1, 1)));
    assert_eq!(target.group_members(SKU).await.unwrap().iter().map(|m| m.id.clone()).collect::<Vec<_>>(), [user.id.clone()]);
    let Created::Confirmed(second, _) = target.create_user("bob@contoso.com", "Bob", "B", "bob@contoso.com").await.unwrap() else { panic!() };
    let err = keyhole_err(target.add_group_member(SKU, &second.id).await.unwrap_err());
    assert!(err.to_string().contains("service plans are not available"), "no seats left says so: {err}");

    // A leaver loses the license, is blocked, then deleted.
    target.remove_group_member(SKU, &user.id).await.unwrap();
    assert!(target.group_members(SKU).await.unwrap().is_empty());
    target.set_active(&user.id, false).await.unwrap();
    assert_eq!(state.users.lock().unwrap().iter().find(|u| u["id"] == user.id.as_str()).unwrap()["accountEnabled"], false);
    target.delete_user(&user.id).await.unwrap();
    assert!(!state.users.lock().unwrap().iter().any(|u| u["id"] == user.id.as_str()));
}

#[tokio::test]
async fn microsoft365_needs_a_valid_usage_location_setting() {
    let (origin, _) = spawn_m365(5).await;
    let mut dk: Value = serde_json::from_str(include_str!("../doorkeys/microsoft365.doorkey.json")).unwrap();
    dk["base_url"] = json!(format!("{origin}/v1.0"));
    dk["hosts"] = json!(["127.0.0.1"]);
    dk["auth"]["token_url"] = json!(format!("{origin}/{{tenant_id}}/oauth2/v2.0/token"));
    let cred = json!({ "tenant_id": "contoso.onmicrosoft.com", "client_id": "app-id", "client_secret": "app-secret" }).to_string();
    let keyhole = || Keyhole::new(parse(dk.clone()), cred.clone(), sealer(), true).unwrap();
    for bad in ["", "de", "DEU", "D1"] {
        assert!(keyhole().with_params(&BTreeMap::from([("usage_location".to_string(), bad.to_string())])).is_err(), "{bad:?}");
    }
    assert!(keyhole().with_params(&BTreeMap::new()).is_err(), "the setting is required");
}
