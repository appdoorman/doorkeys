//! A fake of Linear's GraphQL API, built from Linear's published schema
//! (https://github.com/linear/linear/blob/master/packages/sdk/src/schema.graphql).

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

/// A fake of Linear's GraphQL API at `/graphql`: users (with `includeDisabled`), organization
/// invites, `organizationInviteCreate`, `organizationInviteDelete`, `userSuspend` and
/// `userUnsuspend`, Relay-paged with `first`/`after`. It answers as Linear does: HTTP 200 with an
/// `errors` array for a failed operation, the personal API key bare in `Authorization`, and an
/// `endCursor` that stays set on the last page.
#[derive(Clone, Default)]
pub struct LinearApi {
    pub users: Arc<Mutex<Vec<Value>>>,
    pub invites: Arc<Mutex<Vec<Value>>>,
    /// Every request body the fake received, in order.
    pub sent: Arc<Mutex<Vec<Value>>>,
    /// Answer every operation with HTTP 200, partial data and this error.
    pub fail_with: Arc<Mutex<Option<String>>>,
    /// Answer mutations with `success: false` and change nothing.
    pub refuse: Arc<Mutex<bool>>,
    /// Answer as a Free workspace, which can only invite admins.
    pub free_plan: Arc<Mutex<bool>>,
    /// Ignore `after`, as an app that does not page would.
    pub ignore_after: Arc<Mutex<bool>>,
    /// Leave `hasNextPage` out of `pageInfo`.
    pub drop_has_next: Arc<Mutex<bool>>,
    next: Arc<Mutex<u32>>,
}

pub const LINEAR_KEY: &str = "lin_api_test";

impl LinearApi {
    fn id(&self, kind: &str) -> String {
        let mut n = self.next.lock().unwrap();
        *n += 1;
        format!("{kind}-{:04}", *n)
    }

    pub fn add_user(&self, email: &str, app: bool) -> String {
        let id = self.id("user");
        self.users.lock().unwrap().push(json!({ "id": id, "email": email, "name": email, "active": true, "admin": false, "app": app, "lastSeen": "2026-11-05T12:00:00.000Z" }));
        id
    }

    /// The invitee accepts: as live Linear does, the invite leaves the invite list and the
    /// placeholder user it created becomes an active member, seen, with the same id.
    pub fn accept(&self, email: &str) -> String {
        let same = |v: &Value| v["email"].as_str().is_some_and(|e| e.eq_ignore_ascii_case(email));
        self.invites.lock().unwrap().retain(|i| !same(i));
        let mut users = self.users.lock().unwrap();
        let user = users.iter_mut().find(|u| same(u) && u["lastSeen"].is_null()).expect("an invited Linear user");
        user["active"] = json!(true);
        user["lastSeen"] = json!("2026-11-05T12:00:00.000Z");
        user["id"].as_str().unwrap().to_string()
    }

    pub fn active(&self, id: &str) -> Option<bool> {
        self.users.lock().unwrap().iter().find(|u| u["id"] == id).and_then(|u| u["active"].as_bool())
    }
}

fn gql_error(message: &str, code: &str) -> Value {
    json!({ "errors": [{ "message": message, "extensions": { "code": code, "type": code.to_lowercase() } }], "data": null })
}

/// One Relay page of `items` after the cursor (the last id read), `first` at a time.
fn relay_page(api: &LinearApi, items: Vec<Value>, vars: &Value) -> Value {
    let after = vars["after"].as_str().filter(|_| !*api.ignore_after.lock().unwrap());
    let start = after.and_then(|a| items.iter().position(|i| i["id"] == a)).map_or(0, |p| p + 1);
    let first = vars["first"].as_u64().unwrap_or(50) as usize;
    let nodes: Vec<Value> = items.iter().skip(start).take(first).cloned().collect();
    let has_next = start + nodes.len() < items.len();
    // Linear keeps endCursor on the last page; only hasNextPage says the list is done.
    let end = nodes.last().map(|n| n["id"].clone()).unwrap_or(Value::Null);
    let mut info = json!({ "hasNextPage": has_next, "endCursor": end, "hasPreviousPage": start > 0, "startCursor": nodes.first().map(|n| n["id"].clone()) });
    if *api.drop_has_next.lock().unwrap() {
        info.as_object_mut().unwrap().remove("hasNextPage");
    }
    json!({ "nodes": nodes, "pageInfo": info })
}

async fn linear_graphql(State(api): State<LinearApi>, headers: HeaderMap, axum::Json(body): axum::Json<Value>) -> Response {
    api.sent.lock().unwrap().push(body.clone());
    // Personal API keys go bare in Authorization. As live Linear answers: a Bearer prefix is a 400
    // input error, and any other wrong key a 401.
    match headers.get("authorization").and_then(|v| v.to_str().ok()) {
        Some(LINEAR_KEY) => {}
        Some(v) if v.starts_with("Bearer ") => {
            return (StatusCode::BAD_REQUEST, axum::Json(gql_error("It looks like you're trying to use an API key as a Bearer token. Remove the Bearer prefix from the Authorization header.", "INPUT_ERROR"))).into_response();
        }
        _ => return (StatusCode::UNAUTHORIZED, axum::Json(gql_error("Authentication required, not authenticated", "AUTHENTICATION_ERROR"))).into_response(),
    }
    let query = body["query"].as_str().unwrap_or_default();
    let vars = &body["variables"];
    if let Some(message) = api.fail_with.lock().unwrap().clone() {
        // Partial success: some data, and an error beside it.
        return axum::Json(json!({ "data": { "users": { "nodes": [], "pageInfo": { "hasNextPage": false, "endCursor": null } } }, "errors": [{ "message": message }] })).into_response();
    }
    let refuse = *api.refuse.lock().unwrap();
    let root = |name: &str| query.contains(&format!("{{ {name}(")) || query.contains(&format!("{{{name}("));
    let data = if root("users") {
        let include_disabled = query.contains("includeDisabled: true");
        let users: Vec<Value> = api.users.lock().unwrap().iter().filter(|u| include_disabled || u["active"] == true).cloned().collect();
        json!({ "users": relay_page(&api, users, vars) })
    } else if root("organizationInvites") {
        let invites = api.invites.lock().unwrap().clone();
        json!({ "organizationInvites": relay_page(&api, invites, vars) })
    } else if root("organizationInviteCreate") {
        let email = vars["email"].as_str().unwrap_or_default().to_string();
        let admin = query.contains("role: admin");
        if !admin && !query.contains("role: user") {
            return axum::Json(gql_error("unexpected role", "INVALID_INPUT")).into_response();
        }
        if !admin && *api.free_plan.lock().unwrap() {
            return axum::Json(gql_error("Not allowed on free plan", "FORBIDDEN")).into_response();
        }
        let taken = api.users.lock().unwrap().iter().any(|u| u["email"].as_str().is_some_and(|e| e.eq_ignore_ascii_case(&email)))
            || api.invites.lock().unwrap().iter().any(|i| i["email"].as_str().is_some_and(|e| e.eq_ignore_ascii_case(&email)) && i["acceptedAt"].is_null());
        if taken {
            return axum::Json(gql_error("User is already a member or has a pending invite", "INVALID_INPUT")).into_response();
        }
        if refuse {
            return axum::Json(json!({ "data": { "organizationInviteCreate": { "success": false, "organizationInvite": null } } })).into_response();
        }
        let invite = json!({ "id": api.id("invite"), "email": email, "role": if admin { "admin" } else { "user" }, "acceptedAt": null, "expiresAt": "2026-12-04T00:00:00.000Z" });
        api.invites.lock().unwrap().push(invite.clone());
        // Live Linear lists an invitee at once, as an inactive user who has never been seen.
        let placeholder = api.id("user");
        api.users.lock().unwrap().push(json!({ "id": placeholder, "email": email, "name": email, "active": false, "admin": admin, "app": false, "lastSeen": null }));
        json!({ "organizationInviteCreate": { "success": true, "organizationInvite": { "id": invite["id"], "email": invite["email"] } } })
    } else if root("organizationInviteDelete") {
        let id = vars["id"].as_str().unwrap_or_default();
        let mut invites = api.invites.lock().unwrap();
        let Some(p) = invites.iter().position(|i| i["id"] == id) else {
            return axum::Json(gql_error("Entity not found: OrganizationInvite", "INVALID_INPUT")).into_response();
        };
        if !refuse {
            let gone = invites.remove(p);
            // Deleting the invite deletes its placeholder user too.
            api.users.lock().unwrap().retain(|u| !(u["email"] == gone["email"] && u["lastSeen"].is_null()));
        }
        json!({ "organizationInviteDelete": { "success": !refuse, "entityId": id, "lastSyncId": 1.0 } })
    } else if root("userSuspend") || root("userUnsuspend") {
        let active = root("userUnsuspend");
        let field = if active { "userUnsuspend" } else { "userSuspend" };
        let id = vars["id"].as_str().unwrap_or_default();
        let mut users = api.users.lock().unwrap();
        let Some(user) = users.iter_mut().find(|u| u["id"] == id) else {
            return axum::Json(gql_error("Entity not found: User", "INVALID_INPUT")).into_response();
        };
        if !refuse {
            user["active"] = json!(active);
        }
        json!({ field: { "success": !refuse } })
    } else {
        return axum::Json(gql_error("Cannot query this field", "GRAPHQL_VALIDATION_FAILED")).into_response();
    };
    axum::Json(json!({ "data": data })).into_response()
}

/// Serve the Linear fake on a loopback port; returns its origin and its state.
pub async fn spawn_linear() -> (String, LinearApi) {
    let api = LinearApi::default();
    let app = axum::Router::new().route("/graphql", axum::routing::post(linear_graphql)).with_state(api.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app.into_make_service()).await.unwrap() });
    (format!("http://127.0.0.1:{port}"), api)
}

/// The bundled Linear Doorkey, pointed at the fake at `origin`.
pub fn linear_doorkey(origin: &str) -> crate::Doorkey {
    let (raw, _) = crate::bundled("linear").unwrap();
    let mut dk: Value = serde_json::from_str(raw).unwrap();
    dk["base_url"] = json!(origin);
    dk["hosts"] = json!(["127.0.0.1"]);
    serde_json::from_value(dk).unwrap()
}
