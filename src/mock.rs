//! A mock SCIM app, kept in memory: what the reference Doorkey (`doorkeys/mock.doorkey.json`) and
//! most tests run against, and what AppDoorman's dev mode offers as its test app. It is a
//! development server and is never part of a production router.

use axum::extract::{Path, Query};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, OnceLock};

/// The domain of the people the mock app starts with.
pub const DEMO_DOMAIN: &str = "demo.example";
/// The bearer token the mock app accepts.
pub const MOCK_TOKEN: &str = "dev-token";

#[derive(Default)]
struct MockApp {
    users: BTreeMap<String, Value>,
    groups: BTreeMap<String, Value>,
    next: u64,
}

fn mock_store() -> &'static Mutex<HashMap<String, MockApp>> {
    static S: OnceLock<Mutex<HashMap<String, MockApp>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

fn seeded_mock() -> MockApp {
    let mut app = MockApp::default();
    for (user_name, given, family) in [
        (format!("breakglass-admin@{DEMO_DOMAIN}"), "Break", "Glass"),
        (format!("service-bot@{DEMO_DOMAIN}"), "Service", "Bot"),
        (format!("lea.schmitt@{DEMO_DOMAIN}"), "Lea", "Schmitt"),
    ] {
        app.next += 1;
        let id = format!("mock-{}", app.next);
        app.users.insert(
            id.clone(),
            json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "id": id, "userName": user_name, "active": true,
                "name": { "givenName": given, "familyName": family },
                "emails": [{ "type": "work", "value": user_name, "primary": true }],
            }),
        );
    }
    app
}

fn scim_error(status: StatusCode, detail: &str) -> Response {
    (
        status,
        Json(json!({ "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"], "status": status.as_u16().to_string(), "detail": detail })),
    )
        .into_response()
}

fn authorized(headers: &HeaderMap) -> bool {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == format!("Bearer {MOCK_TOKEN}"))
        .unwrap_or(false)
}

fn with_mock<T>(key: &str, f: impl FnOnce(&mut MockApp) -> T) -> T {
    let mut map = mock_store().lock().unwrap();
    f(map.entry(key.to_string()).or_insert_with(seeded_mock))
}

pub fn mock_router<S: Clone + Send + Sync + 'static>() -> Router<S> {
    Router::new()
        .route("/{key}/v2/ServiceProviderConfig", get(spc))
        .route("/{key}/v2/Users", get(list_users).post(create_user))
        .route("/{key}/v2/Users/{id}", get(get_user).put(put_user).patch(patch_user).delete(delete_user))
        .route("/{key}/v2/Groups", get(list_groups).post(create_group))
        .route("/{key}/v2/Groups/{id}", get(get_group).put(put_group).patch(patch_group).delete(delete_group))
}

async fn spc(headers: HeaderMap) -> Response {
    if !authorized(&headers) {
        return scim_error(StatusCode::UNAUTHORIZED, "invalid token");
    }
    Json(json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch": { "supported": true }, "bulk": { "supported": false }, "filter": { "supported": true, "maxResults": 200 },
        "changePassword": { "supported": false }, "sort": { "supported": false }, "etag": { "supported": false },
    }))
    .into_response()
}

async fn list_users(Path(key): Path<String>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if !authorized(&headers) {
        return scim_error(StatusCode::UNAUTHORIZED, "invalid token");
    }
    let filter_user = q.get("filter").and_then(|f| {
        let f = f.trim();
        f.strip_prefix("userName eq \"").and_then(|r| r.strip_suffix('"')).map(|s| s.to_lowercase())
    });
    let start: usize = q.get("startIndex").and_then(|v| v.parse().ok()).unwrap_or(1).max(1);
    let count: usize = q.get("count").and_then(|v| v.parse().ok()).unwrap_or(100).min(200);
    with_mock(&key, |app| {
        let all: Vec<&Value> = app
            .users
            .values()
            .filter(|u| match &filter_user {
                Some(un) => u["userName"].as_str().map(|s| s.to_lowercase()) == Some(un.clone()),
                None => true,
            })
            .collect();
        let page: Vec<Value> = all.iter().skip(start - 1).take(count).map(|v| (*v).clone()).collect();
        Json(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": all.len(), "startIndex": start, "itemsPerPage": page.len(), "Resources": page,
        }))
        .into_response()
    })
}

async fn create_user(Path(key): Path<String>, headers: HeaderMap, Json(mut body): Json<Value>) -> Response {
    if !authorized(&headers) {
        return scim_error(StatusCode::UNAUTHORIZED, "invalid token");
    }
    let Some(user_name) = body.get("userName").and_then(Value::as_str).map(str::to_lowercase) else {
        return scim_error(StatusCode::BAD_REQUEST, "userName is required");
    };
    with_mock(&key, |app| {
        if app.users.values().any(|u| u["userName"].as_str().map(str::to_lowercase) == Some(user_name.clone())) {
            return scim_error(StatusCode::CONFLICT, "userName already exists");
        }
        app.next += 1;
        let id = format!("mock-{}", app.next);
        body["id"] = json!(id);
        if body.get("active").is_none() {
            body["active"] = json!(true);
        }
        app.users.insert(id, body.clone());
        (StatusCode::CREATED, Json(body)).into_response()
    })
}

async fn get_user(Path((key, id)): Path<(String, String)>, headers: HeaderMap) -> Response {
    if !authorized(&headers) {
        return scim_error(StatusCode::UNAUTHORIZED, "invalid token");
    }
    with_mock(&key, |app| match app.users.get(&id) {
        Some(u) => Json(u.clone()).into_response(),
        None => scim_error(StatusCode::NOT_FOUND, "not found"),
    })
}

async fn put_user(Path((key, id)): Path<(String, String)>, headers: HeaderMap, Json(mut body): Json<Value>) -> Response {
    if !authorized(&headers) {
        return scim_error(StatusCode::UNAUTHORIZED, "invalid token");
    }
    with_mock(&key, |app| {
        if !app.users.contains_key(&id) {
            return scim_error(StatusCode::NOT_FOUND, "not found");
        }
        body["id"] = json!(id);
        app.users.insert(id, body.clone());
        Json(body).into_response()
    })
}

fn set_path(target: &mut Value, path: &str, value: Value) {
    if path == "emails" || path.starts_with("emails[") {
        let v = if path == "emails" { value } else { json!([{ "type": "work", "value": value, "primary": true }]) };
        target["emails"] = v;
        return;
    }
    if path.starts_with("urn:") {
        if let Some((schema, attr)) = path.rsplit_once(':') {
            if target.get(schema).is_none() {
                target[schema] = json!({});
            }
            target[schema][attr] = value;
        }
        return;
    }
    let mut cur = target;
    let parts: Vec<&str> = path.split('.').collect();
    for (i, p) in parts.iter().enumerate() {
        if i == parts.len() - 1 {
            cur[*p] = value;
            return;
        }
        if cur.get(*p).is_none() {
            cur[*p] = json!({});
        }
        cur = &mut cur[*p];
    }
}

async fn patch_user(Path((key, id)): Path<(String, String)>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if !authorized(&headers) {
        return scim_error(StatusCode::UNAUTHORIZED, "invalid token");
    }
    with_mock(&key, |app| {
        let Some(user) = app.users.get_mut(&id) else { return scim_error(StatusCode::NOT_FOUND, "not found") };
        for op in body.get("Operations").and_then(Value::as_array).cloned().unwrap_or_default() {
            let value = op.get("value").cloned().unwrap_or(Value::Null);
            match op.get("path").and_then(Value::as_str) {
                Some(path) => set_path(user, path, value),
                None => {
                    if let Some(obj) = value.as_object() {
                        for (k, v) in obj {
                            user[k] = v.clone();
                        }
                    }
                }
            }
        }
        Json(user.clone()).into_response()
    })
}

async fn delete_user(Path((key, id)): Path<(String, String)>, headers: HeaderMap) -> Response {
    if !authorized(&headers) {
        return scim_error(StatusCode::UNAUTHORIZED, "invalid token");
    }
    with_mock(&key, |app| match app.users.remove(&id) {
        Some(_) => StatusCode::NO_CONTENT.into_response(),
        None => scim_error(StatusCode::NOT_FOUND, "not found"),
    })
}

async fn list_groups(Path(key): Path<String>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if !authorized(&headers) {
        return scim_error(StatusCode::UNAUTHORIZED, "invalid token");
    }
    let name = q.get("filter").and_then(|f| f.trim().strip_prefix("displayName eq \"").and_then(|r| r.strip_suffix('"')).map(str::to_string));
    with_mock(&key, |app| {
        let list: Vec<Value> = app
            .groups
            .values()
            .filter(|g| name.as_deref().map(|n| g["displayName"].as_str() == Some(n)).unwrap_or(true))
            .cloned()
            .collect();
        Json(json!({ "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"], "totalResults": list.len(), "startIndex": 1, "itemsPerPage": list.len(), "Resources": list })).into_response()
    })
}

async fn create_group(Path(key): Path<String>, headers: HeaderMap, Json(mut body): Json<Value>) -> Response {
    if !authorized(&headers) {
        return scim_error(StatusCode::UNAUTHORIZED, "invalid token");
    }
    with_mock(&key, |app| {
        if app.groups.values().any(|g| g["displayName"] == body["displayName"]) {
            return scim_error(StatusCode::CONFLICT, "group already exists");
        }
        app.next += 1;
        let id = format!("grp-{}", app.next);
        body["id"] = json!(id);
        if body.get("members").is_none() {
            body["members"] = json!([]);
        }
        app.groups.insert(id, body.clone());
        (StatusCode::CREATED, Json(body)).into_response()
    })
}

async fn get_group(Path((key, id)): Path<(String, String)>, headers: HeaderMap) -> Response {
    if !authorized(&headers) {
        return scim_error(StatusCode::UNAUTHORIZED, "invalid token");
    }
    with_mock(&key, |app| match app.groups.get(&id) {
        Some(g) => Json(g.clone()).into_response(),
        None => scim_error(StatusCode::NOT_FOUND, "not found"),
    })
}

async fn put_group(Path((key, id)): Path<(String, String)>, headers: HeaderMap, Json(mut body): Json<Value>) -> Response {
    if !authorized(&headers) {
        return scim_error(StatusCode::UNAUTHORIZED, "invalid token");
    }
    with_mock(&key, |app| {
        if !app.groups.contains_key(&id) {
            return scim_error(StatusCode::NOT_FOUND, "not found");
        }
        body["id"] = json!(id);
        app.groups.insert(id, body.clone());
        Json(body).into_response()
    })
}

async fn patch_group(Path((key, id)): Path<(String, String)>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if !authorized(&headers) {
        return scim_error(StatusCode::UNAUTHORIZED, "invalid token");
    }
    with_mock(&key, |app| {
        let Some(group) = app.groups.get_mut(&id) else { return scim_error(StatusCode::NOT_FOUND, "not found") };
        let mut members: Vec<Value> = group["members"].as_array().cloned().unwrap_or_default();
        for op in body.get("Operations").and_then(Value::as_array).cloned().unwrap_or_default() {
            let kind = op.get("op").and_then(Value::as_str).unwrap_or_default().to_lowercase();
            let path = op.get("path").and_then(Value::as_str).unwrap_or_default().to_string();
            let value = op.get("value").cloned().unwrap_or(Value::Null);
            match (kind.as_str(), path.as_str()) {
                ("add", "members") => {
                    for m in value.as_array().cloned().unwrap_or_default() {
                        if !members.iter().any(|x| x["value"] == m["value"]) {
                            members.push(json!({ "value": m["value"] }));
                        }
                    }
                }
                ("remove", p) if p.starts_with("members[value eq \"") => {
                    let target = p.trim_start_matches("members[value eq \"").trim_end_matches("\"]").to_string();
                    members.retain(|x| x["value"].as_str() != Some(target.as_str()));
                }
                ("replace", "displayName") => group["displayName"] = value,
                _ => {}
            }
        }
        group["members"] = json!(members);
        Json(group.clone()).into_response()
    })
}

async fn delete_group(Path((key, id)): Path<(String, String)>, headers: HeaderMap) -> Response {
    if !authorized(&headers) {
        return scim_error(StatusCode::UNAUTHORIZED, "invalid token");
    }
    with_mock(&key, |app| match app.groups.remove(&id) {
        Some(_) => StatusCode::NO_CONTENT.into_response(),
        None => scim_error(StatusCode::NOT_FOUND, "not found"),
    })
}
