//! Fake admin APIs for tests, built from each vendor's documentation, shared by the Doorkey and
//! sync tests.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Which organization Admin API the fake answers as. They share a shape: members and invites
/// paged by id, invites read pending, accepted or expired.
#[derive(Clone, Copy, PartialEq)]
pub enum Vendor {
    /// `/v1/organizations/…`, `x-api-key` plus a required `anthropic-version`, paged with `after_id`.
    Anthropic,
    /// `/v1/organization/…`, a bearer key, paged with `after`; service accounts among the users.
    OpenAi,
}

impl Vendor {
    pub fn prefix(self) -> &'static str {
        match self {
            Vendor::Anthropic => "/v1/organizations",
            Vendor::OpenAi => "/v1/organization",
        }
    }
    fn cursor(self) -> &'static str {
        match self {
            Vendor::Anthropic => "after_id",
            Vendor::OpenAi => "after",
        }
    }
    pub fn token(self) -> &'static str {
        match self {
            Vendor::Anthropic => "ak-test",
            Vendor::OpenAi => "sk-admin-test",
        }
    }
}

#[derive(Clone)]
pub struct AdminApi {
    pub vendor: Vendor,
    pub users: Arc<Mutex<Vec<Value>>>,
    pub invites: Arc<Mutex<Vec<Value>>>,
    next: Arc<Mutex<u32>>,
}

impl AdminApi {
    fn new(vendor: Vendor) -> Self {
        Self { vendor, users: Arc::default(), invites: Arc::default(), next: Arc::default() }
    }

    fn id(&self, kind: &str) -> String {
        let mut n = self.next.lock().unwrap();
        *n += 1;
        format!("{kind}_{:04}", *n)
    }

    pub fn add_user(&self, email: &str, service_account: bool) -> String {
        let id = self.id("user");
        let mut user = json!({ "id": id, "email": email, "role": "user", "name": email });
        if self.vendor == Vendor::OpenAi {
            user["is_service_account"] = json!(service_account);
            if service_account {
                user["email"] = Value::Null;
            }
        }
        self.users.lock().unwrap().push(user);
        id
    }

    /// The invitee accepts: the invite reads accepted, and they are a member.
    pub fn accept(&self, email: &str) -> String {
        for i in self.invites.lock().unwrap().iter_mut().filter(|i| i["email"] == email && i["status"] == "pending") {
            i["status"] = json!("accepted");
        }
        self.add_user(email, false)
    }

    pub fn status_of_invite(&self, email: &str) -> Vec<String> {
        self.invites.lock().unwrap().iter().filter(|i| i["email"] == email).map(|i| i["status"].as_str().unwrap_or_default().to_string()).collect()
    }

    fn denied(&self, headers: &HeaderMap) -> Option<Response> {
        let get = |n: &str| headers.get(n).and_then(|v| v.to_str().ok()).map(str::to_string);
        let ok = match self.vendor {
            Vendor::Anthropic => get("x-api-key").as_deref() == Some(self.vendor.token()) && get("anthropic-version").as_deref() == Some("2023-06-01"),
            Vendor::OpenAi => get("authorization") == Some(format!("Bearer {}", self.vendor.token())),
        };
        (!ok).then(|| err(StatusCode::UNAUTHORIZED, "invalid x-api-key"))
    }
}

fn err(status: StatusCode, message: &str) -> Response {
    (status, axum::Json(json!({ "type": "error", "error": { "type": "invalid_request_error", "message": message } }))).into_response()
}

/// One page of `items`, after the id in the vendor's cursor parameter.
fn page(api: &AdminApi, items: Vec<Value>, q: &HashMap<String, String>) -> Response {
    let start = q.get(api.vendor.cursor()).and_then(|after| items.iter().position(|i| i["id"] == after.as_str())).map_or(0, |p| p + 1);
    let limit: usize = q.get("limit").and_then(|l| l.parse().ok()).unwrap_or(20);
    let data: Vec<Value> = items.iter().skip(start).take(limit).cloned().collect();
    let has_more = start + data.len() < items.len();
    let (first, last) = (data.first().map(|i| i["id"].clone()), data.last().map(|i| i["id"].clone()));
    axum::Json(json!({ "data": data, "has_more": has_more, "first_id": first, "last_id": last })).into_response()
}

async fn list_users(State(api): State<AdminApi>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if let Some(d) = api.denied(&headers) {
        return d;
    }
    let users = api.users.lock().unwrap().clone();
    page(&api, users, &q)
}

async fn get_user(State(api): State<AdminApi>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    if let Some(d) = api.denied(&headers) {
        return d;
    }
    match api.users.lock().unwrap().iter().find(|u| u["id"] == id.as_str()) {
        Some(u) => axum::Json(u.clone()).into_response(),
        None => err(StatusCode::NOT_FOUND, "user not found"),
    }
}

async fn delete_user(State(api): State<AdminApi>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    if let Some(d) = api.denied(&headers) {
        return d;
    }
    let mut users = api.users.lock().unwrap();
    let before = users.len();
    users.retain(|u| u["id"] != id.as_str());
    if users.len() == before {
        return err(StatusCode::NOT_FOUND, "user not found");
    }
    axum::Json(json!({ "id": id, "type": "user_deleted", "deleted": true })).into_response()
}

async fn list_invites(State(api): State<AdminApi>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if let Some(d) = api.denied(&headers) {
        return d;
    }
    let invites = api.invites.lock().unwrap().clone();
    page(&api, invites, &q)
}

async fn create_invite(State(api): State<AdminApi>, headers: HeaderMap, axum::Json(body): axum::Json<Value>) -> Response {
    if let Some(d) = api.denied(&headers) {
        return d;
    }
    let email = body["email"].as_str().unwrap_or_default().to_string();
    // OpenAI's refusal for a company address invited into a Gmail-owned
    // organization: a vague message, with the reason only in the code.
    if email.ends_with("@blocked.example") {
        let refusal = json!({ "error": { "message": "We couldn't send this invite right now. Please contact OpenAI Support if you believe this is an error.", "type": "invalid_request_error", "param": null, "code": "block_invite_organization_user" } });
        return (StatusCode::BAD_REQUEST, axum::Json(refusal)).into_response();
    }
    if api.invites.lock().unwrap().iter().any(|i| i["email"] == email.as_str() && i["status"] == "pending") {
        return err(StatusCode::BAD_REQUEST, "A pending invite already exists for this email address");
    }
    let invite = json!({ "id": api.id("invite"), "email": email, "role": body["role"], "status": "pending" });
    api.invites.lock().unwrap().push(invite.clone());
    axum::Json(invite).into_response()
}

async fn delete_invite(State(api): State<AdminApi>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    if let Some(d) = api.denied(&headers) {
        return d;
    }
    let mut invites = api.invites.lock().unwrap();
    match invites.iter().position(|i| i["id"] == id.as_str()) {
        Some(p) if invites[p]["status"] == "pending" => {
            invites.remove(p);
            axum::Json(json!({ "id": id, "type": "invite_deleted", "deleted": true })).into_response()
        }
        Some(_) => err(StatusCode::BAD_REQUEST, "Only a pending invite can be withdrawn"),
        None => err(StatusCode::NOT_FOUND, "invite not found"),
    }
}

/// Serve the fake on a loopback port; returns its origin and its state.
pub async fn spawn(vendor: Vendor) -> (String, AdminApi) {
    let api = AdminApi::new(vendor);
    let p = vendor.prefix();
    let app = axum::Router::new()
        .route(&format!("{p}/users"), axum::routing::get(list_users))
        .route(&format!("{p}/users/{{id}}"), axum::routing::get(get_user).delete(delete_user))
        .route(&format!("{p}/invites"), axum::routing::get(list_invites).post(create_invite))
        .route(&format!("{p}/invites/{{id}}"), axum::routing::delete(delete_invite))
        .with_state(api.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app.into_make_service()).await.unwrap() });
    (format!("http://127.0.0.1:{port}"), api)
}

/// The bundled Doorkey for `vendor`, pointed at the fake at `origin`.
pub fn doorkey(vendor: Vendor, origin: &str) -> super::Doorkey {
    let id = match vendor {
        Vendor::Anthropic => "anthropic",
        Vendor::OpenAi => "openai",
    };
    let (raw, _) = super::bundled(id).unwrap();
    let mut dk: Value = serde_json::from_str(raw).unwrap();
    dk["base_url"] = json!(format!("{origin}{}", vendor.prefix()));
    dk["hosts"] = json!(["127.0.0.1"]);
    serde_json::from_value(dk).unwrap()
}
pub mod linear;
