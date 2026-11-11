//! Minimal, defensive SCIM 2.0 client (RFC 7643/7644) for the provider side of an app.

use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct ScimError {
    pub status: Option<u16>,
    pub message: String,
    /// The request may have reached the app and been carried out (a timeout or a server error),
    /// so whether it changed anything is unknown.
    pub uncertain: bool,
}

impl ScimError {
    pub fn new(status: Option<u16>, message: impl Into<String>) -> Self {
        Self { status, message: message.into(), uncertain: false }
    }

    /// Credentials are wrong or expired: further calls in this run are pointless.
    pub fn is_auth(&self) -> bool {
        matches!(self.status, Some(401 | 403))
    }
}

pub type ScimResult<T> = Result<T, ScimError>;

#[derive(Clone)]
pub enum Auth {
    Bearer(String),
    Basic { user: String, password: String },
    Header { name: String, value: String },
}

impl Auth {
    /// Builds auth from the stored secret. Basic secrets are stored as "user:password".
    pub fn from_parts(auth_type: &str, header: Option<&str>, secret: &str) -> Self {
        match auth_type {
            "basic" => {
                let (user, password) = secret.split_once(':').unwrap_or((secret, ""));
                Auth::Basic { user: user.into(), password: password.into() }
            }
            "header" => Auth::Header { name: header.map(str::trim).filter(|h| !h.is_empty()).unwrap_or("X-API-Key").into(), value: secret.into() },
            _ => Auth::Bearer(bare_token(secret).into()),
        }
    }
}

/// Apps often show the token as "Bearer xyz" or a whole "Authorization: Bearer xyz" line.
/// People paste it as shown, so keep only the token itself.
fn bare_token(secret: &str) -> &str {
    let mut t = secret.trim();
    if t.len() > 14 && t[..14].eq_ignore_ascii_case("authorization:") {
        t = t[14..].trim_start();
    }
    if t.len() > 7 && t[..7].eq_ignore_ascii_case("bearer ") {
        t = t[7..].trim_start();
    }
    t
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Capabilities {
    pub patch: bool,
    pub filter: bool,
    pub bulk: bool,
    pub etag: bool,
    pub max_results: Option<u64>,
    /// The app accepts SCIM Groups (needed for group push).
    #[serde(default)]
    pub groups: bool,
}

#[derive(Clone)]
pub struct ScimClient {
    http: reqwest::Client,
    base: String,
    auth: Auth,
}

const SCIM_JSON: &str = "application/scim+json";
/// Users asked for per page.
const PAGE_SIZE: u64 = 100;
/// Pages read before giving up on a list: 100,000 accounts at a full page each.
const MAX_PAGES: u64 = 1000;

impl ScimClient {
    pub fn new(http: reqwest::Client, base: &str, auth: Auth) -> Self {
        Self { http, base: base.trim_end_matches('/').to_string(), auth }
    }

    async fn call(&self, method: Method, path: &str, body: Option<&Value>) -> ScimResult<(StatusCode, Value)> {
        let url = format!("{}{}", self.base, path);
        // Sent again after a timeout or a server error, a POST can create a second account; the
        // other methods leave the app the same however often they arrive. A refused connection
        // or a 429 means the app did nothing, so any request is tried again after those.
        let repeatable = method != Method::POST;
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            let mut req = self.http.request(method.clone(), &url).header("Accept", SCIM_JSON);
            req = match &self.auth {
                Auth::Bearer(t) => req.bearer_auth(t),
                Auth::Basic { user, password } => req.basic_auth(user, Some(password)),
                Auth::Header { name, value } => req.header(name.as_str(), value.as_str()),
            };
            if let Some(b) = body {
                req = req.header("Content-Type", SCIM_JSON).body(b.to_string());
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) if attempt < 3 && (e.is_connect() || (repeatable && e.is_timeout())) => {
                    tokio::time::sleep(Duration::from_millis(500 * 2u64.pow(attempt))).await;
                    continue;
                }
                Err(e) => return Err(ScimError { uncertain: !e.is_connect(), ..ScimError::new(None, describe_transport_error(&e)) }),
            };
            let status = resp.status();
            if (status == StatusCode::TOO_MANY_REQUESTS || (repeatable && status.is_server_error())) && attempt < 4 {
                let wait = resp
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(2u64.pow(attempt))
                    .min(60);
                tokio::time::sleep(Duration::from_secs(wait)).await;
                continue;
            }
            let text = resp.text().await.unwrap_or_default();
            let parsed: Option<Value> = if text.trim().is_empty() { Some(Value::Null) } else { serde_json::from_str(&text).ok() };
            if status.is_success() {
                return match parsed {
                    Some(value) => Ok((status, value)),
                    // A login page or a proxy's error page with a 200 is no answer, and a read must
                    // never take it for an empty app.
                    None if method == Method::GET => {
                        Err(ScimError::new(None, "The app answered with a page that is not SCIM JSON, such as a login page. Check the base URL and the token."))
                    }
                    None => Ok((status, Value::Null)),
                };
            }
            let value = parsed.unwrap_or(Value::Null);
            let detail = value
                .get("detail")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| text.chars().take(200).collect());
            let message = match status.as_u16() {
                401 => "The app rejected the SCIM token (401 Unauthorized). Paste a new token.".to_string(),
                403 => "The SCIM token is not allowed to do this (403 Forbidden).".to_string(),
                404 if path == "/Users" || path.starts_with("/Users?") => {
                    "No SCIM Users endpoint at this URL (404). Check the base URL.".to_string()
                }
                code => format!("HTTP {code} from the app: {detail}"),
            };
            return Err(ScimError { uncertain: status.is_server_error(), ..ScimError::new(Some(status.as_u16()), message) });
        }
    }

    pub async fn service_provider_config(&self) -> ScimResult<Capabilities> {
        let (_, v) = self.call(Method::GET, "/ServiceProviderConfig", None).await?;
        let supported = |k: &str| v.get(k).and_then(|o| o.get("supported")).and_then(Value::as_bool).unwrap_or(false);
        Ok(Capabilities {
            patch: supported("patch"),
            filter: supported("filter"),
            bulk: supported("bulk"),
            etag: supported("etag"),
            max_results: v.get("filter").and_then(|f| f.get("maxResults")).and_then(Value::as_u64),
            groups: false,
        })
    }

    /// Lists all users, following SCIM pagination. Fails rather than return part of the list: an
    /// account left out would be planned as a create, or its person as gone from the app.
    pub async fn list_users(&self) -> ScimResult<Vec<Value>> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut start = 1u64;
        for _ in 0..MAX_PAGES {
            let (_, v) = self.call(Method::GET, &format!("/Users?startIndex={start}&count={PAGE_SIZE}"), None).await?;
            let page = list_page(&v)?;
            let n = page.resources.len() as u64;
            let before = out.len();
            for user in page.resources {
                if seen.insert(user["id"].as_str().unwrap_or_default().to_string()) {
                    out.push(user);
                }
            }
            let all_counted = page.total.is_some_and(|total| out.len() as u64 >= total);
            let incomplete = |why: &str| {
                let total = page.total.map(|t| format!(" of the {t} it reports")).unwrap_or_default();
                ScimError::new(None, format!("The app listed {} users{total} and then {why}, so the list may be incomplete and nothing was changed.", out.len()))
            };
            if n == 0 {
                // An app that leaves the total out has listed everyone once a page comes back empty.
                return if page.total.is_none() || all_counted { Ok(out) } else { Err(incomplete("an empty page")) };
            }
            if out.len() == before {
                // The same people again: the app ignores startIndex.
                return if all_counted { Ok(out) } else { Err(incomplete("the same users again for the next page")) };
            }
            // A short page ends the list once the total is reached. A full one is followed by one
            // more read, because some apps report a single page's length as the total.
            if n < PAGE_SIZE && all_counted {
                return Ok(out);
            }
            start += n;
        }
        Err(ScimError::new(None, format!("The app listed more than {MAX_PAGES} pages of users, so AppDoorman stopped reading and changed nothing.")))
    }

    pub async fn find_by_user_name(&self, user_name: &str) -> ScimResult<Option<Value>> {
        let filter = format!("userName eq \"{}\"", user_name.replace('\\', "\\\\").replace('"', "\\\""));
        let path = format!("/Users?filter={}", urlencoding::encode(&filter));
        let (_, v) = self.call(Method::GET, &path, None).await?;
        filtered_match(&v, "userName", user_name)
    }

    pub async fn get_user(&self, id: &str) -> ScimResult<Option<Value>> {
        match self.call(Method::GET, &format!("/Users/{}", urlencoding::encode(id)), None).await {
            Ok((_, v)) => resource(v).map(Some),
            Err(e) if e.status == Some(404) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub async fn create_user(&self, payload: &Value) -> ScimResult<Value> {
        let (_, v) = self.call(Method::POST, "/Users", Some(payload)).await?;
        if v.get("id").and_then(Value::as_str).is_none() {
            return Err(ScimError::new(None, "The app created the user but returned no id"));
        }
        Ok(v)
    }

    pub async fn patch_user(&self, id: &str, operations: Vec<Value>) -> ScimResult<()> {
        let body = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": operations,
        });
        self.call(Method::PATCH, &format!("/Users/{}", urlencoding::encode(id)), Some(&body)).await?;
        Ok(())
    }

    pub async fn replace_user(&self, id: &str, payload: &Value) -> ScimResult<()> {
        let mut body = payload.clone();
        body["id"] = json!(id);
        self.call(Method::PUT, &format!("/Users/{}", urlencoding::encode(id)), Some(&body)).await?;
        Ok(())
    }

    pub async fn delete_user(&self, id: &str) -> ScimResult<()> {
        match self.call(Method::DELETE, &format!("/Users/{}", urlencoding::encode(id)), None).await {
            Ok(_) => Ok(()),
            Err(e) if e.status == Some(404) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

impl ScimClient {
    /// True when the app answers on /Groups, which is what group push needs.
    pub async fn supports_groups(&self) -> bool {
        self.call(Method::GET, "/Groups?startIndex=1&count=1", None).await.is_ok()
    }

    pub async fn find_group_by_name(&self, name: &str) -> ScimResult<Option<Value>> {
        let filter = format!("displayName eq \"{}\"", name.replace('\\', "\\\\").replace('"', "\\\""));
        let (_, v) = self.call(Method::GET, &format!("/Groups?filter={}", urlencoding::encode(&filter)), None).await?;
        filtered_match(&v, "displayName", name)
    }

    pub async fn get_group(&self, id: &str) -> ScimResult<Option<Value>> {
        match self.call(Method::GET, &format!("/Groups/{}", urlencoding::encode(id)), None).await {
            Ok((_, v)) => resource(v).map(Some),
            Err(e) if e.status == Some(404) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub async fn create_group(&self, name: &str, member_ids: &[String]) -> ScimResult<Value> {
        let body = json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": name,
            "members": member_ids.iter().map(|id| json!({ "value": id })).collect::<Vec<_>>(),
        });
        let (_, v) = self.call(Method::POST, "/Groups", Some(&body)).await?;
        if v.get("id").and_then(Value::as_str).is_none() {
            return Err(ScimError::new(None, "The app created the group but returned no id"));
        }
        Ok(v)
    }

    pub async fn patch_group(&self, id: &str, operations: Vec<Value>) -> ScimResult<()> {
        let body = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": operations,
        });
        self.call(Method::PATCH, &format!("/Groups/{}", urlencoding::encode(id)), Some(&body)).await?;
        Ok(())
    }

    pub async fn replace_group(&self, id: &str, name: &str, member_ids: &[String]) -> ScimResult<()> {
        let body = json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "id": id,
            "displayName": name,
            "members": member_ids.iter().map(|m| json!({ "value": m })).collect::<Vec<_>>(),
        });
        self.call(Method::PUT, &format!("/Groups/{}", urlencoding::encode(id)), Some(&body)).await?;
        Ok(())
    }
}

/// Ids of the members of a SCIM Group resource.
/// Member ids of a group resource, or None when the app leaves members out of its responses
/// (AWS IAM Identity Center does). An empty list means the app says the group is empty.
pub fn reported_members(group: &Value) -> Option<Vec<String>> {
    group
        .get("members")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|m| m.get("value").and_then(Value::as_str).map(str::to_string)).collect())
}

struct ListPage {
    resources: Vec<Value>,
    total: Option<u64>,
}

/// One page of a SCIM list response. Anything that is not one is an error: a missing or broken
/// list must never read as "nobody".
fn list_page(v: &Value) -> ScimResult<ListPage> {
    let not_a_list = |why: &str| ScimError::new(None, format!("The app's answer is not a SCIM list ({why})."));
    let obj = v.as_object().ok_or_else(|| not_a_list("not a JSON object"))?;
    let total = match obj.get("totalResults") {
        None | Some(Value::Null) => None,
        Some(t) => Some(t.as_u64().ok_or_else(|| not_a_list("totalResults is not a number"))?),
    };
    let resources = match obj.get("Resources") {
        Some(Value::Array(a)) => a.clone(),
        // RFC 7644 lets a list leave Resources out only when it is empty.
        None | Some(Value::Null) if total == Some(0) => vec![],
        None | Some(Value::Null) => return Err(not_a_list("Resources is missing")),
        Some(_) => return Err(not_a_list("Resources is not a list")),
    };
    if resources.iter().any(|r| r.get("id").and_then(Value::as_str).is_none_or(|id| id.is_empty())) {
        return Err(not_a_list("an entry has no id"));
    }
    Ok(ListPage { resources, total })
}

/// The entry of a filtered list whose `attr` is `wanted`. An app that ignores the filter answers
/// with other entries, and taking the first of those would change the wrong account or group.
fn filtered_match(v: &Value, attr: &str, wanted: &str) -> ScimResult<Option<Value>> {
    let resources = list_page(v)?.resources;
    let listed = resources.len();
    let mut ids = HashSet::new();
    let mut hits: Vec<Value> = resources
        .into_iter()
        .filter(|r| r.get(attr).and_then(Value::as_str).is_some_and(|s| s.eq_ignore_ascii_case(wanted)))
        .filter(|r| ids.insert(r["id"].as_str().unwrap_or_default().to_string()))
        .collect();
    match hits.len() {
        0 if listed == 0 => Ok(None),
        0 => Err(ScimError::new(None, format!("The app answered a search for {attr} \"{wanted}\" with other entries, so it ignores SCIM filters."))),
        1 => Ok(hits.pop()),
        _ => Err(ScimError::new(None, format!("The app has more than one entry with {attr} \"{wanted}\"."))),
    }
}

/// A single user or group the app returned, which must at least say its id.
fn resource(v: Value) -> ScimResult<Value> {
    if v.get("id").and_then(Value::as_str).is_some_and(|id| !id.is_empty()) {
        Ok(v)
    } else {
        Err(ScimError::new(None, "The app answered with something that is not a SCIM resource (no id)."))
    }
}

fn describe_transport_error(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "The app did not answer within 30 seconds".into()
    } else if e.is_connect() {
        "Could not connect to the app. Check the URL.".into()
    } else if e.is_redirect() {
        "The app answered with a redirect. Use the final SCIM URL.".into()
    } else {
        "Could not reach the app".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_prefix_is_stripped() {
        for pasted in ["abc123", " abc123\n", "Bearer abc123", "bearer  abc123", "Authorization: Bearer abc123"] {
            match Auth::from_parts("bearer", None, pasted) {
                Auth::Bearer(t) => assert_eq!(t, "abc123", "pasted {pasted:?}"),
                _ => panic!("expected bearer auth"),
            }
        }
    }

    #[test]
    fn a_blank_header_name_falls_back_to_x_api_key() {
        for name in [None, Some(""), Some("  ")] {
            match Auth::from_parts("header", name, "k") {
                Auth::Header { name, value } => assert_eq!((name.as_str(), value.as_str()), ("X-API-Key", "k")),
                _ => panic!("expected header auth"),
            }
        }
        assert!(matches!(Auth::from_parts("header", Some("x-api-key"), "k"), Auth::Header { name, .. } if name == "x-api-key"));
    }

    use axum::extract::Query;
    use axum::http::StatusCode as Status;
    use axum::response::{IntoResponse, Response};
    use axum::routing::get;
    use axum::Router;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// A client for an app served from `router` under `/scim/v2`, giving up on an answer after 300 ms.
    async fn client(router: Router) -> ScimClient {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}/scim/v2", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let http = reqwest::Client::builder().timeout(Duration::from_millis(300)).build().unwrap();
        ScimClient::new(http, &base, Auth::Bearer("t".into()))
    }

    fn people(n: usize) -> Vec<Value> {
        (0..n).map(|i| json!({ "id": format!("u{i}"), "userName": format!("p{i}@acme.eu"), "active": true })).collect()
    }

    /// An app whose `/Users` list answers each `(startIndex, count)` with `answer`.
    async fn lister(answer: impl Fn(usize, usize) -> Value + Clone + Send + Sync + 'static) -> ScimClient {
        client(Router::new().route(
            "/scim/v2/Users",
            get(move |Query(q): Query<HashMap<String, String>>| async move {
                let n = |k: &str| q.get(k).and_then(|v| v.parse().ok()).unwrap_or(1);
                axum::Json(answer(n("startIndex"), n("count")))
            }),
        ))
        .await
    }

    /// The page an honest app answers: `per_page` at most, and the real total unless `total` says otherwise.
    fn page(all: &[Value], start: usize, count: usize, per_page: usize, total: Option<Value>) -> Value {
        let items: Vec<Value> = all.iter().skip(start - 1).take(count.min(per_page)).cloned().collect();
        let mut v = json!({ "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"], "itemsPerPage": items.len(), "Resources": items });
        v["totalResults"] = total.unwrap_or(json!(all.len()));
        v
    }

    #[tokio::test]
    async fn every_page_is_read() {
        let all = people(250);
        let users = lister(move |s, c| page(&all, s, c, 100, None)).await.list_users().await.unwrap();
        assert_eq!(users.len(), 250);

        // An app with smaller pages than asked for, which still says how many it has.
        let all = people(120);
        assert_eq!(lister(move |s, c| page(&all, s, c, 50, None)).await.list_users().await.unwrap().len(), 120);

        // No total: read until a page comes back empty.
        let all = people(150);
        let users = lister(move |s, c| page(&all, s, c, 100, Some(Value::Null))).await.list_users().await.unwrap();
        assert_eq!(users.len(), 150);

        // A total that is only the page's length is not trusted while pages come back full.
        let all = people(250);
        let users = lister(move |s, c| {
            let mut p = page(&all, s, c, 100, None);
            p["totalResults"] = json!(p["Resources"].as_array().unwrap().len());
            p
        })
        .await
        .list_users()
        .await
        .unwrap();
        assert_eq!(users.len(), 250);

        // An app that ignores paging but answers with everyone each time.
        let all = people(30);
        assert_eq!(lister(move |_, _| page(&all, 1, 1000, 1000, None)).await.list_users().await.unwrap().len(), 30);
    }

    #[tokio::test]
    async fn an_empty_app_is_an_empty_list() {
        assert!(lister(|_, _| json!({ "totalResults": 0, "Resources": [] })).await.list_users().await.unwrap().is_empty());
        // RFC 7644 lets an empty list leave Resources out.
        assert!(lister(|_, _| json!({ "totalResults": 0 })).await.list_users().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_answer_that_is_not_a_list_is_an_error_never_an_empty_app() {
        for body in [json!({}), json!({ "totalResults": 3 }), json!({ "totalResults": 1, "Resources": "u1" }), json!({ "totalResults": 1, "Resources": [{ "userName": "p@acme.eu" }] }), json!(null), json!([])] {
            let err = lister(move |_, _| body.clone()).await.list_users().await.unwrap_err();
            assert!(err.message.contains("not a SCIM list"), "{}", err.message);
        }

        // A login page with a 200, as an expired session or a wrong URL gets.
        let app = client(Router::new().route("/scim/v2/Users", get(|| async { "<html><body>Sign in</body></html>" }))).await;
        let err = app.list_users().await.unwrap_err();
        assert!(err.message.contains("not SCIM JSON"), "{}", err.message);
        let err = app.find_by_user_name("p0@acme.eu").await.unwrap_err();
        assert!(err.message.contains("not SCIM JSON"), "{}", err.message);
    }

    #[tokio::test]
    async fn a_list_that_stops_short_is_an_error() {
        // The total says 250, but the pages run out after 100.
        let all = people(100);
        let err = lister(move |s, c| page(&all, s, c, 100, Some(json!(250)))).await.list_users().await.unwrap_err();
        assert!(err.message.contains("listed 100 users of the 250"), "{}", err.message);

        // The app ignores startIndex and repeats the first page.
        let all = people(250);
        let err = lister(move |_, c| page(&all, 1, c, 100, None)).await.list_users().await.unwrap_err();
        assert!(err.message.contains("the same users again"), "{}", err.message);

        // No total and no end: give up rather than loop.
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let err = lister(move |s, _| {
            seen.fetch_add(1, Ordering::SeqCst);
            json!({ "Resources": [{ "id": format!("u{s}"), "userName": format!("p{s}@acme.eu") }] })
        })
        .await
        .list_users()
        .await
        .unwrap_err();
        assert!(err.message.contains("more than 1000 pages"), "{}", err.message);
        assert_eq!(calls.load(Ordering::SeqCst), 1000);
    }

    #[tokio::test]
    async fn a_search_answered_with_someone_else_is_an_error() {
        let all = people(3);
        let app = lister(move |_, _| page(&all, 1, 100, 100, None)).await;
        let err = app.find_by_user_name("new@acme.eu").await.unwrap_err();
        assert!(err.message.contains("ignores SCIM filters"), "{}", err.message);
        assert_eq!(app.find_by_user_name("P1@acme.eu").await.unwrap().unwrap()["id"], "u1", "userName is matched without case");

        let app = lister(|_, _| json!({ "totalResults": 0, "Resources": [] })).await;
        assert!(app.find_by_user_name("new@acme.eu").await.unwrap().is_none());

        let app = lister(|_, _| json!({ "totalResults": 2, "Resources": [{ "id": "a", "userName": "p@acme.eu" }, { "id": "b", "userName": "P@acme.eu" }] })).await;
        assert!(app.find_by_user_name("p@acme.eu").await.unwrap_err().message.contains("more than one"));
    }

    /// An app that counts the requests reaching `/Users` and answers each as `answer` says for
    /// that attempt (1, 2, …).
    async fn counting(answer: impl Fn(usize) -> Response + Clone + Send + Sync + 'static) -> (ScimClient, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let handler = move || {
            let answer = answer.clone();
            let seen = seen.clone();
            async move { answer(seen.fetch_add(1, Ordering::SeqCst) + 1) }
        };
        let router = Router::new().route("/scim/v2/Users", get(handler.clone()).post(handler.clone())).route("/scim/v2/Users/{id}", get(handler.clone()).put(handler));
        (client(router).await, calls)
    }

    fn unavailable() -> Response {
        (Status::SERVICE_UNAVAILABLE, [("retry-after", "0")], "busy").into_response()
    }

    #[tokio::test]
    async fn a_create_is_sent_once_when_its_outcome_is_unknown() {
        let new_user = json!({ "userName": "new@acme.eu" });

        // The app takes longer than the client waits: the create may have gone through.
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let slow = move || async move {
            seen.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(500)).await;
            axum::Json(json!({ "id": "u9" }))
        };
        let app = client(Router::new().route("/scim/v2/Users", axum::routing::post(slow))).await;
        let err = app.create_user(&new_user).await.unwrap_err();
        assert!(err.uncertain && err.status.is_none(), "{err:?}");
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1, "a timed-out create is never sent again");

        // A server error may come after the account was made.
        let (app, calls) = counting(|_| unavailable()).await;
        let err = app.create_user(&new_user).await.unwrap_err();
        assert!(err.uncertain && err.status == Some(503), "{err:?}");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // A 429 means the app did nothing, so the create is tried again.
        let (app, calls) = counting(|n| if n == 1 { (Status::TOO_MANY_REQUESTS, [("retry-after", "0")], "slow down").into_response() } else { (Status::CREATED, axum::Json(json!({ "id": "u9" }))).into_response() }).await;
        assert_eq!(app.create_user(&new_user).await.unwrap()["id"], "u9");
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        // A refusal is definite.
        let (app, _) = counting(|_| (Status::BAD_REQUEST, axum::Json(json!({ "detail": "bad email" }))).into_response()).await;
        let err = app.create_user(&new_user).await.unwrap_err();
        assert!(!err.uncertain && err.message.contains("bad email"), "{err:?}");
    }

    #[tokio::test]
    async fn reads_and_replacements_are_tried_again_after_a_server_error() {
        let answer = |n: usize| if n == 1 { unavailable() } else { axum::Json(json!({ "id": "u1", "userName": "p@acme.eu" })).into_response() };
        let (app, calls) = counting(answer).await;
        assert_eq!(app.get_user("u1").await.unwrap().unwrap()["id"], "u1");
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        let (app, calls) = counting(answer).await;
        app.replace_user("u1", &json!({ "userName": "p@acme.eu" })).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
