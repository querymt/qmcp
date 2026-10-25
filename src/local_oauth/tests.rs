use super::*;
use crate::{BridgeConfig, QmcpServer, policy::PermissionPolicy, transport};
use axum::body::Body;
use serde_json::Value;
use tower::ServiceExt;

const RESOURCE: &str = "https://mcp.example.com/mcp";
const ISSUER: &str = "https://mcp.example.com";
const CALLBACK: &str = "https://client.example/callback?existing=1";
// Public deterministic test fixture, not a runtime credential.
const SECRET: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG._~-";
const STATE: &str = "a&b=+ /?#%\"<>\0";

struct Harness {
    auth: LocalOAuth,
    app: Router,
}
struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    text: String,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_str(&self.text).unwrap()
    }
    fn location(&self) -> Url {
        assert_eq!(self.status, StatusCode::OK);
        assert!(!self.headers.contains_key(header::LOCATION));
        let link = self
            .text
            .split("<a href=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        let link = link
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&");
        Url::parse(&link).unwrap()
    }
    fn parameter(&self, key: &str) -> String {
        self.location()
            .query_pairs()
            .find(|(k, _)| k == key)
            .unwrap()
            .1
            .into_owned()
    }
}

fn encoded(pairs: &[(&str, &str)]) -> String {
    form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs.iter().copied())
        .finish()
}

impl Harness {
    fn new() -> Self {
        let auth = LocalOAuth::new(RESOURCE, SECRET).unwrap();
        let server = QmcpServer::new(
            BridgeConfig::new("127.0.0.1:1", false, PermissionPolicy::Cancel).unwrap(),
        )
        .unwrap();
        let app = transport::http_router_with_local_oauth(
            server,
            "127.0.0.1:3031".parse().unwrap(),
            auth.clone(),
            &[],
        )
        .unwrap();
        Self { auth, app }
    }

    async fn request(
        &self,
        method: &str,
        uri: &str,
        body: String,
        headers: &[(&str, &str)],
    ) -> Reply {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header("host", "mcp.example.com");
        for (key, value) in headers {
            request = request.header(*key, *value);
        }
        let response = self
            .app
            .clone()
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()["x-frame-options"], "DENY");
        let status = response.status();
        let headers = response.headers().clone();
        let text = String::from_utf8(
            to_bytes(response.into_body(), 65536)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        Reply {
            status,
            headers,
            text,
        }
    }

    async fn register(&self, value: Value) -> Reply {
        self.request(
            "POST",
            "/oauth/register",
            value.to_string(),
            &[("content-type", "application/json")],
        )
        .await
    }

    async fn client(&self) -> String {
        let response = self.register(json!({ "redirect_uris": [CALLBACK], "client_name": "<script>untrusted & client</script>" })).await;
        assert_eq!(response.status, StatusCode::CREATED, "{}", response.text);
        response.json()["client_id"].as_str().unwrap().into()
    }

    async fn authorize(&self, client: &str, changes: &[(&str, &str)]) -> Reply {
        let challenge = URL_SAFE_NO_PAD.encode(digest(VERIFIER));
        let mut pairs = vec![
            ("client_id", client),
            ("redirect_uri", CALLBACK),
            ("resource", RESOURCE),
            ("scope", SCOPE),
            ("response_type", "code"),
            ("code_challenge_method", "S256"),
            ("code_challenge", challenge.as_str()),
            ("state", STATE),
        ];
        for (key, value) in changes {
            pairs.retain(|(k, _)| k != key);
            pairs.push((key, value));
        }
        self.request(
            "GET",
            &format!("/oauth/authorize?{}", encoded(&pairs)),
            String::new(),
            &[],
        )
        .await
    }

    fn browser(reply: &Reply) -> (String, String) {
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text);
        let cookie = reply.headers[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let csrf = reply
            .text
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap()
            .to_owned();
        (cookie, csrf)
    }

    async fn consent(
        &self,
        cookie: &str,
        csrf: &str,
        secret: &str,
        decision: &str,
        origin: Option<&str>,
    ) -> Reply {
        let mut headers = vec![
            ("content-type", "application/x-www-form-urlencoded"),
            ("cookie", cookie),
        ];
        if let Some(origin) = origin {
            headers.push(("origin", origin));
        }
        self.request(
            "POST",
            "/oauth/authorize",
            encoded(&[
                ("csrf", csrf),
                ("owner_secret", secret),
                ("decision", decision),
            ]),
            &headers,
        )
        .await
    }

    async fn code(&self, client: &str) -> String {
        let page = self.authorize(client, &[]).await;
        let (cookie, csrf) = Self::browser(&page);
        let response = self
            .consent(&cookie, &csrf, SECRET, "approve", Some(ISSUER))
            .await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.parameter("iss"), ISSUER);
        assert_eq!(response.parameter("state"), STATE);
        assert_eq!(response.parameter("existing"), "1");
        response.parameter("code")
    }

    async fn refresh_client(&self) -> String {
        let reply = self
            .register(json!({
                "redirect_uris": [CALLBACK], "client_name": "ChatGPT", "scope": SCOPE,
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
                "client_uri": "https://client.example/", "logo_uri": "https://client.example/icon",
                "application_type": "web", "unknown_metadata": {"safe": [1, 2]}
            }))
            .await;
        assert_eq!(reply.status, StatusCode::CREATED);
        assert_eq!(
            reply.json()["grant_types"],
            json!(["authorization_code", "refresh_token"])
        );
        assert_eq!(reply.json()["token_endpoint_auth_method"], "none");
        reply.json()["client_id"].as_str().unwrap().to_owned()
    }

    async fn refresh(&self, client: &str, token: &str, changes: &[(&str, &str)]) -> Reply {
        let mut pairs = vec![
            ("grant_type", "refresh_token"),
            ("client_id", client),
            ("refresh_token", token),
        ];
        for (key, value) in changes {
            pairs.retain(|(k, _)| k != key);
            pairs.push((key, value));
        }
        self.request(
            "POST",
            "/oauth/token",
            encoded(&pairs),
            &[("content-type", "application/x-www-form-urlencoded")],
        )
        .await
    }

    async fn initial_tokens(&self, client: &str) -> Value {
        let code = self.code(client).await;
        let reply = self.exchange(client, &code, &[]).await;
        assert_eq!(reply.status, StatusCode::OK);
        reply.json()
    }

    async fn mcp_status(&self, access: &str) -> StatusCode {
        let bearer = format!("Bearer {access}");
        let initialize = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1"}}});
        self.request(
            "POST",
            "/mcp",
            initialize.to_string(),
            &[
                ("authorization", &bearer),
                ("content-type", "application/json"),
                ("accept", "application/json, text/event-stream"),
            ],
        )
        .await
        .status
    }

    async fn exchange(&self, client: &str, code: &str, changes: &[(&str, &str)]) -> Reply {
        let mut pairs = vec![
            ("grant_type", "authorization_code"),
            ("client_id", client),
            ("code", code),
            ("redirect_uri", CALLBACK),
            ("resource", RESOURCE),
            ("code_verifier", VERIFIER),
        ];
        for (key, value) in changes {
            pairs.retain(|(k, _)| k != key);
            pairs.push((key, value));
        }
        self.request(
            "POST",
            "/oauth/token",
            encoded(&pairs),
            &[("content-type", "application/x-www-form-urlencoded")],
        )
        .await
    }
}

#[tokio::test]
async fn token_protects_real_mcp_transport_without_origin_stripping() {
    let h = Harness::new();
    let unauthenticated = h.request("POST", "/mcp", String::new(), &[]).await;
    assert_eq!(unauthenticated.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        unauthenticated.headers[header::WWW_AUTHENTICATE],
        format!(
            "Bearer resource_metadata=\"{ISSUER}/.well-known/oauth-protected-resource/mcp\", scope=\"{SCOPE}\""
        )
    );
    let client = h.client().await;
    let tokens = h.initial_tokens(&client).await;
    let access = tokens["access_token"].as_str().unwrap();
    let bearer = format!("Bearer {access}");
    let forbidden = h
        .request(
            "POST",
            "/mcp",
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
                "protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}).to_string(),
            &[
                ("authorization", &bearer),
                ("origin", ISSUER),
                ("content-type", "application/json"),
                ("accept", "application/json, text/event-stream"),
            ],
        )
        .await;
    assert_eq!(forbidden.status, StatusCode::FORBIDDEN);
    assert_eq!(h.mcp_status(access).await, StatusCode::OK);
    for reply in [unauthenticated, forbidden] {
        let output = format!("{:?}{}", reply.headers, reply.text);
        for credential in [access, SECRET, VERIFIER] {
            assert!(!output.contains(credential));
        }
    }
}

#[tokio::test]
async fn discovery_and_all_route_host_origin_guards() {
    let h = Harness::new();
    for path in [
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
    ] {
        let r = h.request("GET", path, String::new(), &[]).await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(r.json()["resource"], RESOURCE);
        assert_eq!(r.json()["authorization_servers"], json!([ISSUER]));
    }
    let r = h
        .request(
            "GET",
            "/.well-known/oauth-authorization-server",
            String::new(),
            &[],
        )
        .await;
    let metadata = r.json();
    assert_eq!(metadata["issuer"], ISSUER);
    assert_eq!(
        metadata["code_challenge_methods_supported"],
        json!(["S256"])
    );
    assert_eq!(
        metadata["grant_types_supported"],
        json!(["authorization_code", "refresh_token"])
    );
    assert_eq!(
        metadata["token_endpoint_auth_methods_supported"],
        json!(["none"])
    );
    assert_eq!(
        metadata["authorization_response_iss_parameter_supported"],
        true
    );
    assert!(metadata.get("refresh_token").is_none());
    for (key, path) in [
        ("authorization_endpoint", "/oauth/authorize"),
        ("token_endpoint", "/oauth/token"),
        ("registration_endpoint", "/oauth/register"),
    ] {
        assert_eq!(metadata[key], format!("{ISSUER}{path}"));
    }
    for path in [
        "/mcp",
        "/unknown",
        "/oauth/authorize",
        "/oauth/register",
        "/oauth/token",
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-protected-resource",
    ] {
        let r = h
            .request("GET", path, String::new(), &[("host", "evil.example")])
            .await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{path}");
        let r = h
            .request("GET", path, String::new(), &[("origin", ISSUER)])
            .await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{path}");
    }
    let r = h
        .request(
            "POST",
            "/oauth/token?owner_secret=not-allowed",
            String::new(),
            &[],
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn dcr_validation_body_bounds_and_rate_limit() {
    for value in [
        json!({"redirect_uris": []}),
        json!({"redirect_uris": ["http://remote.example/cb"]}),
        json!({"redirect_uris": ["https://u:p@client.example/cb"]}),
        json!({"redirect_uris": ["https://client.example/cb#x"]}),
        json!({"redirect_uris": ["https://client.example/cb?code=x"]}),
        json!({"redirect_uris": [CALLBACK], "token_endpoint_auth_method": "client_secret_post"}),
        json!({"redirect_uris": [CALLBACK], "grant_types": ["refresh_token"]}),
        json!({"redirect_uris": [CALLBACK], "grant_types": []}),
        json!({"redirect_uris": [CALLBACK], "grant_types": ["authorization_code", "authorization_code"]}),
        json!({"redirect_uris": [CALLBACK], "grant_types": ["authorization_code", "refresh_token", "refresh_token"]}),
        json!({"redirect_uris": [CALLBACK], "grant_types": ["authorization_code", "client_credentials"]}),
        json!({"redirect_uris": [CALLBACK], "scope": "other"}),
        json!({"redirect_uris": [CALLBACK], "response_types": ["token"]}),
        json!({"redirect_uris": [CALLBACK], "client_name": "x".repeat(129)}),
        json!({"redirect_uris": vec![CALLBACK; 9]}),
    ] {
        let h = Harness::new();
        let r = h.register(value).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.text);
        assert!(h.auth.0.store.lock().unwrap().clients.is_empty());
    }
    for uri in [
        "http://localhost:3210/callback",
        "http://127.0.0.1:3210/callback",
        "http://[::1]:3210/callback",
        CALLBACK,
    ] {
        assert!(valid_redirect(uri), "{uri}");
    }
    for uri in [
        "http://localhost.evil/cb",
        "http://192.168.0.1/cb",
        "javascript:alert(1)",
        "https://client.example",
        "https://client.example/cb?iss=x",
    ] {
        assert!(!valid_redirect(uri), "{uri}");
    }
    let h = Harness::new();
    let r = h
        .request(
            "POST",
            "/oauth/register",
            "x".repeat(MAX_BODY + 1),
            &[("content-type", "application/json")],
        )
        .await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
    for _ in 0..16 {
        h.client().await;
    }
    assert_eq!(
        h.register(json!({"redirect_uris": [CALLBACK]}))
            .await
            .status,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn owner_login_consent_csrf_and_origin_are_mandatory() {
    let h = Harness::new();
    let client = h.client().await;
    let page = h.authorize(&client, &[]).await;
    assert!(
        page.text
            .contains("&lt;script&gt;untrusted &amp; client&lt;/script&gt;")
    );
    assert!(!page.text.contains("<script>"));
    assert!(!page.text.contains(SECRET));
    let set_cookie = page.headers[header::SET_COOKIE].to_str().unwrap();
    for attribute in [
        "Secure",
        "HttpOnly",
        "SameSite=Lax",
        "Path=/oauth/authorize",
        "Max-Age=300",
    ] {
        assert!(set_cookie.contains(attribute));
    }
    let (cookie, csrf) = Harness::browser(&page);
    for origin in [
        None,
        Some("null"),
        Some("https://evil.example"),
        Some("https://mcp.example.com.evil"),
        Some("https://mcp.example.com/"),
    ] {
        assert_eq!(
            h.consent(&cookie, &csrf, SECRET, "approve", origin)
                .await
                .status,
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        h.consent(&cookie, "wrong-csrf", SECRET, "approve", Some(ISSUER))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        h.consent(&cookie, &csrf, SECRET, "approve", Some(ISSUER))
            .await
            .status,
        StatusCode::OK
    );
    // The invalid CSRF did not destroy the flow; valid approval is now consumed.
    assert_eq!(
        h.consent(&cookie, &csrf, SECRET, "approve", Some(ISSUER))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    h.auth.0.store.lock().unwrap().codes.clear();
    for secret in ["", "wrong-password"] {
        let page = h.authorize(&client, &[]).await;
        let (cookie, csrf) = Harness::browser(&page);
        let r = h
            .consent(&cookie, &csrf, secret, "approve", Some(ISSUER))
            .await;
        assert_eq!(r.parameter("error"), "access_denied");
        assert_eq!(r.parameter("iss"), ISSUER);
        assert!(!r.text.contains(secret) || secret.is_empty());
    }
    let page = h.authorize(&client, &[]).await;
    let (cookie, csrf) = Harness::browser(&page);
    let r = h.consent(&cookie, &csrf, "", "deny", Some(ISSUER)).await;
    assert_eq!(r.parameter("error"), "access_denied");
    assert_eq!(r.parameter("state"), STATE);
    assert!(h.auth.0.store.lock().unwrap().codes.is_empty());
    let page = h.authorize(&client, &[]).await;
    let (cookie, csrf) = Harness::browser(&page);
    let r = h.consent(&cookie, &csrf, SECRET, "", Some(ISSUER)).await;
    assert_eq!(r.parameter("error"), "access_denied");
    assert!(h.auth.0.store.lock().unwrap().codes.is_empty());
}

#[tokio::test]
async fn authorize_exact_redirect_resource_scope_pkce_and_encoded_errors() {
    let h = Harness::new();
    let client = h.client().await;
    for changes in [
        vec![("response_type", "token")],
        vec![("resource", "https://other.example/mcp")],
        vec![("scope", "other")],
        vec![("code_challenge_method", "plain")],
        vec![("code_challenge", "short")],
    ] {
        let r = h.authorize(&client, &changes).await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(r.parameter("iss"), ISSUER);
        assert_eq!(r.parameter("state"), STATE);
        assert!(r.location().query_pairs().any(|(k, _)| k == "error"));
    }
    for target in [
        "https://client.example/callback",
        "https://client.example/callback?existing=2",
        "https://evil.example/callback",
    ] {
        let r = h.authorize(&client, &[("redirect_uri", target)]).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST);
        assert!(!r.headers.contains_key(header::LOCATION));
    }
    assert_eq!(
        h.authorize(&client, &[("state", &"x".repeat(1025))])
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        h.authorize(&client, &[("owner_secret", SECRET)])
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    assert!(h.auth.0.store.lock().unwrap().transactions.is_empty());
}

#[tokio::test]
async fn code_exchange_pkce_bindings_and_replay() {
    for (key, wrong) in [
        ("client_id", "other-client"),
        ("redirect_uri", "https://client.example/callback"),
        ("resource", "https://other.example/mcp"),
        ("scope", "other"),
        ("code_verifier", "too-short"),
        (
            "code_verifier",
            "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG!bad",
        ),
        (
            "code_verifier",
            "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG._~x",
        ),
    ] {
        let h = Harness::new();
        let client = h.client().await;
        let code = h.code(&client).await;
        assert_eq!(
            h.exchange(&client, &code, &[(key, wrong)]).await.status,
            StatusCode::BAD_REQUEST,
            "{key}"
        );
        assert_eq!(
            h.exchange(&client, &code, &[]).await.status,
            StatusCode::BAD_REQUEST
        );
        assert!(h.auth.0.store.lock().unwrap().tokens.is_empty());
    }
    let h = Harness::new();
    let client = h.client().await;
    let code = h.code(&client).await;
    let (a, b) = tokio::join!(
        h.exchange(&client, &code, &[]),
        h.exchange(&client, &code, &[])
    );
    assert_eq!(
        [a.status, b.status]
            .iter()
            .filter(|s| **s == StatusCode::OK)
            .count(),
        1
    );
    let token_reply = if a.status == StatusCode::OK { a } else { b };
    let json = token_reply.json();
    assert_eq!(json["expires_in"], 1800);
    assert_eq!(json["scope"], SCOPE);
    assert!(json.get("refresh_token").is_none());
    let token = json["access_token"].as_str().unwrap();
    {
        let store = h.auth.0.store.lock().unwrap();
        assert!(store.codes.is_empty());
        assert!(store.tokens.contains_key(&digest(token)));
    }
    assert!(h.auth.accepts(token));
    assert!(!h.auth.accepts("not-a-token"));
}

fn grant(client: &str) -> Grant {
    Grant {
        client: client.into(),
        redirect: CALLBACK.into(),
        resource: RESOURCE.into(),
        scope: SCOPE.into(),
        challenge: digest(VERIFIER),
    }
}

#[tokio::test]
async fn every_state_table_is_capped_and_expired_entries_release_slots() {
    let h = Harness::new();
    let client = h.client().await;
    {
        let mut store = h.auth.0.store.lock().unwrap();
        for i in 0..MAX_TRANSACTIONS {
            store.transactions.insert(
                digest(&i.to_string()),
                Transaction {
                    grant: grant(&client),
                    state: None,
                    csrf: digest("csrf"),
                    expires: Instant::now() + TRANSACTION_TTL,
                },
            );
        }
    }
    let response = h.authorize(&client, &[]).await;
    assert_eq!(response.parameter("error"), "temporarily_unavailable");
    assert_eq!(
        h.auth.0.store.lock().unwrap().transactions.len(),
        MAX_TRANSACTIONS
    );
    for t in h.auth.0.store.lock().unwrap().transactions.values_mut() {
        t.expires = Instant::now() - Duration::from_secs(1);
    }
    let page = h.authorize(&client, &[]).await;
    assert_eq!(h.auth.0.store.lock().unwrap().transactions.len(), 1);
    let (cookie, csrf) = Harness::browser(&page);
    {
        let mut store = h.auth.0.store.lock().unwrap();
        for i in 0..MAX_CODES {
            store.codes.insert(
                digest(&i.to_string()),
                Code {
                    grant: grant(&client),
                    expires: Instant::now() + CODE_TTL,
                },
            );
        }
    }
    let response = h
        .consent(&cookie, &csrf, SECRET, "approve", Some(ISSUER))
        .await;
    assert_eq!(response.parameter("error"), "temporarily_unavailable");
    assert_eq!(h.auth.0.store.lock().unwrap().codes.len(), MAX_CODES);
    for c in h.auth.0.store.lock().unwrap().codes.values_mut() {
        c.expires = Instant::now() - Duration::from_secs(1);
    }
    let code = h.code(&client).await;
    assert_eq!(h.auth.0.store.lock().unwrap().codes.len(), 1);
    {
        let mut store = h.auth.0.store.lock().unwrap();
        for i in 0..MAX_TOKENS {
            store.tokens.insert(
                digest(&i.to_string()),
                Token {
                    family: None,
                    client: client.clone(),
                    resource: RESOURCE.into(),
                    scope: SCOPE.into(),
                    expires: Instant::now() + TOKEN_TTL,
                },
            );
        }
    }
    assert_eq!(
        h.exchange(&client, &code, &[]).await.status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(h.auth.0.store.lock().unwrap().tokens.len(), MAX_TOKENS);
    for token in h.auth.0.store.lock().unwrap().tokens.values_mut() {
        token.expires = Instant::now() - Duration::from_secs(1);
    }
    let code = h.code(&client).await;
    assert_eq!(h.exchange(&client, &code, &[]).await.status, StatusCode::OK);
    assert_eq!(h.auth.0.store.lock().unwrap().tokens.len(), 1);
}

#[tokio::test]
async fn chatgpt_dcr_grant_sets_are_normalized_and_metadata_urls_are_not_fetched() {
    let h = Harness::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let metadata_url = format!("http://{}/metadata", listener.local_addr().unwrap());
    for grants in [
        json!(["authorization_code", "refresh_token"]),
        json!(["refresh_token", "authorization_code"]),
    ] {
        let reply = h
            .register(json!({
                "redirect_uris": [CALLBACK], "client_name": "ChatGPT",
                "token_endpoint_auth_method": "none", "grant_types": grants,
                "response_types": ["code"], "scope": SCOPE,
                "client_uri": metadata_url, "logo_uri": metadata_url,
                "application_type": "web", "unknown_safe": {"nested": true}
            }))
            .await;
        assert_eq!(reply.status, StatusCode::CREATED);
        assert_eq!(
            reply.json()["grant_types"],
            json!(["authorization_code", "refresh_token"])
        );
        assert_eq!(reply.json()["token_endpoint_auth_method"], "none");
        assert!(!reply.text.contains("metadata"));
        let client = reply.json()["client_id"].as_str().unwrap().to_owned();
        assert!(h.auth.0.store.lock().unwrap().clients[&client].refresh_allowed);
    }
    for metadata in [
        json!({"redirect_uris": [CALLBACK]}),
        json!({"redirect_uris": [CALLBACK], "grant_types": ["authorization_code"]}),
    ] {
        let reply = h.register(metadata).await;
        assert_eq!(reply.status, StatusCode::CREATED);
        assert_eq!(reply.json()["grant_types"], json!(["authorization_code"]));
        let client = reply.json()["client_id"].as_str().unwrap().to_owned();
        assert!(!h.auth.0.store.lock().unwrap().clients[&client].refresh_allowed);
        let tokens = h.initial_tokens(&client).await;
        assert!(tokens.get("refresh_token").is_none());
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn refresh_issuance_requires_registered_permission_owner_consent_and_pkce() {
    let h = Harness::new();
    let client = h.refresh_client().await;
    assert!(h.auth.0.store.lock().unwrap().refresh.is_empty());
    let page = h.authorize(&client, &[]).await;
    let (cookie, csrf) = Harness::browser(&page);
    let denied = h
        .consent(&cookie, &csrf, SECRET, "deny", Some(ISSUER))
        .await;
    assert_eq!(denied.parameter("error"), "access_denied");
    assert!(h.auth.0.store.lock().unwrap().refresh.is_empty());
    let code = h.code(&client).await;
    let bad = h
        .exchange(&client, &code, &[("code_verifier", "too-short")])
        .await;
    assert_eq!(bad.json()["error"], "invalid_grant");
    assert!(h.auth.0.store.lock().unwrap().refresh.is_empty());
    let tokens = h.initial_tokens(&client).await;
    assert_eq!(tokens["expires_in"], 1800);
    let refresh = tokens["refresh_token"].as_str().unwrap();
    assert_eq!(URL_SAFE_NO_PAD.decode(refresh).unwrap().len(), 32);
    assert!(!h.auth.accepts(refresh));
    let no_refresh_client = h.client().await;
    assert_eq!(
        h.refresh(&no_refresh_client, refresh, &[]).await.json()["error"],
        "invalid_grant"
    );
    let no_refresh = h.initial_tokens(&no_refresh_client).await;
    assert!(no_refresh.get("refresh_token").is_none());
    assert_eq!(
        h.refresh(
            &no_refresh_client,
            no_refresh["access_token"].as_str().unwrap(),
            &[]
        )
        .await
        .json()["error"],
        "invalid_grant"
    );
    assert_eq!(
        h.refresh(&client, refresh, &[]).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn refresh_rotation_replay_revokes_only_its_family_including_real_mcp_access() {
    let h = Harness::new();
    let client = h.refresh_client().await;
    let other_client = h.refresh_client().await;
    let original = h.initial_tokens(&client).await;
    let independent = h.initial_tokens(&client).await;
    let other = h.initial_tokens(&other_client).await;
    let old = original["refresh_token"].as_str().unwrap();
    let family = digest(old);
    let deadline = h.auth.0.store.lock().unwrap().families[&family].expires;
    let rotated = h.refresh(&client, old, &[]).await;
    assert_eq!(rotated.status, StatusCode::OK);
    let rotated = rotated.json();
    let current = rotated["refresh_token"].as_str().unwrap();
    assert!(old != current);
    assert!(original["access_token"] != rotated["access_token"]);
    assert_eq!(rotated["expires_in"], 1800);
    {
        let store = h.auth.0.store.lock().unwrap();
        assert_eq!(store.families[&family].expires, deadline);
        assert!(store.refresh[&digest(old)].consumed);
        assert!(!store.refresh[&digest(current)].consumed);
        assert_eq!(store.families[&family].records, 2);
    }
    for tokens in [&original, &rotated, &independent, &other] {
        assert_eq!(
            h.mcp_status(tokens["access_token"].as_str().unwrap()).await,
            StatusCode::OK
        );
    }
    let replay = h.refresh(&client, old, &[]).await;
    assert_eq!(replay.status, StatusCode::BAD_REQUEST);
    assert_eq!(replay.json(), json!({"error": "invalid_grant"}));
    for tokens in [&original, &rotated] {
        assert_eq!(
            h.mcp_status(tokens["access_token"].as_str().unwrap()).await,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        h.refresh(&client, current, &[]).await.json()["error"],
        "invalid_grant"
    );
    for (id, tokens) in [(&client, &independent), (&other_client, &other)] {
        assert_eq!(
            h.mcp_status(tokens["access_token"].as_str().unwrap()).await,
            StatusCode::OK
        );
        assert_eq!(
            h.refresh(id, tokens["refresh_token"].as_str().unwrap(), &[])
                .await
                .status,
            StatusCode::OK
        );
    }
    let mut store = h.auth.0.store.lock().unwrap();
    store.prune(Instant::now() + TOKEN_TTL + Duration::from_secs(1));
    assert!(store.families[&family].revoked);
    assert!(store.refresh.contains_key(&digest(old)));
    assert!(store.refresh.contains_key(&digest(current)));
    store.prune(deadline);
    assert!(!store.families.contains_key(&family));
    assert!(!store.refresh.contains_key(&digest(old)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_refresh_exchanges_issue_once_then_replay_revokes_the_winner() {
    let h = Arc::new(Harness::new());
    let client = h.refresh_client().await;
    let tokens = h.initial_tokens(&client).await;
    let raw = tokens["refresh_token"].as_str().unwrap().to_owned();
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let mut jobs = Vec::new();
    for _ in 0..2 {
        let (h, client, raw, barrier) = (h.clone(), client.clone(), raw.clone(), barrier.clone());
        jobs.push(tokio::spawn(async move {
            barrier.wait().await;
            h.refresh(&client, &raw, &[]).await
        }));
    }
    let a = jobs.remove(0).await.unwrap();
    let b = jobs.remove(0).await.unwrap();
    assert_eq!(
        [a.status, b.status]
            .iter()
            .filter(|s| **s == StatusCode::OK)
            .count(),
        1
    );
    let (winner, replay) = if a.status == StatusCode::OK {
        (a, b)
    } else {
        (b, a)
    };
    assert_eq!(replay.status, StatusCode::BAD_REQUEST);
    assert_eq!(replay.json()["error"], "invalid_grant");
    let winner = winner.json();
    assert_eq!(
        h.refresh(&client, winner["refresh_token"].as_str().unwrap(), &[])
            .await
            .json()["error"],
        "invalid_grant"
    );
    assert_eq!(
        h.mcp_status(winner["access_token"].as_str().unwrap()).await,
        StatusCode::UNAUTHORIZED
    );
    let store = h.auth.0.store.lock().unwrap();
    assert_eq!(store.families.len(), 1);
    assert_eq!(store.refresh.len(), 2);
    assert!(store.tokens.is_empty());
}

#[test]
fn resource_and_secret_validation_do_not_echo_credentials() {
    for resource in [
        "http://mcp.example.com/mcp",
        "https://u:p@mcp.example.com/mcp",
        "https://mcp.example.com/",
        "https://mcp.example.com/mcp?x=1",
        "https://mcp.example.com/mcp#x",
        "https://MCP.example.com/mcp",
    ] {
        assert!(LocalOAuth::new(resource, SECRET).is_err(), "{resource}");
    }
    for secret in [
        "password".into(),
        "a".repeat(64),
        "01".repeat(32),
        SECRET.to_uppercase(),
    ] {
        let e = LocalOAuth::new(RESOURCE, &secret)
            .err()
            .unwrap()
            .to_string();
        assert!(!e.contains(&secret));
    }
}

#[cfg(unix)]
#[test]
fn secret_file_requires_absolute_owned_0600_regular_file_without_links() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = std::env::temp_dir().join(format!("qmcp-oauth-fixture-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.join("fixture");
    std::fs::write(&path, format!("{SECRET}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(LocalOAuth::from_secret_file(RESOURCE, &path).is_ok());
    assert!(LocalOAuth::from_secret_file(RESOURCE, Path::new("relative")).is_err());
    for mode in [0o644, 0o660, 0o400, 0o1600] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(LocalOAuth::from_secret_file(RESOURCE, &path).is_err());
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let link = dir.join("symlink");
    symlink(&path, &link).unwrap();
    assert!(LocalOAuth::from_secret_file(RESOURCE, &link).is_err());
    let hardlink = dir.join("hardlink");
    std::fs::hard_link(&path, &hardlink).unwrap();
    assert!(LocalOAuth::from_secret_file(RESOURCE, &hardlink).is_err());
    assert!(LocalOAuth::from_secret_file(RESOURCE, &dir).is_err());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn request_parsing_and_browser_policy_fail_closed() {
    let h = Harness::new();
    let client = h.client().await;
    for invalid in [
        b"state=one&state=two".as_slice(),
        b"state=%",
        b"state=%GG",
        b"state=%FF",
        b"state=\xff",
    ] {
        assert!(fields(invalid).is_err());
    }
    for key in [
        "client_id",
        "resource",
        "code",
        "code_verifier",
        "grant_type",
        "client_assertion",
    ] {
        assert!(fields(format!("{key}=one&{key}=two").as_bytes()).is_err());
    }
    let duplicate = format!(
        r#"{{"redirect_uris":["{CALLBACK}"],"token_endpoint_auth_method":null,"token_endpoint_auth_method":"none"}}"#
    );
    assert_eq!(
        h.request(
            "POST",
            "/oauth/register",
            duplicate,
            &[("content-type", "application/json")]
        )
        .await
        .status,
        StatusCode::BAD_REQUEST
    );
    let permits = h.auth.0.body_slots.acquire_many(16).await.unwrap();
    assert_eq!(
        h.register(json!({"redirect_uris":[CALLBACK]})).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    drop(permits);
    let page = h.authorize(&client, &[]).await;
    assert_eq!(page.headers["referrer-policy"], "same-origin");
    assert_eq!(
        page.headers["content-security-policy"],
        "default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    );
    let (cookie, csrf) = Harness::browser(&page);
    for bad_cookie in [String::new(), format!("{cookie}; {cookie}")] {
        assert_eq!(
            h.consent(&bad_cookie, &csrf, SECRET, "approve", Some(ISSUER))
                .await
                .status,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        h.auth.0.store.lock().unwrap().clients[&client]
            .login_rate
            .used,
        0
    );
    let result = h
        .consent(&cookie, &csrf, SECRET, "approve", Some(ISSUER))
        .await;
    assert!(
        result
            .text
            .contains("rel=\"noreferrer noopener\">Continue to ChatGPT</a>")
    );
    assert!(!result.headers.contains_key(header::LOCATION));
    for forbidden in ["<script", "<form", "http-equiv", SECRET] {
        assert!(!result.text.contains(forbidden));
    }
    assert_eq!(result.parameter("state"), STATE);
}

#[tokio::test]
async fn consent_discloses_refresh_lifetime_without_trusting_extensions() {
    let h = Harness::new();
    for refresh in [false, true] {
        let client = if refresh {
            h.refresh_client().await
        } else {
            h.client().await
        };
        let page = h
            .authorize(
                &client,
                &[
                    ("refresh_allowed", "true"),
                    ("consent_duration", "<script>ignored</script>"),
                ],
            )
            .await;
        Harness::browser(&page);
        assert!(
            page.text
                .contains("Only approve a client and callback you trust.")
        );
        assert!(page.text.contains(&format!(
            "Approve grants all QueryMT tools on {RESOURCE} (scope {SCOPE})."
        )));
        assert_eq!(
            page.text
                .contains("24 hours from the initial code exchange"),
            refresh
        );
        assert!(page.text.contains("30 minutes"));
        assert!(!page.text.contains("<script>"));
        let store = h.auth.0.store.lock().unwrap();
        assert!(!store.clients[&client].approved);
        assert!(store.codes.is_empty() && store.tokens.is_empty() && store.refresh.is_empty());
    }
}

#[tokio::test]
async fn approved_clients_survive_pruning_and_owner_attempts_are_client_isolated() {
    let h = Harness::new();
    let approved = h.client().await;
    h.code(&approved).await;
    let pending = h.client().await;
    {
        let mut store = h.auth.0.store.lock().unwrap();
        store.prune(Instant::now() + CLIENT_TTL + Duration::from_secs(1));
        assert!(store.clients.contains_key(&approved));
        assert!(!store.clients.contains_key(&pending));
    }
    let attacker = h.client().await;
    for _ in 0..8 {
        let (cookie, csrf) = Harness::browser(&h.authorize(&attacker, &[]).await);
        h.consent(&cookie, &csrf, "wrong", "approve", Some(ISSUER))
            .await;
    }
    let (cookie, csrf) = Harness::browser(&h.authorize(&attacker, &[]).await);
    assert_eq!(
        h.consent(&cookie, &csrf, SECRET, "approve", Some(ISSUER))
            .await
            .status,
        StatusCode::TOO_MANY_REQUESTS
    );
    // Unknown credentials naming the owner cannot spend its exchange budget.
    for _ in 0..61 {
        assert_eq!(
            h.exchange(&approved, "unknown", &[]).await.status,
            StatusCode::BAD_REQUEST
        );
    }
    assert!(h.initial_tokens(&approved).await["access_token"].is_string());
}

#[tokio::test]
async fn unknown_metadata_is_not_fetched_and_security_extensions_remain_strict() {
    let h = Harness::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "http://{}/<script>ignored</script>",
        listener.local_addr().unwrap()
    );
    let reply = h
        .register(json!({"redirect_uris":[CALLBACK],"logo_uri":url,"client_uri":url}))
        .await;
    let client = reply.json()["client_id"].as_str().unwrap().to_owned();
    let page = h.authorize(&client, &[("future_extension", &url)]).await;
    assert!(!page.text.contains("ignored"));
    let code = h.code(&client).await;
    assert_eq!(
        h.exchange(&client, &code, &[("future_extension", &url)])
            .await
            .status,
        StatusCode::OK
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
    for key in ["client_secret", "client_assertion", "client_assertion_type"] {
        assert_eq!(
            h.authorize(&client, &[(key, "unsupported")]).await.status,
            StatusCode::BAD_REQUEST
        );
        let code = h.code(&client).await;
        assert_eq!(
            h.exchange(&client, &code, &[(key, "unsupported")])
                .await
                .status,
            StatusCode::BAD_REQUEST
        );
    }
}

#[tokio::test]
async fn invalid_refresh_bindings_and_malformed_requests_preserve_current_token() {
    let h = Harness::new();
    let client = h.refresh_client().await;
    let other = h.refresh_client().await;
    let tokens = h.initial_tokens(&client).await;
    let raw = tokens["refresh_token"].as_str().unwrap();
    for (key, value, expected) in [
        ("client_id", other.as_str(), "invalid_grant"),
        ("resource", "https://other.example/mcp", "invalid_target"),
        ("scope", "qmcp:access other", "invalid_scope"),
        ("refresh_token", "unknown", "invalid_grant"),
        ("client_secret", "", "invalid_grant"),
        ("code", "mixed-grants", "invalid_grant"),
    ] {
        assert_eq!(
            h.refresh(&client, raw, &[(key, value)]).await.json()["error"],
            expected
        );
        let store = h.auth.0.store.lock().unwrap();
        assert!(!store.refresh[&digest(raw)].consumed && !store.families[&digest(raw)].revoked);
    }
    let body = encoded(&[
        ("grant_type", "refresh_token"),
        ("client_id", &client),
        ("refresh_token", raw),
    ]);
    for malformed in [
        format!("{body}&refresh_token={raw}"),
        format!("{body}&broken=%GG"),
    ] {
        assert_eq!(
            h.request(
                "POST",
                "/oauth/token",
                malformed,
                &[("content-type", "application/x-www-form-urlencoded")]
            )
            .await
            .status,
            StatusCode::BAD_REQUEST
        );
    }
    let rotated = h
        .refresh(&client, raw, &[("resource", RESOURCE), ("scope", SCOPE)])
        .await
        .json();
    for changes in [
        vec![("client_id", other.as_str())],
        vec![("resource", "wrong")],
        vec![("scope", "wrong")],
    ] {
        assert_eq!(
            h.refresh(&client, raw, &changes).await.status,
            StatusCode::BAD_REQUEST
        );
        assert!(!h.auth.0.store.lock().unwrap().families[&digest(raw)].revoked);
    }
    assert_eq!(
        h.refresh(&client, rotated["refresh_token"].as_str().unwrap(), &[])
            .await
            .status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn expiry_and_restart_invalidate_grants_and_mcp_access() {
    let h = Harness::new();
    let client = h.refresh_client().await;
    let (cookie, csrf) = Harness::browser(&h.authorize(&client, &[]).await);
    for transaction in h.auth.0.store.lock().unwrap().transactions.values_mut() {
        transaction.expires = Instant::now();
    }
    assert_eq!(
        h.consent(&cookie, &csrf, SECRET, "approve", Some(ISSUER))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    let code = h.code(&client).await;
    h.auth
        .0
        .store
        .lock()
        .unwrap()
        .codes
        .get_mut(&digest(&code))
        .unwrap()
        .expires = Instant::now();
    assert_eq!(
        h.exchange(&client, &code, &[]).await.status,
        StatusCode::BAD_REQUEST
    );
    let tokens = h.initial_tokens(&client).await;
    let access = tokens["access_token"].as_str().unwrap();
    let refresh = tokens["refresh_token"].as_str().unwrap();
    assert_eq!(h.mcp_status("bad").await, StatusCode::UNAUTHORIZED);
    assert_eq!(h.mcp_status(access).await, StatusCode::OK);
    h.auth
        .0
        .store
        .lock()
        .unwrap()
        .tokens
        .get_mut(&digest(access))
        .unwrap()
        .expires = Instant::now();
    assert_eq!(h.mcp_status(access).await, StatusCode::UNAUTHORIZED);
    let deadline = Instant::now() + Duration::from_secs(10);
    h.auth
        .0
        .store
        .lock()
        .unwrap()
        .families
        .get_mut(&digest(refresh))
        .unwrap()
        .expires = deadline;
    let rotated = h.refresh(&client, refresh, &[]).await.json();
    assert!(rotated["expires_in"].as_u64().unwrap() <= 10);
    {
        let mut store = h.auth.0.store.lock().unwrap();
        assert!(store.tokens.values().all(|token| token.expires <= deadline));
        store.prune(deadline);
        assert!(store.families.is_empty() && store.refresh.is_empty() && store.tokens.is_empty());
    }
    assert_eq!(
        h.refresh(&client, refresh, &[]).await.status,
        StatusCode::BAD_REQUEST
    );
    let restarted = Harness::new();
    assert_eq!(
        restarted
            .refresh(&client, rotated["refresh_token"].as_str().unwrap(), &[])
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        restarted
            .mcp_status(rotated["access_token"].as_str().unwrap())
            .await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        restarted.authorize(&client, &[]).await.status,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn refresh_capacity_failures_preserve_credentials_and_replay_evidence() {
    let h = Harness::new();
    let client = h.refresh_client().await;
    // Exercise the per-client family bound with real grants, not synthetic matrices.
    let mut issued = Vec::new();
    for _ in 0..MAX_CLIENT_FAMILIES {
        issued.push(h.initial_tokens(&client).await);
    }
    // Start another owner-attempt window without waiting a minute in the test.
    h.auth
        .0
        .store
        .lock()
        .unwrap()
        .clients
        .get_mut(&client)
        .unwrap()
        .login_rate = Rate::default();
    let code = h.code(&client).await;
    assert_eq!(
        h.exchange(&client, &code, &[]).await.status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(
        h.auth
            .0
            .store
            .lock()
            .unwrap()
            .codes
            .contains_key(&digest(&code))
    );
    let old = issued[0]["refresh_token"].as_str().unwrap();
    let current = h.refresh(&client, old, &[]).await.json();
    let raw = current["refresh_token"].as_str().unwrap();
    {
        let mut store = h.auth.0.store.lock().unwrap();
        store.clients.get_mut(&client).unwrap().exchange_rate.used = 60;
    }
    assert_eq!(
        h.refresh(&client, raw, &[]).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    {
        let mut store = h.auth.0.store.lock().unwrap();
        store.clients.get_mut(&client).unwrap().exchange_rate = Rate::default();
        store.families.get_mut(&digest(old)).unwrap().records = MAX_FAMILY_RECORDS;
    }
    assert_eq!(
        h.refresh(&client, raw, &[]).await.status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    {
        let store = h.auth.0.store.lock().unwrap();
        assert!(!store.refresh[&digest(raw)].consumed);
        assert!(store.refresh[&digest(old)].consumed);
    }
    assert_eq!(
        h.refresh(&client, old, &[]).await.json()["error"],
        "invalid_grant"
    );
    assert_eq!(
        h.mcp_status(current["access_token"].as_str().unwrap())
            .await,
        StatusCode::UNAUTHORIZED
    );
}
