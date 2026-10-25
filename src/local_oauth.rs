//! Embedded, volatile, single-owner authorization server. External OAuth stays separate.

use std::{
    collections::{HashMap, HashSet},
    io::Read,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::Url;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::transport::bearer_credential;

const SCOPE: &str = "qmcp:access";
const CLIENT_TTL: Duration = Duration::from_secs(3600);
const TRANSACTION_TTL: Duration = Duration::from_secs(300);
const CODE_TTL: Duration = Duration::from_secs(90);
const TOKEN_TTL: Duration = Duration::from_secs(1800);
const FAMILY_TTL: Duration = Duration::from_secs(24 * 3600);
const MAX_FAMILIES: usize = 128;
const MAX_CLIENT_FAMILIES: usize = 8;
const MAX_REFRESH_RECORDS: usize = 8192;
const MAX_FAMILY_RECORDS: usize = 128;
const MAX_CLIENTS: usize = 128;
const MAX_TRANSACTIONS: usize = 128;
const MAX_CODES: usize = 128;
const MAX_TOKENS: usize = 256;
const MAX_UNAPPROVED_CLIENTS: usize = 96;
const MAX_CLIENT_TRANSACTIONS: usize = 8;
const MAX_CLIENT_CODES: usize = 8;
const MAX_CLIENT_TOKENS: usize = 16;
const AGGREGATE_RATE: usize = 4096;
const REGISTRATION_RATE: usize = 1024;
const MAX_REGISTRATION_ORIGINS: usize = 256;
const MAX_BODY: usize = 8192;
const COOKIE: &str = "__Secure-qmcp_oauth";
type Digest32 = [u8; 32];
type Fields = HashMap<String, String>;

/// Deliberately no Debug: owner secrets, forms, codes and tokens must not be logged.
#[derive(Clone)]
pub struct LocalOAuth(Arc<Server>);

struct Server {
    resource: String,
    issuer: String,
    authority: String,
    owner: Digest32,
    store: Mutex<Store>,
    body_slots: tokio::sync::Semaphore,
}

#[derive(Default)]
struct Store {
    clients: HashMap<String, Client>,
    transactions: HashMap<Digest32, Transaction>,
    codes: HashMap<Digest32, Code>,
    tokens: HashMap<Digest32, Token>,
    families: HashMap<Digest32, Family>,
    refresh: HashMap<Digest32, RefreshRecord>,
    registration_rate: Rate,
    authorization_rate: Rate,
    exchange_rate: Rate,
    registration_origins: HashMap<String, Rate>,
}

struct Client {
    redirects: Vec<String>,
    name: String,
    expires: Instant,
    approved: bool,
    refresh_allowed: bool,
    authorization_rate: Rate,
    login_rate: Rate,
    exchange_rate: Rate,
}

struct Grant {
    client: String,
    redirect: String,
    resource: String,
    scope: String,
    challenge: Digest32,
}

struct Transaction {
    grant: Grant,
    state: Option<String>,
    csrf: Digest32,
    expires: Instant,
}

struct Code {
    grant: Grant,
    expires: Instant,
}

struct Family {
    client: String,
    resource: String,
    scope: String,
    expires: Instant,
    records: usize,
    revoked: bool,
}

struct RefreshRecord {
    family: Digest32,
    consumed: bool,
}

struct Token {
    family: Option<Digest32>,
    client: String,
    resource: String,
    scope: String,
    expires: Instant,
}

/// Fixed-memory windows deliberately ignore spoofable proxy/IP headers.
#[derive(Default)]
struct Rate {
    start: Option<Instant>,
    used: usize,
}

impl Rate {
    fn allow(&mut self, now: Instant, limit: usize) -> bool {
        if self
            .start
            .is_none_or(|start| now.duration_since(start) >= Duration::from_secs(60))
        {
            self.start = Some(now);
            self.used = 0;
        }
        if self.used >= limit {
            return false;
        }
        self.used += 1;
        true
    }
}

impl Store {
    fn prune(&mut self, now: Instant) {
        self.clients.retain(|_, c| c.approved || c.expires > now);
        self.registration_origins.retain(|_, rate| {
            rate.start
                .is_some_and(|start| now.duration_since(start) < Duration::from_secs(60))
        });
        self.transactions.retain(|_, t| t.expires > now);
        self.codes.retain(|_, c| c.expires > now);
        self.families.retain(|_, family| family.expires > now);
        self.refresh
            .retain(|_, record| self.families.contains_key(&record.family));
        self.tokens.retain(|_, t| {
            t.expires > now
                && t.family
                    .is_none_or(|id| self.families.get(&id).is_some_and(|family| !family.revoked))
        });
    }

    fn access_capacity(&self, client: &str) -> bool {
        self.tokens.len() < MAX_TOKENS
            && self.tokens.values().filter(|t| t.client == client).count() < MAX_CLIENT_TOKENS
    }

    fn family_capacity(&self, client: &str) -> bool {
        self.families.len() < MAX_FAMILIES
            && self
                .families
                .values()
                .filter(|f| f.client == client)
                .count()
                < MAX_CLIENT_FAMILIES
            && self.refresh.len() < MAX_REFRESH_RECORDS
    }

    fn revoke_family(&mut self, id: Digest32) {
        if let Some(family) = self.families.get_mut(&id) {
            family.revoked = true;
        }
        self.tokens.retain(|_, token| token.family != Some(id));
        // Keep all refresh digests, including the active one, until absolute expiry.
    }
}

impl LocalOAuth {
    /// Read a generated hex credential (32..64 random bytes) from a protected file.
    pub fn from_secret_file(resource: &str, path: &Path) -> Result<Self> {
        if !path.is_absolute() {
            bail!("owner secret file must be an absolute path");
        }
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Reject final-component symlinks and avoid blocking on a FIFO/device.
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = options
            .open(path)
            .context("open protected owner secret file")?;
        let metadata = file.metadata().context("stat owner secret file")?;
        if !metadata.is_file() || metadata.len() > 130 {
            bail!("owner secret must be a small regular file");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            // SAFETY: geteuid has no arguments or memory-safety preconditions.
            let uid = unsafe { libc::geteuid() };
            if metadata.mode() & 0o7777 != 0o600 || metadata.uid() != uid || metadata.nlink() != 1 {
                bail!("owner secret file must be owned by this user, mode 0600, with one link");
            }
        }
        #[cfg(not(unix))]
        bail!("embedded OAuth secret-file protection currently requires Unix");
        let mut secret = String::new();
        file.take(131)
            .read_to_string(&mut secret)
            .context("read owner secret file")?;
        Self::new(resource, secret.trim_end_matches(['\r', '\n']))
    }

    fn new(resource: &str, secret: &str) -> Result<Self> {
        let url = Url::parse(resource).context("invalid local OAuth resource URL")?;
        if resource.len() > 2048
            || url.scheme() != "https"
            || url.host_str().is_none()
            || url.path() != "/mcp"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.as_str() != resource
        {
            bail!(
                "local OAuth resource must be a canonical HTTPS /mcp URL without userinfo, query or fragment"
            );
        }
        // Encoding/length and obvious-weakness checks cannot prove random generation.
        // Only use a CSPRNG-generated credential, never a password or a derived phrase.
        if !(64..=128).contains(&secret.len())
            || !secret.len().is_multiple_of(2)
            || !secret
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            bail!("owner secret must be 32..64 random bytes encoded as lowercase hex");
        }
        let decoded: Vec<u8> = secret
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        if decoded.iter().collect::<HashSet<_>>().len() < 16 {
            bail!("owner secret is obviously weak; generate it using a secure random generator");
        }
        let issuer = url.origin().ascii_serialization();
        let authority = issuer.strip_prefix("https://").unwrap().to_owned();
        Ok(Self(Arc::new(Server {
            resource: resource.into(),
            issuer,
            authority,
            owner: digest(secret),
            store: Mutex::new(Store::default()),
            body_slots: tokio::sync::Semaphore::new(16),
        })))
    }

    pub(crate) fn authority(&self) -> &str {
        &self.0.authority
    }

    pub(crate) fn routes(&self) -> Router {
        Router::new()
            .route("/.well-known/oauth-authorization-server", get(as_metadata))
            .route(
                "/.well-known/oauth-protected-resource",
                get(resource_metadata),
            )
            .route(
                "/.well-known/oauth-protected-resource/mcp",
                get(resource_metadata),
            )
            .route("/oauth/register", post(register))
            .route("/oauth/authorize", get(authorize).post(consent))
            .route("/oauth/token", post(exchange))
            .with_state(self.clone())
    }

    pub(crate) fn guard(&self, router: Router) -> Router {
        router.layer(middleware::from_fn_with_state(self.clone(), guard))
    }

    fn accepts(&self, credential: &str) -> bool {
        let now = Instant::now();
        let mut store = self.0.store.lock().unwrap();
        store.prune(now);
        store.tokens.get(&digest(credential)).is_some_and(|token| {
            token.resource == self.0.resource && token.scope == SCOPE && !token.client.is_empty()
        })
    }
}

fn digest(value: &str) -> Digest32 {
    Sha256::digest(value.as_bytes()).into()
}

struct Failure(StatusCode, &'static str);

impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        error(self.0, self.1)
    }
}

fn random() -> Result<String, Failure> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|_| Failure(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn secure(mut response: Response) -> Response {
    for (key, value) in [
        ("cache-control", "no-store"),
        ("pragma", "no-cache"),
        (
            "content-security-policy",
            "default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        ),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "no-referrer"),
        ("x-content-type-options", "nosniff"),
    ] {
        response
            .headers_mut()
            .insert(key, HeaderValue::from_static(value));
    }
    response
}

fn error(status: StatusCode, name: &'static str) -> Response {
    secure((status, Json(json!({"error": name}))).into_response())
}

fn one_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(value)
}

async fn guard(State(auth): State<LocalOAuth>, request: Request, next: Next) -> Response {
    let host_ok = one_header(request.headers(), "host")
        .is_some_and(|host| host.eq_ignore_ascii_case(&auth.0.authority));
    let browser_post =
        request.method() == Method::POST && request.uri().path() == "/oauth/authorize";
    let origin = one_header(request.headers(), "origin");
    let origin_ok = if browser_post {
        origin == Some(auth.0.issuer.as_str())
    } else {
        !request.headers().contains_key("origin")
    };
    if !host_ok || !origin_ok {
        return error(StatusCode::FORBIDDEN, "access_denied");
    }
    if request.method() == Method::POST && request.uri().query().is_some() {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    if request.uri().to_string().len() > MAX_BODY {
        return error(StatusCode::URI_TOO_LONG, "invalid_request");
    }
    let mut response = secure(next.run(request).await);
    if response
        .headers()
        .get(header::CONTENT_TYPE)
        .is_some_and(|value| {
            value
                .to_str()
                .is_ok_and(|value| value.starts_with("text/html"))
        })
    {
        // A no-referrer form document makes browser POST Origin opaque (null).
        response
            .headers_mut()
            .insert("referrer-policy", HeaderValue::from_static("same-origin"));
    }
    response
}

pub(crate) async fn require_token(
    State(auth): State<LocalOAuth>,
    mut request: Request,
    next: Next,
) -> Response {
    if !bearer_credential(request.headers()).is_some_and(|token| auth.accepts(token)) {
        let mut response = error(StatusCode::UNAUTHORIZED, "invalid_token");
        let challenge = format!(
            "Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource/mcp\", scope=\"{SCOPE}\"",
            auth.0.issuer
        );
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, challenge.parse().unwrap());
        return response;
    }
    request.headers_mut().remove(header::AUTHORIZATION);
    next.run(request).await
}

async fn as_metadata(State(auth): State<LocalOAuth>) -> Response {
    let issuer = &auth.0.issuer;
    Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/oauth/authorize"),
        "token_endpoint": format!("{issuer}/oauth/token"),
        "registration_endpoint": format!("{issuer}/oauth/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": [SCOPE],
        "authorization_response_iss_parameter_supported": true,
    }))
    .into_response()
}

async fn resource_metadata(State(auth): State<LocalOAuth>) -> Response {
    Json(json!({
        "resource": auth.0.resource,
        "authorization_servers": [auth.0.issuer],
        "scopes_supported": [SCOPE],
        "bearer_methods_supported": ["header"],
    }))
    .into_response()
}

async fn body(auth: &LocalOAuth, request: Request, content_type: &str) -> Result<Vec<u8>, Failure> {
    if !one_header(request.headers(), "content-type").is_some_and(|v| {
        v.split(';')
            .next()
            .is_some_and(|v| v.trim() == content_type)
    }) {
        return Err(Failure(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "invalid_request",
        ));
    }
    // Bound concurrent AS buffers and slow uploads without timing out MCP work.
    let _permit = auth
        .0
        .body_slots
        .try_acquire()
        .map_err(|_| Failure(StatusCode::TOO_MANY_REQUESTS, "slow_down"))?;
    let bytes = tokio::time::timeout(
        Duration::from_secs(10),
        to_bytes(request.into_body(), MAX_BODY),
    )
    .await
    .map_err(|_| Failure(StatusCode::REQUEST_TIMEOUT, "invalid_request"))?
    .map_err(|_| Failure(StatusCode::PAYLOAD_TOO_LARGE, "invalid_request"))?;
    Ok(bytes.to_vec())
}

fn fields(encoded: &[u8]) -> Result<Fields, Failure> {
    if encoded.len() > MAX_BODY {
        return Err(Failure(StatusCode::BAD_REQUEST, "invalid_request"));
    }
    // Reject malformed escapes/UTF-8 rather than silently changing the client's state.
    let mut decoded = Vec::with_capacity(encoded.len());
    let mut index = 0;
    while index < encoded.len() {
        if encoded[index] == b'%' {
            let byte = encoded
                .get(index + 1..index + 3)
                .filter(|pair| pair.iter().all(u8::is_ascii_hexdigit))
                .and_then(|pair| std::str::from_utf8(pair).ok())
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or(Failure(StatusCode::BAD_REQUEST, "invalid_request"))?;
            decoded.push(byte);
            index += 3;
        } else {
            decoded.push(encoded[index]);
            index += 1;
        }
    }
    std::str::from_utf8(&decoded)
        .map_err(|_| Failure(StatusCode::BAD_REQUEST, "invalid_request"))?;
    let mut result = Fields::new();
    for (key, value) in form_urlencoded::parse(encoded) {
        let recognized = matches!(
            key.as_ref(),
            "client_id"
                | "redirect_uri"
                | "response_type"
                | "response_mode"
                | "scope"
                | "resource"
                | "state"
                | "code_challenge"
                | "code_challenge_method"
                | "grant_type"
                | "code"
                | "code_verifier"
                | "csrf"
                | "decision"
                | "owner_secret"
                | "client_secret"
                | "client_assertion"
                | "client_assertion_type"
                | "access_token"
                | "refresh_token"
                | "password"
                | "token"
                | "request"
                | "request_uri"
        );
        if key.len() > 64 || value.len() > 2048 || result.len() >= 32 {
            return Err(Failure(StatusCode::BAD_REQUEST, "invalid_request"));
        }
        if result
            .insert(key.into_owned(), value.into_owned())
            .is_some()
            && recognized
        {
            return Err(Failure(StatusCode::BAD_REQUEST, "invalid_request"));
        }
    }
    Ok(result)
}

fn param<'a>(fields: &'a Fields, name: &str) -> &'a str {
    fields.get(name).map_or("", String::as_str)
}

#[derive(Deserialize)]
struct Registration {
    redirect_uris: Vec<String>,
    client_name: Option<String>,
    token_endpoint_auth_method: Option<String>,
    grant_types: Option<Vec<String>>,
    response_types: Option<Vec<String>>,
    scope: Option<String>,
}

fn valid_redirect(value: &str) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    let loopback = url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    value.len() <= 2048
        && url.host_str().is_some()
        && (url.scheme() == "https" || (url.scheme() == "http" && loopback))
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
        && url.as_str() == value
        && !url.query_pairs().any(|(key, _)| {
            matches!(
                key.as_ref(),
                "code" | "state" | "iss" | "error" | "error_description"
            )
        })
}

async fn register(State(auth): State<LocalOAuth>, request: Request) -> Response {
    let now = Instant::now();
    {
        let mut store = auth.0.store.lock().unwrap();
        store.prune(now);
        if !store.registration_rate.allow(now, REGISTRATION_RATE) {
            return error(StatusCode::TOO_MANY_REQUESTS, "slow_down");
        }
    }
    let bytes = match body(&auth, request, "application/json").await {
        Ok(bytes) => bytes,
        Err(error) => return error.into_response(),
    };
    let registration: Registration = match serde_json::from_slice(&bytes) {
        Ok(registration) => registration,
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid_client_metadata"),
    };
    if registration.redirect_uris.is_empty()
        || registration.redirect_uris.len() > 8
        || registration
            .redirect_uris
            .iter()
            .any(|uri| !valid_redirect(uri))
        || registration
            .client_name
            .as_ref()
            .is_some_and(|name| name.len() > 128 || name.chars().any(char::is_control))
        || registration
            .token_endpoint_auth_method
            .as_deref()
            .is_some_and(|method| method != "none")
        || registration.grant_types.as_ref().is_some_and(|grants| {
            !grants.iter().any(|grant| grant == "authorization_code")
                || grants
                    .iter()
                    .any(|grant| grant != "authorization_code" && grant != "refresh_token")
                || grants.iter().collect::<HashSet<_>>().len() != grants.len()
        })
        || registration
            .response_types
            .as_ref()
            .is_some_and(|types| types != &["code"])
        || registration
            .scope
            .as_deref()
            .is_some_and(|scope| scope != SCOPE)
    {
        return error(StatusCode::BAD_REQUEST, "invalid_client_metadata");
    }
    let id = match random() {
        Ok(id) => id,
        Err(error) => return error.into_response(),
    };
    let mut store = auth.0.store.lock().unwrap();
    // Bound registrations by validated callback origin and aggregate work.
    // Descriptive metadata URLs are never fetched.
    let origins: HashSet<_> = registration
        .redirect_uris
        .iter()
        .map(|uri| Url::parse(uri).unwrap().origin().ascii_serialization())
        .collect();
    let new_origins = origins
        .iter()
        .filter(|origin| !store.registration_origins.contains_key(*origin))
        .count();
    if store.registration_origins.len() + new_origins > MAX_REGISTRATION_ORIGINS {
        return error(StatusCode::TOO_MANY_REQUESTS, "slow_down");
    }
    for origin in origins {
        if !store
            .registration_origins
            .entry(origin)
            .or_default()
            .allow(now, 16)
        {
            return error(StatusCode::TOO_MANY_REQUESTS, "slow_down");
        }
    }
    if store.clients.len() >= MAX_CLIENTS
        || store
            .clients
            .values()
            .filter(|client| !client.approved)
            .count()
            >= MAX_UNAPPROVED_CLIENTS
    {
        return error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    }
    let refresh_allowed = registration
        .grant_types
        .as_ref()
        .is_some_and(|grants| grants.iter().any(|grant| grant == "refresh_token"));
    let grants = if refresh_allowed {
        vec!["authorization_code", "refresh_token"]
    } else {
        vec!["authorization_code"]
    };
    let response = (
        StatusCode::CREATED,
        Json(json!({
            "client_id": id,
            "redirect_uris": registration.redirect_uris, "client_name": registration.client_name,
            "token_endpoint_auth_method": "none", "grant_types": grants,
            "response_types": ["code"], "scope": SCOPE,
        })),
    )
        .into_response();
    store.clients.insert(
        id,
        Client {
            redirects: registration.redirect_uris,
            name: registration
                .client_name
                .unwrap_or_else(|| "Unnamed public client".into()),
            expires: now + CLIENT_TTL,
            approved: false,
            refresh_allowed,
            authorization_rate: Rate::default(),
            login_rate: Rate::default(),
            exchange_rate: Rate::default(),
        },
    );
    response
}

fn completion(
    auth: &LocalOAuth,
    target: &str,
    state: Option<&str>,
    key: &str,
    value: &str,
) -> Response {
    let mut url = Url::parse(target).expect("validated registered redirect");
    {
        let mut pairs = url.query_pairs_mut();
        pairs
            .append_pair(key, value)
            .append_pair("iss", &auth.0.issuer);
        if let Some(state) = state {
            pairs.append_pair("state", state);
        }
    }
    // An ordinary user-clicked link is not a form-action redirect. Keep the
    // callback/code private and do not navigate externally without another click.
    Html(format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Complete qmcp authorization</title></head><body><h1>Complete authorization</h1><p>Continue to the callback you reviewed, including after denial.</p><a href=\"{}\" rel=\"noreferrer noopener\">Continue to ChatGPT</a></body></html>",
        escape(url.as_str())
    )).into_response()
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn cookie(value: &str, max_age: u64) -> HeaderValue {
    format!(
        "{COOKIE}={value}; Max-Age={max_age}; Path=/oauth/authorize; Secure; HttpOnly; SameSite=Lax"
    )
    .parse()
    .unwrap()
}

async fn authorize(State(auth): State<LocalOAuth>, request: Request) -> Response {
    let fields = match fields(request.uri().query().unwrap_or("").as_bytes()) {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    // Never accept a credential in a URL, even as an unknown extension parameter.
    if fields.keys().any(|k| {
        matches!(
            k.as_str(),
            "owner_secret"
                | "client_secret"
                | "client_assertion"
                | "client_assertion_type"
                | "access_token"
                | "refresh_token"
                | "code"
                | "code_verifier"
                | "password"
                | "token"
        )
    }) || fields.get("state").is_some_and(|s| s.len() > 1024)
        || fields
            .get("response_mode")
            .is_some_and(|mode| mode != "query")
        || fields.contains_key("request")
        || fields.contains_key("request_uri")
    {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let now = Instant::now();
    let mut store = auth.0.store.lock().unwrap();
    store.prune(now);
    if !store.authorization_rate.allow(now, AGGREGATE_RATE) {
        return error(StatusCode::TOO_MANY_REQUESTS, "slow_down");
    }
    let Some(client) = store.clients.get_mut(param(&fields, "client_id")) else {
        return error(StatusCode::BAD_REQUEST, "invalid_client");
    };
    if !client.authorization_rate.allow(now, 30) {
        return error(StatusCode::TOO_MANY_REQUESTS, "slow_down");
    }
    let name = escape(&client.name);
    let refresh_allowed = client.refresh_allowed;
    let target = param(&fields, "redirect_uri");
    if !client.redirects.iter().any(|r| r == target) {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let state = fields.get("state").cloned();
    let fail = |name| completion(&auth, target, state.as_deref(), "error", name);
    if param(&fields, "response_type") != "code" {
        return fail("unsupported_response_type");
    }
    if param(&fields, "resource") != auth.0.resource {
        return fail("invalid_target");
    }
    if param(&fields, "scope") != SCOPE {
        return fail("invalid_scope");
    }
    let challenge = param(&fields, "code_challenge");
    let challenge_bytes = URL_SAFE_NO_PAD.decode(challenge).ok();
    if param(&fields, "code_challenge_method") != "S256"
        || challenge.len() != 43
        || !challenge_bytes
            .as_ref()
            .is_some_and(|b| b.len() == 32 && URL_SAFE_NO_PAD.encode(b) == challenge)
    {
        return fail("invalid_request");
    }
    if store.transactions.len() >= MAX_TRANSACTIONS
        || store
            .transactions
            .values()
            .filter(|t| t.grant.client == param(&fields, "client_id"))
            .count()
            >= MAX_CLIENT_TRANSACTIONS
    {
        return fail("temporarily_unavailable");
    }
    let transaction = match random() {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let csrf = match random() {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let access_minutes = TOKEN_TTL.as_secs() / 60;
    let duration = if refresh_allowed {
        format!(
            "Each access token lasts up to {access_minutes} minutes. Access can be renewed without a new login for up to {} hours from the initial code exchange; renewal does not extend this deadline.",
            FAMILY_TTL.as_secs() / 3600
        )
    } else {
        format!("Access lasts up to {access_minutes} minutes.")
    };
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>qmcp owner login and authorization</title></head><body><h1>Owner login + authorize</h1><p>Unverified public client: <strong>{name}</strong></p><p>Redirect: {}</p><p>Approve grants all QueryMT tools on {} (scope {SCOPE}). {duration} Only approve a client and callback you trust.</p><form method=\"post\" action=\"/oauth/authorize\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\"><label>Generated owner secret <input type=\"password\" name=\"owner_secret\" autocomplete=\"off\" maxlength=\"128\"></label><button type=\"submit\" name=\"decision\" value=\"approve\">Log in and Approve</button><button type=\"submit\" name=\"decision\" value=\"deny\">Deny</button></form></body></html>",
        escape(target),
        escape(&auth.0.resource)
    );
    let grant = Grant {
        client: param(&fields, "client_id").into(),
        redirect: target.into(),
        resource: auth.0.resource.clone(),
        scope: SCOPE.into(),
        challenge: challenge_bytes.unwrap().try_into().unwrap(),
    };
    store.transactions.insert(
        digest(&transaction),
        Transaction {
            grant,
            state,
            csrf: digest(&csrf),
            expires: now + TRANSACTION_TTL,
        },
    );
    let mut response = Html(html).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        cookie(&transaction, TRANSACTION_TTL.as_secs()),
    );
    response
}

fn browser_cookie(headers: &HeaderMap) -> Option<&str> {
    let mut found = None;
    for header in headers.get_all(header::COOKIE) {
        for item in header.to_str().ok()?.split(';') {
            let Some((key, value)) = item.trim().split_once('=') else {
                continue;
            };
            if key == COOKIE {
                if found.is_some() || value.len() != 43 {
                    return None;
                }
                found = Some(value);
            }
        }
    }
    found
}

async fn consent(State(auth): State<LocalOAuth>, request: Request) -> Response {
    let transaction = browser_cookie(request.headers()).map(digest);
    let bytes = match body(&auth, request, "application/x-www-form-urlencoded").await {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    let fields = match fields(&bytes) {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    let now = Instant::now();
    let mut store = auth.0.store.lock().unwrap();
    store.prune(now);
    // Exact Origin is checked by guard before any body or owner-attempt work.
    // Invalid cookies/CSRF neither consume an attempt nor destroy a valid flow.
    let Some(id) = transaction else {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let Some(transaction) = store.transactions.get(&id) else {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    if !bool::from(transaction.csrf.ct_eq(&digest(param(&fields, "csrf")))) {
        return error(StatusCode::FORBIDDEN, "access_denied");
    }
    let client_id = transaction.grant.client.clone();
    let Some(client) = store.clients.get_mut(&client_id) else {
        return error(StatusCode::BAD_REQUEST, "invalid_client");
    };
    if !client.login_rate.allow(now, 8) {
        return error(StatusCode::TOO_MANY_REQUESTS, "slow_down");
    }
    // One owner attempt per CSRF-validated transaction, bounded per client.
    let transaction = store.transactions.remove(&id).unwrap();
    let grant = transaction.grant;
    let approved = param(&fields, "decision") == "approve"
        && !fields
            .keys()
            .any(|k| !matches!(k.as_str(), "csrf" | "decision" | "owner_secret"))
        && bool::from(auth.0.owner.ct_eq(&digest(param(&fields, "owner_secret"))));
    if approved {
        store.clients.get_mut(&grant.client).unwrap().approved = true;
    }
    let result = if !approved {
        completion(
            &auth,
            &grant.redirect,
            transaction.state.as_deref(),
            "error",
            "access_denied",
        )
    } else if store.codes.len() >= MAX_CODES
        || store
            .codes
            .values()
            .filter(|code| code.grant.client == grant.client)
            .count()
            >= MAX_CLIENT_CODES
    {
        completion(
            &auth,
            &grant.redirect,
            transaction.state.as_deref(),
            "error",
            "temporarily_unavailable",
        )
    } else {
        let code = match random() {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
        let result = completion(
            &auth,
            &grant.redirect,
            transaction.state.as_deref(),
            "code",
            &code,
        );
        store.codes.insert(
            digest(&code),
            Code {
                grant,
                expires: now + CODE_TTL,
            },
        );
        result
    };
    let mut result = result;
    result
        .headers_mut()
        .insert(header::SET_COOKIE, cookie("", 0));
    result
}

async fn exchange(State(auth): State<LocalOAuth>, request: Request) -> Response {
    if request.headers().contains_key(header::AUTHORIZATION) {
        return error(StatusCode::BAD_REQUEST, "invalid_client");
    }
    {
        let now = Instant::now();
        let mut store = auth.0.store.lock().unwrap();
        store.prune(now);
        if !store.exchange_rate.allow(now, AGGREGATE_RATE) {
            return error(StatusCode::TOO_MANY_REQUESTS, "slow_down");
        }
    }
    let bytes = match body(&auth, request, "application/x-www-form-urlencoded").await {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    let fields = match fields(&bytes) {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    let mut store = auth.0.store.lock().unwrap();
    let now = Instant::now();
    store.prune(now);
    match param(&fields, "grant_type") {
        "authorization_code" => exchange_code(&mut store, &fields, now),
        "refresh_token" => exchange_refresh(&mut store, &fields, now),
        _ => error(StatusCode::BAD_REQUEST, "unsupported_grant_type"),
    }
}

fn exchange_code(store: &mut Store, fields: &Fields, now: Instant) -> Response {
    let id = digest(param(fields, "code"));
    // Unknown codes cannot consume a named client's budget.
    if let Some(code) = store.codes.get(&id) {
        let actual_client = code.grant.client.clone();
        if let Some(client) = store.clients.get_mut(&actual_client)
            && !client.exchange_rate.allow(now, 60)
        {
            return error(StatusCode::TOO_MANY_REQUESTS, "slow_down");
        }
    }
    let Some(code) = store.codes.get(&id) else {
        return error(StatusCode::BAD_REQUEST, "invalid_grant");
    };
    let verifier = param(fields, "code_verifier");
    let verifier_ok = (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b));
    if code.expires <= now
        || fields.contains_key("client_secret")
        || fields.contains_key("client_assertion")
        || fields.contains_key("client_assertion_type")
        || param(fields, "client_id") != code.grant.client
        || param(fields, "redirect_uri") != code.grant.redirect
        || param(fields, "resource") != code.grant.resource
        || fields.get("scope").is_some_and(|s| s != &code.grant.scope)
        || !verifier_ok
        || !bool::from(code.grant.challenge.ct_eq(&digest(verifier)))
    {
        // Failed PKCE/bindings consume the code; transient capacity failures do not.
        store.codes.remove(&id);
        return error(StatusCode::BAD_REQUEST, "invalid_grant");
    }
    let refresh_allowed = store
        .clients
        .get(&code.grant.client)
        .is_some_and(|client| client.approved && client.refresh_allowed);
    if !store.access_capacity(&code.grant.client)
        || (refresh_allowed && !store.family_capacity(&code.grant.client))
    {
        return error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    }
    let token = match random() {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let refresh = if refresh_allowed {
        match random() {
            Ok(v) => Some(v),
            Err(e) => return e.into_response(),
        }
    } else {
        None
    };
    // Validation, capacity checks, removal and all issuance share the same lock.
    let grant = store.codes.remove(&id).unwrap().grant;
    let family_id = refresh.as_deref().map(digest);
    if let Some(family) = family_id {
        store.families.insert(
            family,
            Family {
                client: grant.client.clone(),
                resource: grant.resource.clone(),
                scope: grant.scope.clone(),
                expires: now + FAMILY_TTL,
                records: 1,
                revoked: false,
            },
        );
        store.refresh.insert(
            family,
            RefreshRecord {
                family,
                consumed: false,
            },
        );
    }
    store.tokens.insert(
        digest(&token),
        Token {
            family: family_id,
            client: grant.client,
            resource: grant.resource,
            scope: grant.scope,
            expires: now + TOKEN_TTL,
        },
    );
    token_response(token, refresh, TOKEN_TTL)
}

fn exchange_refresh(store: &mut Store, fields: &Fields, now: Instant) -> Response {
    let raw = param(fields, "refresh_token");
    // Only canonical 32-byte opaque credentials, never mixed authentication/grant material.
    if raw.len() != 43
        || !URL_SAFE_NO_PAD
            .decode(raw)
            .is_ok_and(|bytes| bytes.len() == 32 && URL_SAFE_NO_PAD.encode(bytes) == raw)
        || param(fields, "client_id").is_empty()
        || [
            "client_secret",
            "client_assertion",
            "client_assertion_type",
            "code",
            "code_verifier",
            "redirect_uri",
            "owner_secret",
            "password",
            "access_token",
            "token",
        ]
        .iter()
        .any(|key| fields.contains_key(*key))
    {
        return error(StatusCode::BAD_REQUEST, "invalid_grant");
    }
    let id = digest(raw);
    let Some(record) = store.refresh.get(&id) else {
        return error(StatusCode::BAD_REQUEST, "invalid_grant");
    };
    let family_id = record.family;
    let family = &store.families[&family_id];
    if family.revoked
        || family.expires <= now
        || param(fields, "client_id") != family.client
        || !store
            .clients
            .get(&family.client)
            .is_some_and(|c| c.approved && c.refresh_allowed)
    {
        return error(StatusCode::BAD_REQUEST, "invalid_grant");
    }
    // Validate bindings before replay handling: malformed/wrong-target attempts do not revoke.
    // RFC 8707 permits omission to reuse the original (single) bound resource.
    if fields
        .get("resource")
        .is_some_and(|resource| resource != &family.resource)
    {
        return error(StatusCode::BAD_REQUEST, "invalid_target");
    }
    if fields
        .get("scope")
        .is_some_and(|scope| scope != &family.scope)
    {
        return error(StatusCode::BAD_REQUEST, "invalid_scope");
    }
    if record.consumed {
        store.revoke_family(family_id);
        return error(StatusCode::BAD_REQUEST, "invalid_grant");
    }
    let client_id = family.client.clone();
    let resource = family.resource.clone();
    let scope = family.scope.clone();
    let expires = family.expires;
    let records = family.records;
    if !store
        .clients
        .get_mut(&client_id)
        .unwrap()
        .exchange_rate
        .allow(now, 60)
    {
        return error(StatusCode::TOO_MANY_REQUESTS, "slow_down");
    }
    if !store.access_capacity(&client_id)
        || store.refresh.len() >= MAX_REFRESH_RECORDS
        || records >= MAX_FAMILY_RECORDS
    {
        return error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    }
    let token = match random() {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let refresh = match random() {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let ttl = TOKEN_TTL.min(expires.duration_since(now));
    store.refresh.get_mut(&id).unwrap().consumed = true;
    store.families.get_mut(&family_id).unwrap().records += 1;
    store.refresh.insert(
        digest(&refresh),
        RefreshRecord {
            family: family_id,
            consumed: false,
        },
    );
    store.tokens.insert(
        digest(&token),
        Token {
            family: Some(family_id),
            client: client_id,
            resource,
            scope,
            expires: now + ttl,
        },
    );
    token_response(token, Some(refresh), ttl)
}

fn token_response(access: String, refresh: Option<String>, ttl: Duration) -> Response {
    let mut response = json!({ "access_token": access, "token_type": "Bearer",
        "expires_in": ttl.as_secs(), "scope": SCOPE });
    if let Some(refresh) = refresh {
        response["refresh_token"] = refresh.into();
    }
    Json(response).into_response()
}

#[cfg(test)]
mod tests;
