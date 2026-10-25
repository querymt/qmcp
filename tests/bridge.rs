use std::{
    collections::VecDeque,
    path::PathBuf,
    process::Stdio,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use futures_util::{SinkExt, StreamExt};
use qmacp::protocol::{JsonRpcMessage, schema::v1 as acp};
use qmcp::{BridgeConfig, QmcpServer, policy::PermissionPolicy, transport};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines},
    net::{TcpListener, TcpStream},
    process::{Child, ChildStdin, ChildStdout},
    sync::oneshot,
    task::{JoinHandle, JoinSet},
};
use tokio_tungstenite::{WebSocketStream, accept_async, tungstenite::Message};

struct MockAcp {
    url: String,
    requests: Arc<Mutex<Vec<Value>>>,
    active: Arc<AtomicUsize>,
    task: JoinHandle<()>,
    workspace: Arc<Mutex<MockWorkspace>>,
}

#[derive(Default)]
struct MockWorkspace {
    created: Vec<Value>,
    listing: Option<Vec<Value>>,
    reject_creation: bool,
    replay_error: bool,
    forced_id: Option<String>,
    creation_gates: VecDeque<CreationGate>,
}

struct CreationGate {
    observed: oneshot::Sender<()>,
    release: oneshot::Receiver<()>,
}

#[derive(Clone, Copy, Default)]
enum SubmissionBehavior {
    #[default]
    Idle,
    PollError,
    Busy,
    NoReply,
    HistoryUnavailable,
    MissingReceiptStatus,
    WrongReceiptId,
}

impl MockAcp {
    async fn start() -> Self {
        Self::with_submission(SubmissionBehavior::Idle).await
    }

    async fn with_submission(behavior: SubmissionBehavior) -> Self {
        Self::with_handshake_delay(behavior, Duration::ZERO).await
    }

    async fn with_handshake_delay(behavior: SubmissionBehavior, delay: Duration) -> Self {
        Self::with_options(behavior, delay, None, None).await
    }

    async fn with_listing_pages(pages: usize) -> Self {
        Self::with_options(SubmissionBehavior::Idle, Duration::ZERO, Some(pages), None).await
    }

    async fn with_extension_payload(payload: Value) -> Self {
        Self::with_options(
            SubmissionBehavior::Idle,
            Duration::ZERO,
            None,
            Some(payload),
        )
        .await
    }

    async fn with_options(
        behavior: SubmissionBehavior,
        delay: Duration,
        listing_pages: Option<usize>,
        extension_payload: Option<Value>,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/acp/ws", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let active = Arc::new(AtomicUsize::new(0));
        let recorded = requests.clone();
        let workspace = Arc::new(Mutex::new(MockWorkspace::default()));
        let workspaces = workspace.clone();
        let connections = active.clone();
        let task = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.unwrap();
                        let recorded = recorded.clone();
                        let active = connections.clone();
                        let payload = extension_payload.clone();
                        let workspace = workspaces.clone();
                        tasks.spawn(async move {
                            active.fetch_add(1, Ordering::SeqCst);
                            let _guard = ConnectionGuard(active);
                            tokio::time::sleep(delay).await;
                            let socket = accept_async(stream).await.unwrap();
                            serve_acp(socket, recorded, behavior, listing_pages, payload, workspace).await;
                        });
                    }
                    Some(result) = tasks.join_next(), if !tasks.is_empty() => { result.unwrap(); }
                }
            }
        });
        Self {
            url,
            requests,
            active,
            task,
            workspace,
        }
    }

    fn recorded(&self) -> Vec<Value> {
        self.requests.lock().unwrap().clone()
    }

    async fn wait_disconnected(&self) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while self.active.load(Ordering::SeqCst) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("ACP connections must be released after a tool call");
    }
}

impl Drop for MockAcp {
    fn drop(&mut self) {
        self.task.abort();
    }
}
struct ConnectionGuard(Arc<AtomicUsize>);
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

async fn send(socket: &mut WebSocketStream<TcpStream>, value: Value) {
    socket
        .send(Message::Text(value.to_string().into()))
        .await
        .unwrap();
}

async fn serve_acp(
    mut socket: WebSocketStream<TcpStream>,
    requests: Arc<Mutex<Vec<Value>>>,
    behavior: SubmissionBehavior,
    listing_pages: Option<usize>,
    extension_payload: Option<Value>,
    workspace: Arc<Mutex<MockWorkspace>>,
) {
    let mut submitted = false;
    while let Some(Ok(message)) = socket.next().await {
        let Message::Text(text) = message else {
            continue;
        };
        let request: Value = serde_json::from_str(&text).unwrap();
        requests.lock().unwrap().push(request.clone());
        let Some(method) = request["method"].as_str() else {
            continue;
        };
        let id = request["id"].clone();
        if id.is_null() {
            continue;
        }
        let params = &request["params"];
        if method == "session/load" && workspace.lock().unwrap().replay_error {
            send(&mut socket, json!({"jsonrpc":"2.0","id":id,"error":{"code":-32000,"message":"Loaded session has no runtime ref for ACP replay"}})).await;
            continue;
        }
        if matches!(
            method,
            "_querymt/profiles"
                | "_querymt/models"
                | "_querymt/refreshModels"
                | "_querymt/session/getLifecycle"
                | "_querymt/session/setLifecycle"
                | "_querymt/session/setPinned"
                | "_querymt/session/runtimeState"
        ) && let Some(payload) = &extension_payload
        {
            send(
                &mut socket,
                json!({"jsonrpc": "2.0", "id": id, "result": {"data": payload}}),
            )
            .await;
            continue;
        }
        if method == "session/new" && workspace.lock().unwrap().reject_creation {
            send(&mut socket, json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32000, "message": "creation rejected"}})).await;
            continue;
        }
        if method == "session/list" {
            let listing = workspace.lock().unwrap().listing.clone();
            if let Some(pages) = listing {
                assert!(
                    params.get("cwd").is_none(),
                    "workspace discovery must be unfiltered"
                );
                assert!(
                    params.get("_meta").is_none(),
                    "workspace discovery must include all lifecycles"
                );
                let page = params["cursor"]
                    .as_str()
                    .and_then(|cursor| cursor.strip_prefix("page-"))
                    .and_then(|n| n.parse::<usize>().ok())
                    .unwrap_or(1)
                    - 1;
                let reply = &pages[page.min(pages.len() - 1)];
                let mut response = json!({"jsonrpc": "2.0", "id": id});
                response[if reply.get("error").is_some() {
                    "error"
                } else {
                    "result"
                }] = reply.get("error").unwrap_or(reply).clone();
                send(&mut socket, response).await;
                continue;
            }
        }
        let result = match method {
            "initialize" => {
                json!({"protocolVersion": 1, "agentInfo": {"name": "fixture", "version": "1"}, "agentCapabilities": {"loadSession": true, "sessionCapabilities": {"list": {}, "resume": {}, "close": {}}}})
            }
            "_querymt/capabilities" => {
                json!({"features": {"session_lifecycle": true, "session_pins": true}, "methods": ["querymt/session/getLifecycle", "querymt/session/setLifecycle", "querymt/session/setPinned"]})
            }
            "_querymt/profiles" => json!({"profiles": [{"id": "fixture-profile"}]}),
            "session/new" => {
                let mut workspace = workspace.lock().unwrap();
                let number = workspace.created.len() + 1;
                let session_id = workspace.forced_id.clone().unwrap_or_else(|| {
                    if number == 1 {
                        "fixture-session".to_owned()
                    } else {
                        format!("fixture-session-{number}")
                    }
                });
                workspace.created.push(json!({"sessionId": session_id, "cwd": params["cwd"], "_meta": params["_meta"]}));
                json!({"sessionId": session_id})
            }
            "session/close" => json!({}),
            "session/resume" | "session/load" => {
                if matches!(behavior, SubmissionBehavior::HistoryUnavailable) {
                    send(&mut socket, json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32000, "message": "history replay unavailable"}})).await;
                    continue;
                }
                json!({"configOptions": [{"id": "model", "name": "Model", "type": "select", "currentValue": "fixture-model", "options": [{"value": "fixture-model", "name": "Fixture"}]}]})
            }
            "session/list" => {
                if let Some(total) = listing_pages {
                    let page: usize = params["cursor"]
                        .as_str()
                        .map(|cursor| cursor.strip_prefix("page-").unwrap().parse().unwrap())
                        .unwrap_or(1);
                    assert!(
                        page <= total,
                        "the fixture must not be scanned beyond its final page"
                    );
                    let mut result = json!({"sessions": [
                        {"sessionId": format!("listed-{page}"), "cwd": "/workspace", "title": format!("Listed {page}")},
                        {"sessionId": format!("extra-{page}"), "cwd": "/workspace", "title": format!("Listed extra {page}")},
                    ]});
                    if page < total {
                        result["nextCursor"] = json!(format!("page-{}", page + 1));
                    }
                    result
                } else if params["cursor"] == "page-2" {
                    json!({"sessions": [{"sessionId": "second-session", "cwd": "/workspace", "title": "Second"}]})
                } else {
                    let created = workspace.lock().unwrap().created.clone();
                    json!({"sessions": if created.is_empty() { vec![json!({"sessionId": "fixture-session", "cwd": "/workspace", "title": "Fixture"})] } else { created }, "nextCursor": "page-2"})
                }
            }
            "_querymt/session/runtimeState" => {
                if submitted && matches!(behavior, SubmissionBehavior::PollError) {
                    send(&mut socket, json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32000, "message": "poll failed after submission"}})).await;
                    continue;
                }
                if matches!(behavior, SubmissionBehavior::Idle) {
                    json!({"phase": "idle", "steerable": false})
                } else {
                    json!({"phase": "tools", "steerable": true, "active_run_id": "fixture-run"})
                }
            }
            "_querymt/session/getLifecycle" => json!({"resolved": false, "archived": false}),
            "_querymt/session/setLifecycle" | "_querymt/session/setPinned" => params.clone(),
            "_querymt/session/queue" | "_querymt/session/steer" => {
                submitted = true;
                if matches!(behavior, SubmissionBehavior::NoReply) {
                    continue;
                }
                let input_id = &params["client_input_id"];
                match behavior {
                    SubmissionBehavior::MissingReceiptStatus => {
                        json!({"data": {"input_id": input_id}})
                    }
                    SubmissionBehavior::WrongReceiptId => {
                        json!({"status": "queued", "data": {"input_id": "wrong-input"}})
                    }
                    _ => json!({
                        "status": if method.ends_with("/steer") { "steered" } else { "queued" },
                        "data": {"input_id": input_id, "run_id": "fixture-run", "position": 1},
                    }),
                }
            }
            "_querymt/session/discardQueuedInput" => json!({"accepted": true}),
            "session/set_mode" if params["modeId"] == "flood-config" => {
                for _ in 0..300 {
                    send(&mut socket, json!({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": "fixture-session", "update": {"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": "event"}}}})).await;
                }
                send(&mut socket, json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32000, "message": "configuration rejected after event flood"}})).await;
                continue;
            }
            "session/prompt" => {
                let text = params["prompt"][0]["text"].as_str().unwrap();
                if text == "wait" {
                    continue;
                }
                let permission = acp::RequestPermissionRequest::new(
                    params["sessionId"].as_str().unwrap().to_owned(),
                    acp::ToolCallUpdate::new("tool-1", acp::ToolCallUpdateFields::new()),
                    vec![acp::PermissionOption::new(
                        "allow",
                        "Allow once",
                        acp::PermissionOptionKind::AllowOnce,
                    )],
                )
                .to_untyped_message()
                .unwrap();
                send(&mut socket, json!({"jsonrpc": "2.0", "id": "permission-1", "method": permission.method, "params": permission.params})).await;
                let reply = socket.next().await.unwrap().unwrap().into_text().unwrap();
                let reply: Value = serde_json::from_str(&reply).unwrap();
                assert_eq!(reply["result"]["outcome"]["optionId"], "allow");
                requests.lock().unwrap().push(reply);
                let reply = if text == "oversized" {
                    "x".repeat(1024 * 1024 + 32)
                } else {
                    format!("reply:{text}")
                };
                send(&mut socket, json!({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": params["sessionId"], "update": {"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": reply}}}})).await;
                json!({"stopReason": if text == "cancelled" { "cancelled" } else { "end_turn" }})
            }
            _ => {
                send(&mut socket, json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32000, "message": "fixture RPC failure"}})).await;
                continue;
            }
        };
        if method == "session/new" {
            let gate = workspace.lock().unwrap().creation_gates.pop_front();
            if let Some(gate) = gate {
                gate.observed.send(()).unwrap();
                gate.release.await.unwrap();
            }
        }
        send(
            &mut socket,
            json!({"jsonrpc": "2.0", "id": id, "result": result}),
        )
        .await;
    }
}

#[tokio::test]
async fn inspect_reports_backend_replay_limitation_without_empty_history_or_fallback() {
    for http in [false, true] {
        let backend = MockAcp::start().await;
        backend.workspace.lock().unwrap().replay_error = true;
        let mut mcp = Mcp::start(&backend.url, http).await;
        for full in [false, true] {
            let result = mcp
                .tool(
                    "inspect",
                    json!({"session_id":"fixture-session","full":full}),
                )
                .await;
            assert_eq!(result["isError"], true, "{result}");
            let content = &result["structuredContent"];
            let error = content["error"].as_str().unwrap();
            assert!(error.contains("QueryMT backend cannot replay"), "{result}");
            assert!(error.contains("History is unavailable, not empty"));
            assert!(error.contains("Loaded session has no runtime ref for ACP replay"));
            assert!(content.get("messages").is_none() && content.get("raw").is_none());
        }
        let requests = backend.recorded();
        assert_eq!(
            requests
                .iter()
                .filter(|r| r["method"] == "session/load")
                .count(),
            2
        );
        assert!(requests.iter().all(|r| matches!(
            r["method"].as_str(),
            Some("initialize" | "session/list" | "session/load")
        )));
        // A failed history fallback after successful resume/poll is not a done/empty answer.
        let follow = mcp
            .tool(
                "follow",
                json!({"session_id":"fixture-session","timeout":1,"interval":1}),
            )
            .await;
        assert_eq!(follow["isError"], true, "{follow}");
        assert!(
            follow["structuredContent"]["error"]
                .as_str()
                .unwrap()
                .contains("History is unavailable, not empty")
        );
        assert!(follow["structuredContent"].get("text").is_none());
        assert!(backend.recorded().iter().all(|r| matches!(
            r["method"].as_str(),
            Some(
                "initialize"
                    | "session/list"
                    | "session/load"
                    | "session/resume"
                    | "_querymt/session/runtimeState"
            )
        )));
    }
}

enum Mcp {
    Stdio {
        child: Box<Child>,
        stdin: ChildStdin,
        stdout: Lines<BufReader<ChildStdout>>,
    },
    Http {
        client: reqwest::Client,
        url: String,
        task: JoinHandle<()>,
    },
}

impl Mcp {
    async fn start(backend: &str, http: bool) -> Self {
        Self::start_with_token(backend, http, None).await
    }

    async fn start_with_token(backend: &str, http: bool, token: Option<&str>) -> Self {
        let mut mcp = if http {
            let server = QmcpServer::new(
                BridgeConfig::new(backend, false, PermissionPolicy::AllowOnce).unwrap(),
            )
            .unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let bind = listener.local_addr().unwrap();
            let url = format!("http://{bind}/mcp");
            let router = transport::http_router_with_auth(
                server,
                bind,
                token.map(|value| transport::BearerToken::new(value).unwrap()),
                &[],
            )
            .unwrap();
            let task = tokio::spawn(async move {
                axum::serve(listener, router).await.unwrap();
            });
            let mut headers = reqwest::header::HeaderMap::new();
            if let Some(token) = token {
                let mut value =
                    reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")).unwrap();
                value.set_sensitive(true);
                headers.insert(reqwest::header::AUTHORIZATION, value);
            }
            Self::Http {
                client: reqwest::Client::builder()
                    .no_proxy()
                    .default_headers(headers)
                    .build()
                    .unwrap(),
                url,
                task,
            }
        } else {
            let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_qmcp"))
                .args(["--url", backend])
                .env_remove("QMCP_BEARER_TOKEN")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let stdin = child.stdin.take().unwrap();
            let stdout = BufReader::new(child.stdout.take().unwrap()).lines();
            Self::Stdio {
                child: Box::new(child),
                stdin,
                stdout,
            }
        };
        let initialized = mcp.rpc("initialize", json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "fixture-client", "version": "1"}})).await;
        assert_eq!(initialized["serverInfo"]["name"], "qmcp");
        mcp.message(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await;
        mcp
    }

    async fn message(&mut self, message: Value) -> Option<Value> {
        let expect_response = message.get("id").is_some();
        match self {
            Self::Stdio { stdin, stdout, .. } => {
                stdin
                    .write_all(format!("{message}\n").as_bytes())
                    .await
                    .unwrap();
                stdin.flush().await.unwrap();
                if !expect_response {
                    return None;
                }
                let line = tokio::time::timeout(Duration::from_secs(5), stdout.next_line())
                    .await
                    .unwrap()
                    .unwrap()
                    .expect("MCP stdout ended");
                Some(serde_json::from_str(&line).expect("stdout must contain only MCP JSON"))
            }
            Self::Http { client, url, .. } => {
                let response = client
                    .post(url.as_str())
                    .header("accept", "application/json, text/event-stream")
                    .header("mcp-protocol-version", "2025-11-25")
                    .json(&message)
                    .send()
                    .await
                    .unwrap();
                if !expect_response {
                    assert_eq!(response.status(), 202);
                    return None;
                }
                assert_eq!(response.status(), 200);
                assert_eq!(response.headers()["content-type"], "application/json");
                assert!(!response.headers().contains_key("mcp-session-id"));
                Some(response.json().await.unwrap())
            }
        }
    }

    async fn rpc(&mut self, method: &str, params: Value) -> Value {
        let response = self
            .message(json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
            .await
            .unwrap();
        assert!(response.get("error").is_none(), "{response}");
        response["result"].clone()
    }

    async fn tool(&mut self, name: &str, arguments: Value) -> Value {
        self.rpc("tools/call", json!({"name": name, "arguments": arguments}))
            .await
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        match self {
            Self::Stdio { child, .. } => {
                let _ = child.start_kill();
            }
            Self::Http { task, .. } => task.abort(),
        }
    }
}

#[tokio::test]
async fn workspace_is_sticky_across_calls_and_switches_without_touching_old_sessions() {
    for http in [false, true] {
        let backend = MockAcp::start().await;
        let mut mcp = Mcp::start(&backend.url, http).await;
        assert_eq!(mcp.tool("workspace", json!({})).await["isError"], true);
        assert!(backend.recorded().is_empty());
        let first = mcp
            .tool(
                "workspace",
                json!({"cwd":"/remote/project/./sub/..", "profile":"fixture-profile"}),
            )
            .await;
        assert_eq!(first["isError"], false, "{first}");
        assert_eq!(first["structuredContent"]["cwd"], "/remote/project");
        assert_eq!(first["structuredContent"]["created"], true);
        assert!(
            !backend
                .recorded()
                .iter()
                .any(|r| r["method"] == "session/prompt")
        );
        let first = first["structuredContent"]["sessionId"].as_str().unwrap();
        let same = mcp
            .tool("workspace", json!({"session_id":first,"cwd":"sub/.."}))
            .await;
        assert_eq!(same["structuredContent"]["sessionId"], first);
        assert_eq!(same["structuredContent"]["created"], false);
        assert_eq!(
            mcp.tool("workspace", json!({"session_id":first,"profile":"other"}))
                .await["isError"],
            true
        );
        let prompted = mcp
            .tool("prompt", json!({"session_id":first,"text":"continue"}))
            .await;
        assert_eq!(prompted["structuredContent"]["cwd"], "/remote/project");
        for name in ["status", "inspect", "follow"] {
            let result = mcp.tool(name, json!({"session_id":first})).await;
            assert_eq!(result["isError"], false, "{result}");
            assert_eq!(result["structuredContent"]["cwd"], "/remote/project");
            let before = backend.recorded().len();
            assert_eq!(
                mcp.tool(name, json!({"session_id":first,"cwd":"/wrong"}))
                    .await["isError"],
                true
            );
            assert_eq!(backend.recorded().len(), before);
        }
        let switched = mcp
            .tool("workspace", json!({"session_id":first,"cwd":"../other"}))
            .await;
        assert_eq!(switched["isError"], false, "{switched}");
        assert_eq!(switched["structuredContent"]["previousSessionId"], first);
        assert_eq!(switched["structuredContent"]["cwd"], "/remote/other");
        assert_eq!(switched["structuredContent"]["profileSource"], "inherited");
        let second = switched["structuredContent"]["sessionId"].as_str().unwrap();
        assert_ne!(first, second);
        let old = mcp.tool("status", json!({"session_id":first})).await;
        assert_eq!(old["structuredContent"]["cwd"], "/remote/project");
        let requests = backend.recorded();
        let creations: Vec<_> = requests
            .iter()
            .filter(|r| r["method"] == "session/new")
            .collect();
        assert_eq!(creations.len(), 2);
        assert!(
            creations
                .iter()
                .all(|r| r["params"]["_meta"]["querymt"]["profile_id"] == "fixture-profile")
        );
        assert!(!requests.iter().any(|r| r["method"] == "session/list"));
        assert_no_implicit_cancel(&backend);
    }
}

#[tokio::test]
async fn workspace_metadata_recovery_is_unfiltered_paginated_and_never_trusts_caller_cwd() {
    let backend = MockAcp::start().await;
    backend.workspace.lock().unwrap().listing = Some(vec![
        json!({"sessions": [{"sessionId": "unrelated", "cwd": "/unrelated"}], "nextCursor": "page-2"}),
        json!({"sessions": [{"sessionId": "old", "cwd": "/remote/original/./project", "_meta": {"querymt": {"profile_id": "listed-profile"}}}]}),
    ]);
    // Separate qmcp instances simulate losing all process-local bindings.
    for http in [false, true] {
        let mut mcp = Mcp::start(&backend.url, http).await;
        let rejected = mcp
            .tool(
                "status",
                json!({"session_id": "old", "cwd": "/requested/not-authoritative"}),
            )
            .await;
        assert_eq!(rejected["isError"], true, "{rejected}");
        let selected = mcp.tool("workspace", json!({"session_id": "old"})).await;
        assert_eq!(selected["isError"], false, "{selected}");
        assert_eq!(
            selected["structuredContent"]["cwd"],
            "/remote/original/project"
        );
        assert_eq!(selected["structuredContent"]["profile"], "listed-profile");
        let switched = mcp
            .tool(
                "prompt",
                json!({"session_id": "old", "cwd": "../next", "text": "new workspace"}),
            )
            .await;
        assert_eq!(switched["isError"], false, "{switched}");
        assert_eq!(switched["structuredContent"]["previousSessionId"], "old");
        assert_eq!(
            switched["structuredContent"]["cwd"],
            "/remote/original/next"
        );
        assert_eq!(switched["structuredContent"]["profileSource"], "inherited");
        let old = mcp.tool("status", json!({"session_id": "old"})).await;
        assert_eq!(old["structuredContent"]["cwd"], "/remote/original/project");
    }
    let requests = backend.recorded();
    let listing: Vec<_> = requests
        .iter()
        .filter(|r| r["method"] == "session/list")
        .collect();
    assert_eq!(listing.len(), 4);
    for page in listing {
        assert!(page["params"].get("cwd").is_none());
        assert!(page["params"].get("_meta").is_none());
    }
    for request in requests.iter().filter(|r| {
        matches!(
            r["method"].as_str(),
            Some("session/load" | "session/resume")
        )
    }) {
        assert_eq!(request["params"]["sessionId"], "old");
        assert_eq!(request["params"]["cwd"], "/remote/original/project");
    }
    assert_no_implicit_cancel(&backend);
}

#[tokio::test]
async fn workspace_discovery_fails_closed_for_incomplete_or_unavailable_metadata() {
    let cases = [
        (vec![json!({"sessions":[]})], "not found"),
        (
            vec![json!({"sessions":[],"nextCursor":17})],
            "metadata unavailable",
        ),
        (
            vec![json!({"sessions":[],"nextCursor":"page-1"})],
            "repeated a cursor",
        ),
        (
            vec![json!({"sessions":[{"sessionId":"unknown","cwd":"relative"}]})],
            "missing or not absolute",
        ),
        (
            vec![json!({"sessions":[{"sessionId":"unknown"}]})],
            "metadata unavailable",
        ),
        (
            vec![json!({"error":{"code":-32601,"message":"list unsupported"}})],
            "metadata unavailable",
        ),
        (
            (1..=20)
                .map(|page| json!({"sessions":[],"nextCursor":format!("page-{}",page+1)}))
                .collect(),
            "page cap reached",
        ),
    ];
    for (pages, expected) in cases {
        let backend = MockAcp::start().await;
        backend.workspace.lock().unwrap().listing = Some(pages);
        let mut mcp = Mcp::start(&backend.url, true).await;
        let result = mcp
            .tool(
                "workspace",
                json!({"session_id":"unknown","cwd":"/caller/cannot/prove/this"}),
            )
            .await;
        assert_eq!(result["isError"], true, "{result}");
        assert!(
            result["structuredContent"]["error"]
                .as_str()
                .unwrap()
                .contains(expected),
            "{result}"
        );
        assert!(
            backend
                .recorded()
                .iter()
                .all(|r| matches!(r["method"].as_str(), Some("initialize" | "session/list")))
        );
    }
    // Each entry point must recover metadata before doing any session work.
    for name in ["prompt", "status", "inspect", "follow"] {
        let backend = MockAcp::start().await;
        backend.workspace.lock().unwrap().listing =
            Some(vec![json!({"sessions":[{"sessionId":"unknown"}]})]);
        let mut mcp = Mcp::start(&backend.url, true).await;
        let mut args = json!({"session_id":"unknown","cwd":"/caller/path"});
        if name == "prompt" {
            args["text"] = json!("must not send");
        }
        let result = mcp.tool(name, args).await;
        assert_eq!(result["isError"], true, "{result}");
        assert!(
            result["structuredContent"]["error"]
                .as_str()
                .unwrap()
                .contains("metadata unavailable")
        );
        assert!(
            backend
                .recorded()
                .iter()
                .all(|r| matches!(r["method"].as_str(), Some("initialize" | "session/list")))
        );
    }
}

#[tokio::test]
async fn workspace_profile_unknown_is_explicit_and_paths_are_remote_lexical() {
    let backend = MockAcp::start().await;
    let mut mcp = Mcp::start(&backend.url, true).await;
    let selected = mcp
        .tool("workspace", json!({"session_id":"fixture-session"}))
        .await;
    assert_eq!(selected["structuredContent"]["profileKnown"], false);
    assert_eq!(
        mcp.tool(
            "workspace",
            json!({"session_id":"fixture-session","profile":"cannot-assume"})
        )
        .await["isError"],
        true
    );
    backend
        .workspace
        .lock()
        .unwrap()
        .created
        .push(json!({"sessionId":"fixture-session","cwd":"/workspace"}));
    let switched = mcp
        .tool(
            "workspace",
            json!({"session_id":"fixture-session","cwd":"/remote/nonexistent"}),
        )
        .await;
    assert_eq!(switched["isError"], false, "{switched}");
    assert_eq!(
        switched["structuredContent"]["profileSource"],
        "backend-default-unknown"
    );
    assert_eq!(switched["structuredContent"]["profileKnown"], false);
    let explicit = mcp
        .tool(
            "workspace",
            json!({"session_id":"fixture-session-2","cwd":"/other","profile":"explicit-profile"}),
        )
        .await;
    assert_eq!(explicit["structuredContent"]["profile"], "explicit-profile");
    let requests = backend.recorded();
    let creations: Vec<_> = requests
        .iter()
        .filter(|r| r["method"] == "session/new")
        .collect();
    assert!(creations[0]["params"].get("_meta").is_none());
    assert_eq!(
        creations[1]["params"]["_meta"]["querymt"]["profile_id"],
        "explicit-profile"
    );
    assert_no_implicit_cancel(&backend);
}

#[tokio::test]
async fn workspace_batches_and_close_keep_bindings_and_new_commands_register_immediately() {
    for http in [false, true] {
        for name in ["new", "prompt"] {
            let backend = MockAcp::start().await;
            let mut mcp = Mcp::start(&backend.url, http).await;
            let mut args = json!({"cwd": "/remote/partial", "mode": "invalid"});
            if name == "prompt" {
                args["new"] = json!(true);
                args["text"] = json!("not sent");
            }
            let failed = mcp.tool(name, args).await;
            assert_eq!(failed["isError"], true, "{failed}");
            assert_eq!(
                failed["structuredContent"]["recovery"]["sessionCreated"],
                true
            );
            let status = mcp
                .tool("status", json!({"session_id": "fixture-session"}))
                .await;
            assert_eq!(status["isError"], false, "{status}");
            assert_eq!(status["structuredContent"]["cwd"], "/remote/partial");
            let closed = mcp
                .tool("close", json!({"session_id": "fixture-session"}))
                .await;
            assert_eq!(closed["isError"], false, "{closed}");
            let batch = mcp.tool("exec", json!({"calls": [
                {"name": "workspace", "arguments": {"session_id": "fixture-session"}},
                {"name": "status", "arguments": {"session_id": "fixture-session"}},
                {"name": "prompt", "arguments": {"session_id": "fixture-session", "cwd": "../switched", "text": "batch"}},
                {"name": "status", "arguments": {"session_id": "fixture-session-2"}},
                {"name": "inspect", "arguments": {"session_id": "fixture-session"}},
            ]})).await;
            assert_eq!(batch["isError"], false, "{batch}");
            let steps = batch["structuredContent"]["results"].as_array().unwrap();
            assert_eq!(steps[0]["result"]["cwd"], "/remote/partial");
            assert_eq!(steps[1]["result"]["cwd"], "/remote/partial");
            assert_eq!(steps[2]["result"]["previousSessionId"], "fixture-session");
            assert_eq!(steps[3]["result"]["cwd"], "/remote/switched");
            assert_eq!(steps[4]["result"]["cwd"], "/remote/partial");
            assert!(
                !backend
                    .recorded()
                    .iter()
                    .any(|r| r["method"] == "session/list")
            );
        }
    }
}

#[tokio::test]
async fn workspace_rejected_creation_and_failed_switch_do_not_rebind_old_id() {
    let backend = MockAcp::start().await;
    let mut mcp = Mcp::start(&backend.url, true).await;
    backend.workspace.lock().unwrap().reject_creation = true;
    let rejected = mcp
        .tool("workspace", json!({"cwd": "/remote/rejected"}))
        .await;
    assert_eq!(rejected["isError"], true, "{rejected}");
    assert!(rejected["structuredContent"].get("recovery").is_none());
    backend.workspace.lock().unwrap().reject_creation = false;
    let created = mcp.tool("new", json!({"cwd": "/remote/old"})).await;
    assert_eq!(created["isError"], false, "{created}");
    backend.workspace.lock().unwrap().reject_creation = true;
    let rejected = mcp
        .tool(
            "workspace",
            json!({"session_id": "fixture-session", "cwd": "../rejected"}),
        )
        .await;
    assert_eq!(rejected["isError"], true);
    backend.workspace.lock().unwrap().reject_creation = false;
    let failed = mcp.tool("prompt", json!({"session_id": "fixture-session", "cwd": "../new", "text": "not sent", "mode": "invalid"})).await;
    assert_eq!(failed["isError"], true, "{failed}");
    let recovery = &failed["structuredContent"]["recovery"];
    assert_eq!(recovery["previousSessionId"], "fixture-session");
    assert_eq!(recovery["sessionId"], "fixture-session-2");
    assert_eq!(recovery["sessionCreated"], true);
    assert_eq!(recovery["switched"], true);
    for (id, cwd) in [
        ("fixture-session", "/remote/old"),
        ("fixture-session-2", "/remote/new"),
    ] {
        let status = mcp.tool("status", json!({"session_id": id})).await;
        assert_eq!(status["isError"], false, "{status}");
        assert_eq!(status["structuredContent"]["cwd"], cwd);
    }
    assert_no_implicit_cancel(&backend);
}

#[tokio::test]
async fn concurrent_unknown_workspace_switches_never_bind_caller_paths_to_the_old_id() {
    let backend = MockAcp::start().await;
    backend.workspace.lock().unwrap().listing = Some(vec![
        json!({"sessions": [{"sessionId": "old", "cwd": "/authoritative/old"}]}),
    ]);
    let mut mcp = Mcp::start(&backend.url, true).await;
    let Mcp::Http { client, url, .. } = &mcp else {
        unreachable!()
    };
    let request = |cwd| {
        client.post(url).header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2025-11-25")
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "workspace", "arguments": {"session_id": "old", "cwd": cwd}}}))
    };
    let (first, second) =
        tokio::join!(request("/remote/one").send(), request("/remote/two").send());
    let first: Value = first.unwrap().json().await.unwrap();
    let second: Value = second.unwrap().json().await.unwrap();
    let first = &first["result"]["structuredContent"];
    let second = &second["result"]["structuredContent"];
    assert_eq!(first["ok"], true, "{first}");
    assert_eq!(second["ok"], true, "{second}");
    assert_ne!(first["sessionId"], second["sessionId"]);
    assert_eq!(first["previousSessionId"], "old");
    assert_eq!(second["previousSessionId"], "old");
    for (id, cwd) in [
        (first["sessionId"].as_str().unwrap(), "/remote/one"),
        (second["sessionId"].as_str().unwrap(), "/remote/two"),
        ("old", "/authoritative/old"),
    ] {
        let status = mcp.tool("status", json!({"session_id": id})).await;
        assert_eq!(status["isError"], false, "{status}");
        assert_eq!(status["structuredContent"]["cwd"], cwd);
    }
    assert_no_implicit_cancel(&backend);
}

fn gated_creation(backend: &MockAcp) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
    let (observed, ready) = oneshot::channel();
    let (release, wait) = oneshot::channel();
    backend
        .workspace
        .lock()
        .unwrap()
        .creation_gates
        .push_back(CreationGate {
            observed,
            release: wait,
        });
    (ready, release)
}

fn concurrent_tool(mcp: &Mcp, name: &str, arguments: Value) -> JoinHandle<Value> {
    let Mcp::Http { client, url, .. } = mcp else {
        unreachable!()
    };
    let request = client.post(url).header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2025-11-25")
        .json(&json!({"jsonrpc": "2.0", "id": 91, "method": "tools/call", "params": {"name": name, "arguments": arguments}}));
    tokio::spawn(async move {
        let response: Value = request.send().await.unwrap().json().await.unwrap();
        response["result"].clone()
    })
}

fn assert_creation_conflict(result: &Value, acknowledged_id: &str) {
    assert_eq!(result["isError"], true, "{result}");
    let content = &result["structuredContent"];
    let recovery = &content["recovery"];
    assert_eq!(
        recovery["workspaceConflict"]["acknowledgedSessionId"], acknowledged_id,
        "{result}"
    );
    assert_eq!(recovery["workspaceConflict"]["selectionCommitted"], false);
    for key in [
        "sessionId",
        "cwd",
        "created",
        "sessionCreated",
        "switched",
        "previousSessionId",
    ] {
        assert!(
            recovery.get(key).is_none(),
            "invalid selection in recovery: {result}"
        );
        assert!(
            content.get(key).is_none(),
            "invalid usable selection: {result}"
        );
    }
}

#[tokio::test]
async fn workspace_metadata_before_creation_ack_reconciles_or_reports_a_conflict() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for (metadata_cwd, success) in [("/remote/new", true), ("/contradiction", false)] {
            let backend = MockAcp::start().await;
            let mut mcp = Mcp::start(&backend.url, true).await;
            mcp.tool(
                "workspace",
                json!({"cwd":"/remote/old","profile":"inherited"}),
            )
            .await;
            let (ready, release) = gated_creation(&backend);
            let pending = concurrent_tool(
                &mcp,
                "prompt",
                json!({"session_id":"fixture-session","cwd":"../new","text":"switch prompt"}),
            );
            ready.await.unwrap();
            // The backend has created B, but another call discovers B before its ACK.
            backend.workspace.lock().unwrap().listing = Some(vec![
                json!({"sessions":[{"sessionId":"fixture-session-2","cwd":metadata_cwd}]}),
            ]);
            let discovered = mcp
                .tool("workspace", json!({"session_id":"fixture-session-2"}))
                .await;
            assert_eq!(discovered["structuredContent"]["created"], false);
            assert!(
                !backend
                    .recorded()
                    .iter()
                    .any(|r| r["method"] == "session/prompt")
            );
            release.send(()).unwrap();
            let result = pending.await.unwrap();
            if success {
                assert_eq!(result["isError"], false, "{result}");
                assert_eq!(
                    result["structuredContent"]["sessionId"],
                    "fixture-session-2"
                );
                assert_eq!(result["structuredContent"]["profile"], "inherited");
                assert_eq!(
                    result["structuredContent"]["previousSessionId"],
                    "fixture-session"
                );
            } else {
                assert_creation_conflict(&result, "fixture-session-2");
                assert!(
                    !backend
                        .recorded()
                        .iter()
                        .any(|r| r["method"] == "session/prompt")
                );
            }
            let remembered = mcp
                .tool("workspace", json!({"session_id":"fixture-session-2"}))
                .await;
            assert_eq!(remembered["structuredContent"]["cwd"], metadata_cwd);
            let old = mcp
                .tool("workspace", json!({"session_id":"fixture-session"}))
                .await;
            assert_eq!(old["structuredContent"]["cwd"], "/remote/old");
            assert_no_implicit_cancel(&backend);
        }
    })
    .await
    .expect("barrier-controlled ACK test must complete");
}

#[tokio::test]
async fn workspace_prebound_duplicate_ack_never_publishes_an_invalid_selection() {
    for from_metadata in [false, true] {
        for bound_cwd in ["/remote/new", "/remote/different"] {
            let backend = MockAcp::start().await;
            let mut mcp = Mcp::start(&backend.url, true).await;
            let old = mcp.tool("workspace", json!({"cwd": "/remote/old"})).await;
            assert_eq!(old["isError"], false);
            let duplicate_id = if from_metadata {
                backend.workspace.lock().unwrap().listing = Some(vec![
                    json!({"sessions": [{"sessionId": "prebound", "cwd": bound_cwd}]}),
                ]);
                "prebound"
            } else {
                let prebound = mcp.tool("workspace", json!({"cwd": bound_cwd})).await;
                assert_eq!(prebound["isError"], false);
                "fixture-session-2"
            };
            let known = mcp
                .tool("workspace", json!({"session_id": duplicate_id}))
                .await;
            assert_eq!(known["isError"], false);
            backend.workspace.lock().unwrap().forced_id = Some(duplicate_id.into());
            for name in ["workspace", "prompt"] {
                let mut args = json!({"session_id": "fixture-session", "cwd": "/remote/new"});
                if name == "prompt" {
                    args["text"] = json!("must not be sent");
                }
                let failed = mcp.tool(name, args).await;
                assert_creation_conflict(&failed, duplicate_id);
            }
            // Also cover the backend returning A itself for an A -> new switch.
            backend.workspace.lock().unwrap().forced_id = Some("fixture-session".into());
            let failed = mcp.tool("prompt", json!({"session_id": "fixture-session", "cwd": "/remote/new", "text": "must not be sent"})).await;
            assert_creation_conflict(&failed, "fixture-session");
            for (id, cwd) in [
                ("fixture-session", "/remote/old"),
                (duplicate_id, bound_cwd),
            ] {
                let known = mcp.tool("workspace", json!({"session_id": id})).await;
                assert_eq!(known["structuredContent"]["cwd"], cwd);
            }
            assert!(
                !backend
                    .recorded()
                    .iter()
                    .any(|r| r["method"] == "session/prompt")
            );
            assert_no_implicit_cancel(&backend);
        }
    }
}

async fn exercise_bridge(http: bool) {
    let backend = MockAcp::start().await;
    let mut mcp = Mcp::start(&backend.url, http).await;
    let catalog = mcp.rpc("tools/list", json!({})).await;
    assert_eq!(catalog["tools"].as_array().unwrap().len(), 26);
    assert!(
        backend.recorded().is_empty(),
        "discovery must not connect to ACP"
    );

    let caps = mcp.tool("caps", json!({})).await;
    assert_eq!(caps["structuredContent"]["agent"]["name"], "fixture");
    let cwd: PathBuf = std::env::current_dir().unwrap();
    let prompt = mcp
        .tool("prompt", json!({"new": true, "cwd": cwd, "text": "-"}))
        .await;
    assert_eq!(prompt["isError"], false, "{prompt}");
    assert_eq!(prompt["structuredContent"]["sessionId"], "fixture-session");
    assert_eq!(prompt["structuredContent"]["text"], "reply:-");
    assert_eq!(prompt["structuredContent"]["observationState"], "idle");
    assert!(
        prompt["structuredContent"]["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["type"] == "permission")
    );
    let continued = mcp
        .tool(
            "prompt",
            json!({"session_id": "fixture-session", "cwd": cwd, "text": "continue", "until_idle": false}),
        )
        .await;
    assert_eq!(continued["structuredContent"]["text"], "reply:continue");
    assert_eq!(
        continued["structuredContent"]["observationState"],
        "prompt_returned"
    );

    let listed = mcp
        .tool(
            "sessions",
            json!({"all": true, "resolution": "open", "pinned": false}),
        )
        .await;
    assert_eq!(
        listed["structuredContent"]["sessions"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let pages: Vec<_> = backend
        .recorded()
        .into_iter()
        .filter(|r| r["method"] == "session/list")
        .collect();
    assert_eq!(pages.len(), 2);
    for page in pages {
        assert_eq!(
            page["params"]["_meta"]["querymt"]["sessionFilters"]["pinned"],
            false
        );
    }

    let patched = mcp
        .tool(
            "set_lifecycle",
            json!({"session_id": "fixture-session", "resolved": false}),
        )
        .await;
    assert_eq!(patched["isError"], false, "{patched}");
    let queued = mcp
        .tool(
            "queue",
            json!({"session_id": "fixture-session", "text": "next"}),
        )
        .await;
    assert!(
        queued["structuredContent"]["clientInputId"]
            .as_str()
            .is_some()
    );
    assert_eq!(queued["structuredContent"]["deliveryState"], "accepted");
    let cancelled = mcp
        .tool("cancel", json!({"session_id": "fixture-session"}))
        .await;
    assert_eq!(
        cancelled["structuredContent"]["cancellationRequested"],
        true
    );
    backend.wait_disconnected().await;
    assert!(
        backend
            .recorded()
            .iter()
            .any(|r| r["method"] == "session/cancel"),
        "cancel must be flushed before the socket is dropped"
    );
}

#[tokio::test]
async fn stdio_bridges_native_acp_operations() {
    exercise_bridge(false).await;
}

#[tokio::test]
async fn streamable_http_bridges_native_acp_operations() {
    exercise_bridge(true).await;
}

#[tokio::test]
async fn failures_are_tool_errors_and_timeouts_do_not_cancel_remote_work() {
    let backend = MockAcp::start().await;
    let mut mcp = Mcp::start(&backend.url, true).await;
    let invalid = mcp
        .tool(
            "prompt",
            json!({"new": true, "text": "x", "session_id": "s"}),
        )
        .await;
    assert_eq!(invalid["isError"], true);
    assert!(backend.recorded().is_empty());

    let timeout = mcp
        .tool("prompt", json!({"new": true, "text": "wait", "timeout": 1}))
        .await;
    assert_eq!(timeout["isError"], true, "{timeout}");
    assert_eq!(timeout["structuredContent"]["code"], 4);
    assert!(
        timeout["structuredContent"]["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["sessionId"] == "fixture-session")
    );
    backend.wait_disconnected().await;
    assert!(
        !backend
            .recorded()
            .iter()
            .any(|r| r["method"] == "session/cancel" || r["method"] == "session/close")
    );

    let batch = mcp.tool("exec", json!({"calls": [{"name": "runtime", "arguments": {"session_id": "s"}}, {"name": "set_mode", "arguments": {"session_id": "s", "mode": "invalid"}}, {"name": "close", "arguments": {"session_id": "s"}}]})).await;
    assert_eq!(batch["isError"], true, "{batch}");
    assert_eq!(
        batch["structuredContent"]["results"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(
        !backend
            .recorded()
            .iter()
            .any(|r| r["method"] == "session/close")
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let offline = format!("ws://{}/acp/ws", listener.local_addr().unwrap());
    drop(listener);
    let mut offline_mcp = Mcp::start(&offline, true).await;
    let error = offline_mcp
        .tool("runtime", json!({"session_id": "s"}))
        .await;
    assert_eq!(error["isError"], true);
    assert_eq!(error["structuredContent"]["code"], 2);
}

#[tokio::test]
async fn long_prompt_does_not_block_concurrent_status_runtime_steer_or_cancel() {
    let backend = MockAcp::start().await;
    let mut mcp = Mcp::start(&backend.url, true).await;
    let Mcp::Http { client, url, .. } = &mcp else {
        unreachable!()
    };
    let client = client.clone();
    let url = url.clone();
    let waiting = tokio::spawn(async move {
        client.post(url).header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", "2025-11-25")
            .json(&json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "prompt", "arguments": {"new": true, "text": "wait", "timeout": 1}}}))
            .send().await.unwrap().json::<Value>().await.unwrap()
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while !backend
            .recorded()
            .iter()
            .any(|r| r["method"] == "session/prompt")
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let runtime = tokio::time::timeout(
        Duration::from_millis(500),
        mcp.tool("runtime", json!({"session_id": "fixture-session"})),
    )
    .await
    .unwrap();
    assert_eq!(runtime["isError"], false);
    for (name, args) in [
        ("status", json!({"session_id": "fixture-session"})),
        (
            "steer",
            json!({"session_id": "fixture-session", "run_id": "fixture-run", "text": "steer while prompt waits"}),
        ),
        ("cancel", json!({"session_id": "fixture-session"})),
    ] {
        let result = tokio::time::timeout(Duration::from_millis(500), mcp.tool(name, args))
            .await
            .expect("workspace locks must not block control commands");
        assert_eq!(result["isError"], false, "{name}: {result}");
    }
    assert!(
        !backend
            .recorded()
            .iter()
            .any(|r| r["method"] == "session/list")
    );
    let finished = waiting.await.unwrap();
    assert_eq!(finished["result"]["structuredContent"]["code"], 4);
    backend.wait_disconnected().await;
}

#[tokio::test]
async fn created_session_is_recoverable_after_configuration_failure_and_event_eviction() {
    for http in [false, true] {
        let backend = MockAcp::start().await;
        let mut mcp = Mcp::start(&backend.url, http).await;
        let cwd = std::env::current_dir().unwrap();
        let response = mcp
            .tool("new", json!({"cwd": cwd, "mode": "flood-config"}))
            .await;
        assert_eq!(response["isError"], true);
        let result = &response["structuredContent"];
        assert_eq!(result["code"], 3);
        assert_eq!(result["recovery"]["sessionId"], "fixture-session");
        assert_eq!(result["recovery"]["cwd"], json!(cwd));
        assert_eq!(result["recovery"]["sessionCreated"], true);
        assert!(result["droppedEvents"].as_u64().unwrap() > 0);
        assert_eq!(
            backend
                .recorded()
                .iter()
                .filter(|r| r["method"] == "session/new")
                .count(),
            1
        );
        backend.wait_disconnected().await;
        assert_no_implicit_cancel(&backend);
    }
}

fn assert_no_implicit_cancel(backend: &MockAcp) {
    assert!(
        !backend
            .recorded()
            .iter()
            .any(|r| r["method"] == "session/cancel" || r["method"] == "session/close")
    );
}

#[tokio::test]
async fn submission_identity_survives_poll_failures_and_timeouts_without_input_events() {
    for http in [false, true] {
        for behavior in [
            SubmissionBehavior::PollError,
            SubmissionBehavior::Busy,
            SubmissionBehavior::NoReply,
        ] {
            for delivery in ["queue", "steer"] {
                let backend = MockAcp::with_submission(behavior).await;
                let mut mcp = Mcp::start(&backend.url, http).await;
                let response = mcp.tool("prompt", json!({"session_id": "fixture-session", "text": "next", "delivery": delivery, "timeout": 1})).await;
                assert_eq!(response["isError"], true);
                let result = &response["structuredContent"];
                let expected_code = if matches!(behavior, SubmissionBehavior::PollError) {
                    3
                } else {
                    4
                };
                assert_eq!(result["code"], expected_code);
                let recovery = &result["recovery"];
                assert_eq!(recovery["sessionId"], "fixture-session");
                let submission = &recovery["submission"];
                assert_eq!(submission["delivery"], delivery);
                let requests = backend.recorded();
                let submitted: Vec<_> = requests
                    .iter()
                    .filter(|r| r["method"] == format!("_querymt/session/{delivery}"))
                    .collect();
                assert_eq!(submitted.len(), 1, "no duplicate submission");
                assert_eq!(
                    submission["clientInputId"],
                    submitted[0]["params"]["client_input_id"]
                );
                if matches!(behavior, SubmissionBehavior::NoReply) {
                    assert_eq!(submission["state"], "unconfirmed");
                    assert!(submission.get("acknowledgement").is_none());
                } else {
                    assert_eq!(submission["state"], "acknowledged");
                    assert_eq!(
                        submission["acknowledgement"]["input_id"],
                        submission["clientInputId"]
                    );
                }
                assert!(requests.iter().all(|request| {
                    !matches!(
                        request["method"].as_str(),
                        Some("session/load" | "session/resume")
                    )
                }));
                backend.wait_disconnected().await;
                assert_no_implicit_cancel(&backend);
            }
        }
    }
}

#[tokio::test]
async fn nonwaiting_delivery_skips_unavailable_history_and_returns_the_receipt() {
    for delivery in ["queue", "auto"] {
        let backend = MockAcp::with_submission(SubmissionBehavior::HistoryUnavailable).await;
        let mut mcp = Mcp::start(&backend.url, false).await;
        let response = mcp
            .tool(
                "prompt",
                json!({
                    "session_id": "fixture-session", "text": "callback", "delivery": delivery,
                    "until_idle": false,
                }),
            )
            .await;
        assert_eq!(response["isError"], false, "{response}");
        let result = &response["structuredContent"];
        assert_eq!(
            result["delivery"],
            if delivery == "auto" { "steer" } else { "queue" }
        );
        assert_eq!(result["observationState"], "not_waited");
        assert_eq!(result["text"], "");
        assert_eq!(result["submitted"]["deliveryState"], "accepted");
        assert_eq!(
            result["submitted"]["result"]["input_id"],
            result["submitted"]["clientInputId"]
        );
        assert!(result["events"].as_array().unwrap().iter().any(|event| {
            event["type"] == "submitted"
                && event["clientInputId"] == result["submitted"]["clientInputId"]
        }));
        assert!(backend.recorded().iter().all(|request| {
            !matches!(
                request["method"].as_str(),
                Some("session/load" | "session/resume" | "session/prompt")
            )
        }));
    }
}

#[tokio::test]
async fn invalid_receipts_stay_unconfirmed_and_stop_a_batch() {
    for behavior in [
        SubmissionBehavior::MissingReceiptStatus,
        SubmissionBehavior::WrongReceiptId,
    ] {
        let backend = MockAcp::with_submission(behavior).await;
        let mut mcp = Mcp::start(&backend.url, false).await;
        let response = mcp.tool("exec", json!({"calls": [
            {"name": "queue", "arguments": {"session_id": "fixture-session", "text": "callback"}},
            {"name": "close", "arguments": {"session_id": "fixture-session"}},
        ]})).await;
        assert_eq!(response["isError"], true, "{response}");
        let result = &response["structuredContent"];
        assert_eq!(result["failedCall"], "queue");
        assert_eq!(result["recovery"]["submission"]["state"], "unconfirmed");
        assert!(
            result["recovery"]["submission"]
                .get("acknowledgement")
                .is_none()
        );
        assert!(
            !result["events"]
                .as_array()
                .unwrap()
                .iter()
                .any(|event| event["type"] == "submitted")
        );
        let requests = backend.recorded();
        let sent = requests
            .iter()
            .find(|request| request["method"] == "_querymt/session/queue")
            .unwrap();
        assert_eq!(
            result["recovery"]["submission"]["clientInputId"],
            sent["params"]["client_input_id"]
        );
        assert_no_implicit_cancel(&backend);
    }
}

#[tokio::test]
async fn invalid_runtime_and_missing_active_run_never_submit_work() {
    for (tool, runtime) in [
        ("prompt", json!({})),
        ("prompt", json!({"phase": "tools"})),
        ("steer", json!({"phase": "idle", "steerable": false})),
    ] {
        let backend = MockAcp::with_extension_payload(runtime).await;
        let mut mcp = Mcp::start(&backend.url, false).await;
        let response = mcp
            .tool(
                tool,
                json!({"session_id": "fixture-session", "text": "callback"}),
            )
            .await;
        assert_eq!(response["isError"], true, "{response}");
        assert_eq!(response["structuredContent"]["code"], 3);
        let requests = backend.recorded();
        assert!(requests.iter().all(|request| matches!(
            request["method"].as_str(),
            Some("initialize" | "session/list" | "_querymt/session/runtimeState")
        )));
        assert!(
            requests
                .iter()
                .filter(|request| request["method"] == "session/list")
                .all(|request| {
                    request["params"].get("cwd").is_none()
                        && request["params"].get("_meta").is_none()
                })
        );
    }
}

#[tokio::test]
async fn batch_keeps_each_steps_truncation_status_after_a_later_short_answer() {
    for http in [false, true] {
        let backend = MockAcp::start().await;
        let mut mcp = Mcp::start(&backend.url, http).await;
        let response = mcp
            .tool(
                "exec",
                json!({"calls": [
                    {"name": "prompt", "arguments": {"new": true, "text": "oversized"}},
                    {"name": "prompt", "arguments": {"new": true, "text": "short"}},
                ]}),
            )
            .await;
        assert_eq!(response["isError"], false);
        let result = &response["structuredContent"];
        assert_eq!(result["textTruncated"], true);
        let first = &result["results"][0]["result"];
        let second = &result["results"][1]["result"];
        assert_eq!(first["ok"], true);
        assert_eq!(first["textTruncated"], true);
        assert_eq!(first["text"].as_str().unwrap().len(), 1024 * 1024);
        assert_eq!(second["ok"], true);
        assert_eq!(second["textTruncated"], false);
        assert_eq!(second["text"], "reply:short");
    }
}

#[tokio::test]
async fn cancelled_batch_step_is_an_error_and_prevents_later_mutations() {
    for http in [false, true] {
        let backend = MockAcp::start().await;
        let mut mcp = Mcp::start(&backend.url, http).await;
        let response = mcp
            .tool(
                "exec",
                json!({"calls": [
                    {"name": "prompt", "arguments": {"new": true, "text": "cancelled"}},
                    {"name": "close", "arguments": {"session_id": "fixture-session"}},
                ]}),
            )
            .await;
        assert_eq!(response["isError"], true);
        let result = &response["structuredContent"];
        assert_eq!(result["ok"], false);
        assert_eq!(result["stopReason"], "cancelled");
        assert_eq!(result["results"].as_array().unwrap().len(), 1);
        assert_eq!(result["results"][0]["result"]["ok"], false);
        assert_eq!(result["results"][0]["result"]["stopReason"], "cancelled");
        assert_no_implicit_cancel(&backend);
    }
}

#[tokio::test]
async fn batch_failure_keeps_prior_results_and_failed_step_recovery() {
    for http in [false, true] {
        let backend = MockAcp::start().await;
        let mut mcp = Mcp::start(&backend.url, http).await;
        let response = mcp
            .tool(
                "exec",
                json!({"calls": [
                    {"name": "runtime", "arguments": {"session_id": "fixture-session"}},
                    {"name": "new", "arguments": {"mode": "invalid"}},
                    {"name": "close", "arguments": {"session_id": "fixture-session"}},
                ]}),
            )
            .await;
        assert_eq!(response["isError"], true);
        let result = &response["structuredContent"];
        assert_eq!(result["results"].as_array().unwrap().len(), 1);
        assert_eq!(result["failedCall"], "new");
        assert_eq!(result["failedResult"]["ok"], false);
        assert_eq!(
            result["failedResult"]["recovery"]["sessionId"],
            "fixture-session"
        );
        assert_eq!(result["recovery"]["sessionCreated"], true);
        assert_no_implicit_cancel(&backend);
    }
}

#[tokio::test]
async fn operation_deadlines_cover_a_stalled_acp_handshake_on_both_transports() {
    use tokio::io::AsyncReadExt;
    for http in [false, true] {
        for (name, arguments) in [
            (
                "prompt",
                json!({"new": true, "text": "never sent", "timeout": 1}),
            ),
            ("follow", json!({"session_id": "s", "timeout": 1})),
            ("watch", json!({"session_id": "s", "timeout": 1})),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("ws://{}/acp/ws", listener.local_addr().unwrap());
            let peer = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                socket.read_to_end(&mut bytes).await.unwrap();
                assert!(
                    bytes.starts_with(b"GET "),
                    "the ACP handshake must have started"
                );
            });
            let mut mcp = Mcp::start(&url, http).await;
            let started = tokio::time::Instant::now();
            let response = tokio::time::timeout(Duration::from_secs(3), mcp.tool(name, arguments))
                .await
                .expect("a 1s command must not wait for the 10s connect timeout");
            assert_eq!(response["isError"], true);
            assert_eq!(response["structuredContent"]["code"], 4);
            assert!(started.elapsed() < Duration::from_secs(3));
            tokio::time::timeout(Duration::from_secs(1), peer)
                .await
                .expect("the pending ACP socket must be released")
                .unwrap();
        }
    }
}

#[tokio::test]
async fn connection_time_is_not_added_to_the_command_budget() {
    for http in [false, true] {
        let backend =
            MockAcp::with_handshake_delay(SubmissionBehavior::Idle, Duration::from_millis(800))
                .await;
        let mut mcp = Mcp::start(&backend.url, http).await;
        let response = tokio::time::timeout(
            Duration::from_millis(1600),
            mcp.tool("prompt", json!({"new": true, "text": "wait", "timeout": 1})),
        )
        .await
        .expect("the command deadline must use the budget left after the handshake");
        assert_eq!(response["isError"], true);
        assert_eq!(response["structuredContent"]["code"], 4);
        assert_eq!(
            response["structuredContent"]["recovery"]["sessionId"],
            "fixture-session"
        );
        backend.wait_disconnected().await;
        assert_no_implicit_cancel(&backend);
    }
}

#[tokio::test]
async fn arbitrary_extension_payloads_cannot_override_bridge_metadata_or_panic() {
    for http in [false, true] {
        for payload in [
            Value::Null,
            json!(["profile", 1]),
            json!("opaque"),
            json!(42),
            json!(false),
            json!({"ok": false, "error": "provider-detail", "stopReason": "cancelled",
                "textTruncated": true, "events": ["provider-event"], "droppedEvents": 99}),
        ] {
            let backend = MockAcp::with_extension_payload(payload.clone()).await;
            let mut mcp = Mcp::start(&backend.url, http).await;
            for (name, args) in [
                ("profiles", json!({})),
                ("models", json!({})),
                ("models", json!({"refresh": true})),
                ("get_lifecycle", json!({"session_id": "s"})),
                (
                    "set_lifecycle",
                    json!({"session_id": "s", "resolved": false}),
                ),
                ("pin", json!({"session_id": "s"})),
                ("unpin", json!({"session_id": "s"})),
            ] {
                let response = mcp.tool(name, args).await;
                assert_eq!(response["isError"], false, "{name}: {response}");
                let result = &response["structuredContent"];
                assert_eq!(result["ok"], true);
                assert_eq!(
                    result["result"], payload,
                    "{name} must preserve the extension payload"
                );
                assert!(result.get("error").is_none());
                assert!(result.get("stopReason").is_none());
                assert_eq!(result["textTruncated"], false);
                assert_eq!(result["events"], json!([]));
                assert_eq!(result["droppedEvents"], 0);
                assert_eq!(
                    serde_json::from_str::<Value>(response["content"][0]["text"].as_str().unwrap())
                        .unwrap(),
                    *result
                );
            }
        }
        let backend = MockAcp::with_extension_payload(json!({"models": [
            {"id": "keep", "provider": "fixture"}, {"id": "drop", "provider": "other"},
        ]}))
        .await;
        let mut mcp = Mcp::start(&backend.url, http).await;
        for refresh in [false, true] {
            let response = mcp
                .tool(
                    "models",
                    json!({"refresh": refresh, "provider": "fixture", "query": "keep"}),
                )
                .await;
            assert_eq!(
                response["structuredContent"]["result"]["models"],
                json!([{"id": "keep", "provider": "fixture"}])
            );
        }
    }
}

#[tokio::test]
async fn session_listing_discloses_remaining_pages_on_each_return_path() {
    for http in [false, true] {
        for (args, cursor, truncated) in [
            (json!({}), json!("page-2"), true),
            (json!({"limit": 1}), json!("page-2"), true),
            (json!({"cursor": "page-2"}), Value::Null, false),
            (json!({"all": true}), Value::Null, false),
        ] {
            let backend = MockAcp::start().await;
            let mut mcp = Mcp::start(&backend.url, http).await;
            let response = mcp.tool("sessions", args).await;
            assert_eq!(response["isError"], false);
            let result = &response["structuredContent"];
            assert_eq!(result["nextCursor"], cursor);
            assert_eq!(result["truncated"], truncated);
        }
    }
}

#[tokio::test]
async fn find_discloses_page_cap_without_claiming_an_exhaustive_search() {
    for http in [false, true] {
        for total in [19, 20, 21] {
            let backend = MockAcp::with_listing_pages(total).await;
            let mut mcp = Mcp::start(&backend.url, http).await;
            let response = mcp.tool("find", json!({"query": "not-present", "limit": 50, "resolution": "open", "pinned": false})).await;
            assert_eq!(response["isError"], false);
            let result = &response["structuredContent"];
            assert_eq!(result["sessions"], json!([]));
            assert_eq!(result["scannedPages"], total.min(20));
            assert_eq!(result["scanLimitReached"], total > 20);
            assert_eq!(result["truncated"], total > 20);
            assert_eq!(
                result["nextCursor"],
                if total > 20 {
                    json!("page-21")
                } else {
                    Value::Null
                }
            );
            let requests = backend.recorded();
            let pages: Vec<_> = requests
                .iter()
                .filter(|r| r["method"] == "session/list")
                .collect();
            assert_eq!(pages.len(), total.min(20));
            for page in pages {
                assert_eq!(
                    page["params"]["_meta"]["querymt"]["sessionFilters"]["resolution"],
                    "open"
                );
                assert_eq!(
                    page["params"]["_meta"]["querymt"]["sessionFilters"]["pinned"],
                    false
                );
            }
            if total > 20 {
                let rest = mcp.tool("sessions", json!({"cursor": result["nextCursor"], "resolution": "open", "pinned": false})).await;
                assert_eq!(rest["isError"], false);
                assert_eq!(
                    rest["structuredContent"]["sessions"][0]["sessionId"],
                    "listed-21"
                );
            }
        }
    }
}

#[tokio::test]
async fn find_distinguishes_match_limit_from_scan_limit() {
    for http in [false, true] {
        let backend = MockAcp::with_listing_pages(21).await;
        let mut mcp = Mcp::start(&backend.url, http).await;
        let response = mcp
            .tool("find", json!({"query": "Listed", "limit": 1}))
            .await;
        let result = &response["structuredContent"];
        assert_eq!(result["sessions"].as_array().unwrap().len(), 1);
        assert_eq!(result["scannedPages"], 1);
        assert_eq!(result["truncated"], true);
        assert_eq!(result["scanLimitReached"], false);
        assert_eq!(
            result["nextCursor"],
            Value::Null,
            "a mid-page match limit must not skip unread candidates"
        );
        let response = mcp
            .tool("find", json!({"query": "Listed", "limit": 2}))
            .await;
        let result = &response["structuredContent"];
        assert_eq!(result["truncated"], true);
        assert_eq!(result["scanLimitReached"], false);
        assert_eq!(result["nextCursor"], "page-2");

        let backend = MockAcp::with_listing_pages(1).await;
        let mut mcp = Mcp::start(&backend.url, http).await;
        let response = mcp
            .tool("find", json!({"query": "Listed", "limit": 2}))
            .await;
        let result = &response["structuredContent"];
        assert_eq!(result["truncated"], false);
        assert_eq!(result["scanLimitReached"], false);
        assert_eq!(result["nextCursor"], Value::Null);
    }
}

#[tokio::test]
async fn stateless_http_cancellation_notification_does_not_cancel_another_post() {
    let backend = MockAcp::with_submission(SubmissionBehavior::Busy).await;
    let mut mcp = Mcp::start(&backend.url, true).await;
    let Mcp::Http { client, url, .. } = &mcp else {
        unreachable!()
    };
    let client = client.clone();
    let url = url.clone();
    let waiting =
        tokio::spawn(async move {
            client.post(url)
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", "2025-11-25")
            .json(&json!({"jsonrpc": "2.0", "id": 73, "method": "tools/call", "params": {
                "name": "watch", "arguments": {"session_id": "fixture-session", "timeout": 2},
            }}))
            .send().await.unwrap().json::<Value>().await.unwrap()
        });
    tokio::time::timeout(Duration::from_secs(1), async {
        while !backend
            .recorded()
            .iter()
            .any(|r| r["method"] == "_querymt/session/runtimeState")
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("watch must be running before its cancellation notification is posted");
    mcp.message(
        json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {
            "requestId": 73, "reason": "verify stateless HTTP semantics",
        }}),
    )
    .await;
    assert!(
        !waiting.is_finished(),
        "the notification-only POST must not stop the separate handler"
    );
    let response = tokio::time::timeout(Duration::from_secs(3), waiting)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response["result"]["isError"], true);
    let result = &response["result"]["structuredContent"];
    assert_eq!(result["code"], 4);
    assert!(
        result["error"].as_str().unwrap().contains("timed out"),
        "the original POST must reach its own deadline, not be cancelled"
    );
    assert!(
        backend
            .recorded()
            .iter()
            .filter(|r| r["method"] == "_querymt/session/runtimeState")
            .count()
            >= 2
    );
    backend.wait_disconnected().await;
    assert_no_implicit_cancel(&backend);
}

// Linux routes the entire 127/8 range to loopback without configuring aliases.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn cli_http_accepts_the_selected_alternate_loopback_host_only() {
    let listener = TcpListener::bind("127.0.0.2:0").await.unwrap();
    let bind = listener.local_addr().unwrap();
    drop(listener);
    let backend = MockAcp::start().await;
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_qmcp"))
        .args([
            "--transport",
            "http",
            "--bind",
            &bind.to_string(),
            "--url",
            &backend.url,
        ])
        .env_remove("QMCP_BEARER_TOKEN")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(1))
        .build()
        .unwrap();
    let url = format!("http://{bind}/mcp");
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if client.get(&url).send().await.is_ok() {
                break;
            }
            assert!(
                child.try_wait().unwrap().is_none(),
                "HTTP server exited before listening"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("test HTTP listener must start");
    let request = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "bind-fixture", "version": "1"},
    }});
    let response = client
        .post(&url)
        .header("accept", "application/json, text/event-stream")
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        200,
        "an explicitly accepted loopback bind must accept its normal Host header"
    );
    assert_eq!(
        response.json::<Value>().await.unwrap()["result"]["serverInfo"]["name"],
        "qmcp"
    );
    for (header, value) in [
        ("host", "untrusted.invalid"),
        ("host", "127.0.0.3"),
        ("host", "0.0.0.0"),
        ("origin", "https://untrusted.invalid"),
        ("origin", "http://127.0.0.2"),
    ] {
        let response = client
            .post(&url)
            .header("accept", "application/json, text/event-stream")
            .header(header, value)
            .json(&request)
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            403,
            "must still reject {header}: {value}"
        );
    }
    assert!(
        backend.recorded().is_empty(),
        "protocol discovery must not connect to ACP"
    );
    child.start_kill().unwrap();
    child.wait().await.unwrap();
}

#[tokio::test]
async fn bearer_auth_guards_every_http_request_before_protocol_or_backend_work() {
    const TOKEN: &str = "fixture-token-0123456789abcdef0123456789abcdef";
    let backend = MockAcp::start().await;
    let mut mcp = Mcp::start_with_token(&backend.url, true, Some(TOKEN)).await;
    let Mcp::Http { url, .. } = &mcp else {
        unreachable!()
    };
    let url = url.clone();
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let request = json!({"jsonrpc": "2.0", "id": 11, "method": "tools/call", "params": {
        "name": "new", "arguments": {},
    }});
    for authorization in [
        None,
        Some("Bearer wrong"),
        Some(TOKEN),
        Some("Basic ignored"),
        Some("Bearer"),
        Some("Bearer "),
        Some("Bearer wrong extra"),
    ] {
        let mut builder = client
            .post(&url)
            .header("accept", "application/json, text/event-stream")
            .json(&request);
        if let Some(value) = authorization {
            builder = builder.header("authorization", value);
        }
        let response = builder.send().await.unwrap();
        assert_eq!(response.status(), 401);
        assert_eq!(
            response.headers()["www-authenticate"],
            "Bearer realm=\"qmcp\""
        );
        assert_eq!(response.headers()["cache-control"], "no-store");
        let body = response.text().await.unwrap();
        assert_eq!(body, "unauthorized");
        assert!(!body.contains(TOKEN));
    }
    let response = client
        .post(format!("{url}?access_token={TOKEN}"))
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        401,
        "query parameters must not authenticate"
    );
    for method in [
        reqwest::Method::GET,
        reqwest::Method::DELETE,
        reqwest::Method::OPTIONS,
        reqwest::Method::HEAD,
    ] {
        assert_eq!(
            client.request(method, &url).send().await.unwrap().status(),
            401
        );
    }
    let response = client
        .post(&url)
        .header("authorization", format!("Bearer {TOKEN}"))
        .header("authorization", format!("Bearer {TOKEN}"))
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        401,
        "ambiguous duplicate credentials must fail closed"
    );
    let response = client.post(&url).body("invalid JSON").send().await.unwrap();
    assert_eq!(
        response.status(),
        401,
        "authentication precedes protocol/body parsing"
    );
    assert!(
        backend.recorded().is_empty(),
        "unauthorized requests must not perform backend work"
    );
    for (header, value) in [
        ("host", "untrusted.invalid"),
        ("origin", "https://untrusted.invalid"),
    ] {
        let response = client
            .post(&url)
            .header("authorization", format!("Bearer {TOKEN}"))
            .header("accept", "application/json, text/event-stream")
            .header(header, value)
            .json(&request)
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            403,
            "a valid token must not bypass Host/Origin checks"
        );
    }
    let created = mcp.tool("new", json!({})).await;
    assert_eq!(created["isError"], false);
    assert_eq!(created["structuredContent"]["sessionId"], "fixture-session");
    let response = client.post(&url).json(&request).send().await.unwrap();
    assert_eq!(
        response.status(),
        401,
        "a previously authorized request must not authorize later calls"
    );
    assert_eq!(
        backend
            .recorded()
            .iter()
            .filter(|r| r["method"] == "session/new")
            .count(),
        1
    );
}

#[tokio::test]
async fn cli_auth_configuration_fails_closed_without_leaking_the_token() {
    const TOKEN: &str = "fixture-token-must-not-appear-in-diagnostics-0123456789";
    let cases: &[(&[&str], Option<&str>)] = &[
        (&["--transport", "http", "--bind", "0.0.0.0:0"], None),
        (
            &[
                "--transport",
                "http",
                "--bind",
                "0.0.0.0:0",
                "--allowed-host",
                "mcp.example.com",
            ],
            None,
        ),
        (&["--transport", "http", "--bind", "0.0.0.0:0"], Some(TOKEN)),
        (&["--transport", "http", "--bind", "127.0.0.1:0"], Some("")),
        (
            &["--transport", "http", "--bearer-token", "bad token"],
            None,
        ),
        (&["--transport", "stdio"], Some(TOKEN)),
        (
            &[
                "--transport",
                "http",
                "--bind",
                "0.0.0.0:0",
                "--allowed-host",
                "*",
            ],
            Some(TOKEN),
        ),
    ];
    for (args, token) in cases {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_qmcp"));
        command
            .args(*args)
            .env_remove("QMCP_BEARER_TOKEN")
            .kill_on_drop(true)
            .stdin(Stdio::null());
        if let Some(token) = token {
            command.env("QMCP_BEARER_TOKEN", token);
        }
        let output = tokio::time::timeout(Duration::from_secs(3), command.output())
            .await
            .expect("invalid HTTP config must fail before listening")
            .unwrap();
        assert!(!output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stdout.is_empty(), "startup errors must not pollute stdout");
        assert!(!stderr.contains(TOKEN));
        assert!(!stderr.contains("bad token"));
    }
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_qmcp"))
        .arg("--help")
        .env("QMCP_BEARER_TOKEN", TOKEN)
        .output()
        .await
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("QMCP_BEARER_TOKEN"));
    assert!(
        !help.contains(TOKEN),
        "help must hide the token's environment value"
    );
}

#[tokio::test]
async fn cli_token_allows_wildcard_binding_with_only_explicit_public_hosts() {
    const TOKEN: &str = "fixture-public-token-0123456789abcdef0123456789";
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let bind = listener.local_addr().unwrap();
    drop(listener);
    let backend = MockAcp::start().await;
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_qmcp"))
        .args([
            "--transport",
            "http",
            "--bind",
            &bind.to_string(),
            "--allowed-host",
            "mcp.example.com:443",
            "--url",
            &backend.url,
        ])
        .env("QMCP_BEARER_TOKEN", TOKEN)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(1))
        .build()
        .unwrap();
    let url = format!("http://127.0.0.1:{}/mcp", bind.port());
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if client.get(&url).send().await.is_ok() {
                break;
            }
            assert!(child.try_wait().unwrap().is_none());
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("authenticated HTTP listener must start");
    let request = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "public-fixture", "version": "1"},
    }});
    assert_eq!(
        client
            .post(&url)
            .header("host", "mcp.example.com:443")
            .json(&request)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    for (host, status) in [
        ("mcp.example.com:443", 200),
        ("mcp.example.com:444", 403),
        ("evil.example.com:443", 403),
        ("0.0.0.0", 403),
    ] {
        let response = client
            .post(&url)
            .bearer_auth(TOKEN)
            .header("host", host)
            .header("accept", "application/json, text/event-stream")
            .json(&request)
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            status,
            "public Host validation must remain exact"
        );
    }
    assert!(backend.recorded().is_empty());
    child.start_kill().unwrap();
    child.wait().await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn second_interrupt_forces_exit_during_a_stalled_http_call() {
    let backend = MockAcp::start().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bind = listener.local_addr().unwrap();
    drop(listener);
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_qmcp"))
        .args([
            "--transport",
            "http",
            "--bind",
            &bind.to_string(),
            "--url",
            &backend.url,
        ])
        .env_remove("QMCP_BEARER_TOKEN")
        .env_remove("QMCP_OAUTH_CLIENT_SECRET")
        .env("RUST_LOG", "warn")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stderr = BufReader::new(child.stderr.take().unwrap()).lines();
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let url = format!("http://{bind}/mcp");
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if client.get(&url).send().await.is_ok() {
                break;
            }
            assert!(child.try_wait().unwrap().is_none());
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let pending =
        tokio::spawn(async move {
            client.post(url).header("accept", "application/json, text/event-stream")
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                "name": "prompt", "arguments": {"new": true, "text": "wait", "timeout": 120},
            }})).send().await
        });
    tokio::time::timeout(Duration::from_secs(3), async {
        while !backend
            .recorded()
            .iter()
            .any(|r| r["method"] == "session/prompt")
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let pid = child.id().unwrap().to_string();
    for interrupt in 0..2 {
        // Only signal the child owned by this test, never the test runner or user services.
        let status = tokio::process::Command::new("sh")
            .args(["-c", "kill -INT \"$1\"", "qmcp-test", &pid])
            .status()
            .await
            .unwrap();
        assert!(status.success());
        if interrupt == 0 {
            tokio::time::timeout(Duration::from_secs(2), async {
                while let Some(line) = stderr.next_line().await.unwrap() {
                    if line.contains("interrupt again to force exit") {
                        return;
                    }
                }
                panic!("shutdown acknowledgement missing");
            })
            .await
            .expect("first interrupt must start graceful shutdown");
            assert!(
                child.try_wait().unwrap().is_none(),
                "first interrupt must allow in-flight work to finish"
            );
        }
    }
    let status = tokio::time::timeout(Duration::from_secs(2), child.wait())
        .await
        .expect("second interrupt must not wait for the long request")
        .unwrap();
    assert_eq!(status.code(), Some(130));
    tokio::time::timeout(Duration::from_secs(2), pending)
        .await
        .unwrap()
        .unwrap()
        .ok();
    backend.wait_disconnected().await;
    assert_no_implicit_cancel(&backend);
}

#[tokio::test]
async fn http_rejects_unsupported_methods_and_untrusted_hosts_and_origins() {
    let backend = MockAcp::start().await;
    let mcp = Mcp::start(&backend.url, true).await;
    let Mcp::Http { client, url, .. } = &mcp else {
        unreachable!()
    };
    assert_eq!(
        client
            .get(url)
            .header("accept", "application/json")
            .send()
            .await
            .unwrap()
            .status(),
        405
    );
    assert_eq!(
        client
            .get(url.replace("/mcp", "/unknown"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    let request = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}});
    for (header, value) in [
        ("host", "untrusted.invalid"),
        ("origin", "https://untrusted.invalid"),
    ] {
        let response = client
            .post(url)
            .header("accept", "application/json, text/event-stream")
            .header(header, value)
            .json(&request)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 403);
    }
    assert!(backend.recorded().is_empty());
}
