//! Process-local, immutable session workspace bindings. No lock spans an ACP request.
use std::{
    collections::{HashMap, HashSet},
    path::{Component, Path, PathBuf},
    sync::Mutex,
};

use qmacp::{client::AcpClient, error::CliError, protocol::schema::v1 as acp, session};
use serde_json::{Value, json};

use crate::output::OperationState;

const CAPACITY: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Binding {
    pub cwd: PathBuf,
    pub profile: Option<String>,
}

struct CachedBinding {
    binding: Binding,
    // Entries are never removed: insertion order is bounded by store capacity,
    // not by the (unbounded) number of operations or cancelled reservations.
    generation: usize,
    creation_claimed: bool,
}

#[derive(Default)]
struct Store {
    bindings: HashMap<String, CachedBinding>,
    reserved: usize,
}

pub(crate) struct Workspaces {
    startup_cwd: PathBuf,
    store: Mutex<Store>,
    capacity: usize,
}

pub(crate) struct Selection {
    pub session_id: String,
    pub binding: Binding,
    pub created: bool,
    pub previous: Option<String>,
    profile_source: &'static str,
}

impl Selection {
    pub fn result(&self) -> Value {
        let mut value = json!({
            "sessionId": self.session_id, "cwd": self.binding.cwd,
            "created": self.created, "switched": self.previous.is_some(),
            "profile": self.binding.profile, "profileKnown": self.binding.profile.is_some(),
            "profileSource": self.profile_source,
        });
        if let Some(previous) = &self.previous {
            value["previousSessionId"] = json!(previous);
        }
        value
    }

    pub fn checkpoint(&self, state: &mut OperationState) {
        state.session(&self.session_id, &self.binding.cwd, self.created);
        state
            .recovery
            .extend(self.result().as_object().unwrap().clone());
    }
}

// Capacity is reserved before session/new, released on rejection or cancellation,
// and committed synchronously on acknowledgement, before the next await point.
struct Reservation<'a> {
    workspaces: &'a Workspaces,
    generation: usize,
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        self.workspaces.store.lock().unwrap().reserved -= 1;
    }
}

impl Workspaces {
    pub fn new() -> anyhow::Result<Self> {
        let startup = std::env::current_dir()?;
        Ok(Self {
            startup_cwd: normalize(&startup, &startup).map_err(anyhow::Error::msg)?,
            store: Mutex::new(Store::default()),
            capacity: CAPACITY,
        })
    }

    pub fn initial_cwd(&self, cwd: Option<PathBuf>) -> Result<PathBuf, CliError> {
        normalize(
            cwd.as_deref().unwrap_or(&self.startup_cwd),
            &self.startup_cwd,
        )
        .map_err(CliError::Usage)
    }

    fn reserve(&self) -> Result<Reservation<'_>, CliError> {
        let mut store = self.store.lock().unwrap();
        if store.bindings.len() + store.reserved >= self.capacity {
            return Err(CliError::rpc(
                "workspace binding capacity reached; no session was created",
            ));
        }
        store.reserved += 1;
        Ok(Reservation {
            workspaces: self,
            generation: store.bindings.len(),
        })
    }

    fn insert(
        &self,
        id: &str,
        binding: Binding,
        reservation: Option<&Reservation<'_>>,
    ) -> Result<Binding, CliError> {
        let mut store = self.store.lock().unwrap();
        if let Some(known) = store.bindings.get_mut(id) {
            if reservation
                .is_some_and(|r| known.generation < r.generation || known.creation_claimed)
            {
                return Err(CliError::rpc(
                    "session/new returned an already bound session id; refusing to alias or overwrite the existing workspace",
                ));
            }
            if known.binding.cwd != binding.cwd
                || matches!((&known.binding.profile, &binding.profile), (Some(a), Some(b)) if a != b)
            {
                return Err(CliError::rpc(
                    "backend returned conflicting workspace metadata for an immutable session id; binding was not changed",
                ));
            }
            if known.binding.profile.is_none() {
                known.binding.profile = binding.profile;
            }
            // Only matching authoritative metadata first cached after this
            // reservation may be claimed. A second ACK cannot claim it again.
            known.creation_claimed |= reservation.is_some();
            return Ok(known.binding.clone());
        }
        if reservation.is_none() && store.bindings.len() + store.reserved >= self.capacity {
            return Err(CliError::rpc("workspace binding capacity reached"));
        }
        let generation = store.bindings.len();
        store.bindings.insert(
            id.to_owned(),
            CachedBinding {
                binding: binding.clone(),
                generation,
                creation_claimed: reservation.is_some(),
            },
        );
        Ok(binding)
    }

    pub async fn binding(&self, client: &AcpClient, id: &str) -> Result<Binding, CliError> {
        if let Some(known) = self.store.lock().unwrap().bindings.get(id) {
            return Ok(known.binding.clone());
        }
        client.initialize().await.map_err(CliError::from_request)?;
        let mut cursor = None;
        let mut seen = HashSet::new();
        for _ in 0..session::find_page_cap() {
            // Equivalent to list_sessions(None, cursor, None): no cwd or metadata
            // filters. Retain raw JSON because ACP's typed list decoder can omit
            // malformed summaries (including a target without cwd).
            let mut request = acp::ListSessionsRequest::new();
            if let Some(cursor) = cursor {
                request = request.cursor(cursor);
            }
            let (_page, raw) = client.request_json(request).await.map_err(|error| {
                CliError::rpc(format!("authoritative workspace metadata unavailable from session/list: {error}; refusing to guess cwd or create a session"))
            })?;
            let next_cursor = match raw.get("nextCursor") {
                None | Some(Value::Null) => None,
                Some(Value::String(next)) => Some(next.clone()),
                Some(_) => {
                    return Err(CliError::rpc(
                        "authoritative workspace metadata unavailable: session/list nextCursor must be a string or null; discovery is incomplete, not an exhaustive not-found result",
                    ));
                }
            };
            let summaries = raw.get("sessions").and_then(Value::as_array).ok_or_else(|| CliError::rpc("authoritative workspace metadata unavailable: session/list has no sessions array"))?;
            for item in summaries {
                if item.get("sessionId").and_then(Value::as_str) != Some(id) {
                    continue;
                }
                let cwd = item.get("cwd").and_then(Value::as_str).map(PathBuf::from).ok_or_else(|| CliError::rpc("authoritative workspace metadata unavailable: target session cwd is absent; refusing to guess cwd (even from an explicit caller path)"))?;
                if !cwd.is_absolute() {
                    return Err(CliError::rpc(
                        "authoritative session cwd is missing or not absolute; refusing to guess cwd (even from an explicit caller path)",
                    ));
                }
                let cwd = normalize(&cwd, &self.startup_cwd).map_err(|error| {
                    CliError::rpc(format!("authoritative session cwd is invalid: {error}"))
                })?;
                let profile = item
                    .pointer("/_meta/querymt/profile_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                return self.insert(id, Binding { cwd, profile }, None);
            }
            match next_cursor {
                None => {
                    return Err(CliError::rpc(format!(
                        "session {id} not found in authoritative session/list; no workspace was selected or created"
                    )));
                }
                Some(next) if !seen.insert(next.clone()) => {
                    return Err(CliError::rpc(
                        "workspace metadata discovery incomplete: session/list repeated a cursor; no workspace was selected or created",
                    ));
                }
                Some(next) => cursor = Some(next),
            }
        }
        Err(CliError::rpc(
            "workspace metadata discovery incomplete: session/list page cap reached; session may exist beyond the scan; no workspace was selected or created",
        ))
    }

    pub async fn read_cwd(
        &self,
        client: &AcpClient,
        id: &str,
        cwd: Option<PathBuf>,
    ) -> Result<PathBuf, CliError> {
        let binding = self.binding(client, id).await?;
        if let Some(cwd) = cwd {
            let requested = normalize(&cwd, &binding.cwd).map_err(CliError::Usage)?;
            if requested != binding.cwd {
                return Err(CliError::Usage("read-only session operations cannot change cwd; use workspace with this session_id and cwd to create a NEW session, then use its returned sessionId".into()));
            }
        }
        Ok(binding.cwd)
    }

    pub async fn create(
        &self,
        client: &AcpClient,
        state: &mut OperationState,
        binding: Binding,
        previous: Option<String>,
        profile_source: &'static str,
    ) -> Result<(Selection, acp::NewSessionResponse, Value), CliError> {
        let reservation = self.reserve()?;
        client.initialize().await.map_err(CliError::from_request)?;
        let (created, raw) = client
            .new_session(binding.cwd.clone(), binding.profile.as_deref())
            .await
            .map_err(CliError::from_request)?;
        let session_id = created.session_id.to_string();
        let binding = match self.insert(&session_id, binding, Some(&reservation)) {
            Ok(binding) => binding,
            Err(error) => {
                state.recovery.insert(
                    "workspaceConflict".into(),
                    json!({
                        "acknowledgedSessionId": session_id,
                        "selectionCommitted": false,
                    }),
                );
                return Err(error);
            }
        };
        let profile_source =
            if binding.profile.is_some() && profile_source == "backend-default-unknown" {
                "authoritative-metadata"
            } else {
                profile_source
            };
        let selection = Selection {
            session_id,
            binding,
            created: true,
            previous,
            profile_source,
        };
        selection.checkpoint(state);
        drop(reservation);
        Ok((selection, created, raw))
    }

    pub async fn select(
        &self,
        client: &AcpClient,
        state: &mut OperationState,
        id: Option<String>,
        cwd: Option<PathBuf>,
        profile: Option<String>,
    ) -> Result<Selection, CliError> {
        let Some(id) = id else {
            let cwd = cwd.ok_or_else(|| {
                CliError::Usage(
                    "workspace requires an explicit initial cwd when session_id is omitted".into(),
                )
            })?;
            let binding = Binding {
                cwd: self.initial_cwd(Some(cwd))?,
                profile,
            };
            let source = if binding.profile.is_some() {
                "explicit"
            } else {
                "backend-default-unknown"
            };
            return self
                .create(client, state, binding, None, source)
                .await
                .map(|created| created.0);
        };
        let binding = self.binding(client, &id).await?;
        let requested = cwd
            .map(|cwd| normalize(&cwd, &binding.cwd).map_err(CliError::Usage))
            .transpose()?
            .unwrap_or(binding.cwd.clone());
        if requested == binding.cwd {
            if profile
                .as_ref()
                .is_some_and(|profile| Some(profile) != binding.profile.as_ref())
            {
                return Err(CliError::Usage("profile changes on an existing session are not supported by workspace/prompt; the requested profile differs or the existing profile is unknown; create a new workspace without session_id to select a profile".into()));
            }
            return Ok(Selection {
                session_id: id,
                binding,
                created: false,
                previous: None,
                profile_source: "remembered-or-metadata",
            });
        }
        let source = if profile.is_some() {
            "explicit"
        } else if binding.profile.is_some() {
            "inherited"
        } else {
            "backend-default-unknown"
        };
        let binding = Binding {
            cwd: requested,
            profile: profile.or(binding.profile),
        };
        self.create(client, state, binding, Some(id), source)
            .await
            .map(|created| created.0)
    }
}

/// POSIX lexical paths on the ACP host, not filesystem canonicalization on qmcp.
fn normalize(path: &Path, base: &Path) -> Result<PathBuf, String> {
    let text = path.to_str().ok_or("cwd must be valid UTF-8")?;
    if text.is_empty() || text.chars().any(char::is_control) {
        return Err("cwd must not be empty or contain control characters".into());
    }
    if text.starts_with('~') {
        return Err("cwd cannot use ~ expansion on a remote host; provide an explicit absolute path on the QueryMT host".into());
    }
    if text.contains('\\') || text.as_bytes().get(1) == Some(&b':') || text.starts_with("//") {
        return Err("cwd must be an unambiguous POSIX path, not a Windows drive/UNC path".into());
    }
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    let mut result = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::RootDir => result.push("/"),
            Component::CurDir => {}
            Component::ParentDir => {
                result.pop();
            }
            Component::Normal(name) => result.push(name),
            Component::Prefix(_) => return Err("cwd must be a POSIX path".into()),
        }
    }
    if !result.is_absolute() {
        return Err("cwd must resolve to an absolute POSIX path".into());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_lexical_and_do_not_require_a_local_filesystem() {
        let base = Path::new("/remote/nonexistent/project");
        for (input, expected) in [
            (".", "/remote/nonexistent/project"),
            ("a/../b", "/remote/nonexistent/project/b"),
            ("../other", "/remote/nonexistent/other"),
            ("/a/./b/../../..", "/"),
        ] {
            assert_eq!(
                normalize(Path::new(input), base).unwrap(),
                Path::new(expected)
            );
        }
        for input in [
            "",
            "~",
            "~/project",
            "~user/project",
            "C:",
            "C:/work",
            "a\nb",
            "a\0b",
            "//host/work",
            "C:\\work",
        ] {
            assert!(normalize(Path::new(input), base).is_err(), "{input:?}");
        }
    }

    #[test]
    fn startup_relative_paths_are_stable() {
        let workspaces = Workspaces::new().unwrap();
        let expected =
            normalize(Path::new("relative/../project"), &workspaces.startup_cwd).unwrap();
        assert_eq!(
            workspaces
                .initial_cwd(Some("relative/../project".into()))
                .unwrap(),
            expected
        );
        assert_eq!(
            workspaces.initial_cwd(None).unwrap(),
            workspaces.startup_cwd
        );
    }

    #[tokio::test]
    async fn full_store_fails_before_any_new_session_request() {
        use futures_util::StreamExt;
        use qmacp::policy::PermissionPolicy;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/acp/ws", listener.local_addr().unwrap());
        let peer = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            while let Some(Ok(message)) = socket.next().await {
                assert!(
                    !message.is_text(),
                    "a full workspace store must not send any ACP request"
                );
            }
        });
        let (events, _receiver) = tokio::sync::mpsc::channel(16);
        let client = AcpClient::connect_with_events(&url, &url, PermissionPolicy::Cancel, events)
            .await
            .unwrap();
        let mut workspaces = Workspaces::new().unwrap();
        workspaces.capacity = 0;
        let mut state = OperationState::default();
        let result = workspaces
            .create(
                &client,
                &mut state,
                Binding {
                    cwd: "/remote".into(),
                    profile: None,
                },
                None,
                "backend-default-unknown",
            )
            .await;
        assert!(matches!(result, Err(error) if error.to_string().contains("capacity")));
        assert!(state.recovery.is_empty());
        drop(client);
        tokio::time::timeout(std::time::Duration::from_secs(2), peer)
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn reservation_generations_reconcile_once_and_refund_at_full_capacity() {
        let mut workspaces = Workspaces::new().unwrap();
        workspaces.capacity = 3;
        let binding = Binding {
            cwd: "/remote".into(),
            profile: Some("inherited".into()),
        };
        let first = workspaces.reserve().unwrap();
        let second = workspaces.reserve().unwrap();
        workspaces
            .insert(
                "fresh",
                Binding {
                    profile: None,
                    ..binding.clone()
                },
                None,
            )
            .unwrap();
        assert!(workspaces.reserve().is_err());
        assert_eq!(
            workspaces
                .insert("fresh", binding.clone(), Some(&first))
                .unwrap(),
            binding
        );
        drop(first);
        assert!(
            workspaces
                .insert("fresh", binding.clone(), Some(&second))
                .is_err()
        );
        drop(second);
        {
            let store = workspaces.store.lock().unwrap();
            assert_eq!(store.reserved, 0);
            assert_eq!(store.bindings.len(), 1);
        }
        let reuse = workspaces.reserve().unwrap();
        let spare = workspaces.reserve().unwrap();
        assert!(workspaces.reserve().is_err());
        drop(reuse);
        drop(spare);
        // An ID discovered before the reservation is never a fresh creation,
        // even when cwd and profile are identical and it is metadata-only.
        workspaces
            .insert("prebound", binding.clone(), None)
            .unwrap();
        let reservation = workspaces.reserve().unwrap();
        assert!(
            workspaces
                .insert("prebound", binding, Some(&reservation))
                .is_err()
        );
        drop(reservation);
        assert_eq!(workspaces.store.lock().unwrap().reserved, 0);
    }

    #[test]
    fn conflicting_metadata_does_not_mutate_bindings_or_consume_creation_claim() {
        let workspaces = Workspaces::new().unwrap();
        let reservation = workspaces.reserve().unwrap();
        let binding = Binding {
            cwd: "/remote".into(),
            profile: Some("authoritative".into()),
        };
        workspaces.insert("fresh", binding.clone(), None).unwrap();
        for conflict in [
            Binding {
                cwd: "/wrong".into(),
                ..binding.clone()
            },
            Binding {
                profile: Some("wrong".into()),
                ..binding.clone()
            },
        ] {
            assert!(
                workspaces
                    .insert("fresh", conflict, Some(&reservation))
                    .is_err()
            );
            let store = workspaces.store.lock().unwrap();
            assert_eq!(store.bindings["fresh"].binding, binding);
            assert!(!store.bindings["fresh"].creation_claimed);
        }
        assert_eq!(
            workspaces
                .insert(
                    "fresh",
                    Binding {
                        profile: None,
                        ..binding.clone()
                    },
                    Some(&reservation)
                )
                .unwrap(),
            binding
        );
        drop(reservation);
        assert_eq!(workspaces.store.lock().unwrap().reserved, 0);
    }

    #[tokio::test]
    async fn cancellation_while_awaiting_creation_ack_releases_capacity_without_inventing_an_id() {
        use futures_util::{SinkExt, StreamExt};
        use qmacp::policy::PermissionPolicy;
        use tokio_tungstenite::tungstenite::Message;
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("ws://{}/acp/ws", listener.local_addr().unwrap());
            let (ready, observed) = tokio::sync::oneshot::channel();
            let peer = tokio::spawn(async move {
                let mut ready = Some(ready);
                for attempt in 0..2 {
                    let (socket, _) = listener.accept().await.unwrap();
                    let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
                    while let Some(Ok(message)) = socket.next().await {
                        let Message::Text(text) = message else { continue };
                        let request: Value = serde_json::from_str(&text).unwrap();
                        let result = match request["method"].as_str().unwrap() {
                            "initialize" => json!({"protocolVersion": 1, "agentCapabilities": {}}),
                            "session/new" if attempt == 0 => {
                                // The backend may have created an orphan, but no ID is acknowledged.
                                ready.take().unwrap().send(()).unwrap();
                                continue;
                            }
                            "session/new" => json!({"sessionId": "acknowledged"}),
                            _ => panic!("no implicit remote cancellation, close, load or prompt: {request}"),
                        };
                        socket.send(Message::Text(json!({"jsonrpc": "2.0", "id": request["id"], "result": result}).to_string().into())).await.unwrap();
                    }
                }
            });
            let mut workspaces = Workspaces::new().unwrap();
            workspaces.capacity = 1;
            let mut state = OperationState::default();
            let binding = Binding { cwd: "/remote".into(), profile: None };
            let (events, _receiver) = tokio::sync::mpsc::channel(16);
            let client = AcpClient::connect_with_events(&url, &url, PermissionPolicy::Cancel, events).await.unwrap();
            {
                let operation = workspaces.create(&client, &mut state, binding.clone(), None, "backend-default-unknown");
                tokio::pin!(operation);
                tokio::select! {
                    result = &mut operation => panic!("unexpected creation ACK: {}", result.is_ok()),
                    _ = observed => {},
                }
            }
            assert!(state.recovery.is_empty());
            {
                let store = workspaces.store.lock().unwrap();
                assert!(store.bindings.is_empty());
                assert_eq!(store.reserved, 0);
            }
            drop(client);
            let (events, _receiver) = tokio::sync::mpsc::channel(16);
            let client = AcpClient::connect_with_events(&url, &url, PermissionPolicy::Cancel, events).await.unwrap();
            workspaces.create(&client, &mut state, binding, Some("previous-valid".into()), "backend-default-unknown").await.unwrap();
            assert_eq!(state.recovery["sessionId"], "acknowledged");
            assert_eq!(state.recovery["sessionCreated"], true);
            assert_eq!(workspaces.store.lock().unwrap().reserved, 0);
            // A subsequent invalid ACK must not overwrite any prior valid checkpoint.
            workspaces.capacity = 2;
            let prior = state.recovery.clone();
            let error = workspaces.create(&client, &mut state,
                Binding { cwd: "/fake-new".into(), profile: None },
                Some("fake-previous".into()), "backend-default-unknown").await.err().unwrap();
            let failed = state.finish(crate::output::failure(error));
            for (key, value) in prior {
                assert_eq!(failed["recovery"][&key], value);
            }
            assert_eq!(failed["recovery"]["previousSessionId"], "previous-valid");
            assert_ne!(failed["recovery"]["previousSessionId"], "fake-previous");
            assert_eq!(failed["recovery"]["cwd"], "/remote");
            assert_eq!(failed["recovery"]["workspaceConflict"]["acknowledgedSessionId"], "acknowledged");
            assert_eq!(workspaces.store.lock().unwrap().reserved, 0);
            drop(client);
            peer.await.unwrap();
        }).await.expect("cancellation and capacity reuse must complete without waiting for an ACK");
    }
}
