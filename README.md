# qmcp

MCP server that lets an MCP client control a running QueryMT agent.
Built with Rust and [qmacp](https://github.com/querymt/qmacp), connecting to
QueryMT over ACP WebSockets. Supports **stdio** (default) and **Streamable HTTP**.

## Install

From a checkout, install with Nix:

```sh
nix profile install .
```

Or use Cargo with the toolchain in `rust-toolchain.toml`:

```sh
cargo install --locked --path .
```

## Connect

For ChatGPT, qmcp provides embedded single-owner OAuth with explicit consent,
PKCE, dynamic client registration, and rotating refresh tokens. Run it on the
Mac behind an HTTPS reverse proxy; no external login service is needed:

```sh
qmcp --transport http --permission cancel \
  --oauth-local-resource https://mcp.example.com/mcp \
  --oauth-owner-secret-file /absolute/private/path/to/owner-secret
```

See the [connection guide](docs/how-to-connect.md) for credential generation,
proxy configuration, stdio, static Bearer, tunnels, or external OAuth.
OAuth state is volatile: restart invalidates tokens and registered client IDs.
Approval grants all backend tools, not multi-user isolation.

## Tools

The MCP client discovers the tools and their argument schemas automatically.
Start with `caps`, `profiles`, and `models` to discover available capabilities.

| Tools | Purpose |
| --- | --- |
| `caps`, `profiles`, `models` | Discover protocol features, profiles, and models |
| `workspace`, `new`, `sessions`, `find` | Select a workspace without prompting; create, list, and search sessions |
| `status`, `inspect`, `runtime` | Read configuration, history, and live runtime |
| `get_lifecycle`, `set_lifecycle` | Read or explicitly patch resolved/archived state |
| `pin`, `unpin` | Set session pin state |
| `set_mode`, `set_model`, `set_effort` | Configure the session |
| `prompt`, `follow`, `watch` | Submit work, collect events, or poll until idle |
| `steer`, `queue`, `discard_queued` | Control active and queued input |
| `cancel`, `close` | Request turn cancellation or explicitly close a session |
| `exec` | Run a batch sequentially on one ACP connection |

Choose a workspace once without prompting, then reuse the returned ID:

```text
workspace({"cwd":"/srv/projects/app","profile":"my-profile"})
prompt({"session_id":"<returned sessionId>","text":"Explain this project"})
workspace({"session_id":"<returned sessionId>","cwd":"../other"})
```

A directory switch creates a **new session**: use its returned `sessionId`.
The old ID remains unchanged; nothing implicitly closes or cancels its work.
`new` and `prompt(new=true)` also bind cwd; continuing `prompt` can omit cwd.
`status`, `inspect`, and `follow` reject directory changes. Unknown IDs require
backend `session/list` metadata; missing or incomplete metadata fails closed.
Paths are lexical POSIX paths on the QueryMT host, not a sandbox. Initial relative
paths use qmcp's startup cwd; later ones use the session cwd. `~` is rejected;
supply the backend's absolute home path. See [workspace details](docs/how-to-connect.md#select-a-session-workspace).

## Important Behavior

- Tools can execute work through QueryMT. The default permission policy is
  `allow-once`, with a fallback to the first offered option (possibly `allowAlways`).
  Use `--permission cancel` to deny all approval requests. Interactive elicitation
  is not supported.
- Timeouts and MCP cancellation do **not** stop remote work. Use `cancel`, then
  verify with `runtime`. Stateless HTTP ignores separate MCP cancellation
  notifications; disconnecting is not a guarantee that the operation stopped.
- Failed calls may include `recovery` details. Check them and current runtime
  before retrying: prior effects are not rolled back, including in `exec` batches.
- Queue/steer delivery skips session history. On `prompt`, `until_idle: false`
  returns after submission when either is selected; idle prompt delivery still waits.
- A receipt confirms acceptance, not task success. Check `observationState`;
  invalid receipts fail and keep submission recovery unconfirmed.
- Events and assistant text are returned with the result, not streamed live.
  Check `droppedEvents` and `textTruncated` for incomplete output.
- `find` scans at most 20 pages. Check `truncated` and `scanLimitReached` before
  treating its results as exhaustive.

`inspect` still uses ACP `session/load`, which may restore runtime state; it is
not a guaranteed read-only history API. A backend replay failure is a tool error,
not empty history. No history endpoint or backend fix is supplied here.

## Development

```sh
nix develop -c cargo fmt --all -- --check
nix develop -c cargo clippy --locked --all-targets -- -D warnings
nix develop -c cargo test --locked --all-targets
nix build
```

Tests use mock ACP servers; no running QueryMT instance or provider is needed.
Licensed under [MIT](LICENSE); qmacp's original MIT attribution is retained.
