# How To Connect

[Install qmcp](../README.md#install), then choose a setup:

| Setup | Best for | Authentication |
| --- | --- | --- |
| [Local stdio](#local-stdio) | Desktop and CLI MCP clients | Local process permissions |
| [Embedded OAuth on macOS](#embedded-oauth-on-macos-chatgpt) | Single-owner public ChatGPT connections | Built-in owner login + consent; no external provider |
| [Bearer over HTTPS](#bearer-over-https) | Clients with custom authorization headers | Shared token |
| [Private tunnel](#private-tunnel-chatgpt) | ChatGPT without a public endpoint | OpenAI tunnel access |
| [External OAuth provider](#external-oauth-provider-optional) | Deployments with an existing identity provider | Optional external introspection |

Bearer and OAuth are HTTP authentication modes. The tunnel privately connects
ChatGPT to qmcp over stdio; it is not another MCP transport.

## Start QueryMT

All setups need a configured QueryMT instance with any required provider credentials:

```sh
qmtcode --acp-ws
```

qmcp connects to `ws://127.0.0.1:3030/acp/ws` by default. Change it with `--url`
or `QMCP_ACP_URL`. Prefer `wss://` for remote ACP connections; plaintext
non-loopback ACP requires `--allow-insecure`. qmcp does not launch QueryMT.

## Select a Session Workspace

Call `workspace({"cwd":"/srv/projects/app","profile":"<optional profile ID>"})`
without sending a prompt. Reuse its returned `sessionId` in later calls; omit cwd
until you explicitly change it. There is no global active workspace.
`workspace({"session_id":"A","cwd":"../other"})` creates session B, leaving A
unchanged. Use B's returned ID. Continuing `prompt` with a different cwd behaves
likewise; `status`, `inspect`, and `follow` reject a different cwd.

Paths refer to the QueryMT host and normalize `.`/`..` lexically, without local
filesystem or symlink checks. Initial relative paths use qmcp's startup cwd;
subsequent paths use the bound session cwd. Supply absolute remote paths;
`~`, Windows paths, empty paths, and control characters are rejected.
Known profiles are inherited on switches; unknown ones use the backend default
and report `profileKnown:false`. Same-directory profile changes are rejected.

Bindings are immutable per ID, process-local, shared across HTTP calls, retained
on close, and capped at 4096 without eviction. Unknown IDs (including after
restart) require unfiltered paginated `session/list` metadata. Missing cwd,
repeated cursors, unavailable metadata, or the 20-page scan limit fail closed;
caller cwd cannot override them. Check `recovery` before retrying failed creation:
an acknowledged ID is retained, but an unacknowledged creation may still exist
remotely. Timeouts never implicitly cancel remote work.

## Local stdio

Configure your MCP client to launch qmcp:

```json
{
  "mcpServers": {
    "qmcp": {
      "command": "qmcp",
      "args": ["--url", "ws://127.0.0.1:3030/acp/ws"]
    }
  }
}
```

Use an absolute binary path if your client cannot find `qmcp` on `PATH`.
Stdin/stdout carry MCP; logs go to stderr. Leave HTTP auth options and their
secret environment variables unset for stdio.

For local HTTP instead, run `qmcp --transport http` and connect with Streamable
HTTP to `http://127.0.0.1:3031/mcp`. Without authentication, only loopback binds
are allowed. Other local processes can access that endpoint.

## Bearer over HTTPS

Supply a long random token through your service's `QMCP_BEARER_TOKEN` environment
variable (preferred over the `--bearer-token` argument), then run:

```sh
qmcp --transport http --allowed-host mcp.example.com
```

Place an HTTPS reverse proxy in front of `127.0.0.1:3031`. Connect the MCP client
to `https://mcp.example.com/mcp` with this header on **every** request:

```http
Authorization: Bearer <your-token>
```

This works with clients that support custom headers. ChatGPT's public MCP setup
does not accept a manually supplied static API key; use OAuth or a private tunnel.
A shared token grants the full configured tool surface, not per-user permissions.

## Private Tunnel (ChatGPT)

Use [OpenAI Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)
to keep qmcp private. Your account/workspace must allow tunnels and custom MCP servers.

1. Install `tunnel-client` using the linked guide. Create a tunnel in
   [Platform settings](https://platform.openai.com/settings/organization/tunnels),
   link your ChatGPT workspace, and supply its runtime key as `CONTROL_PLANE_API_KEY`.
2. Set `TUNNEL_ID`, replace the qmcp binary path, and run alongside QueryMT:

   ```sh
   tunnel-client init --sample sample_mcp_stdio_local --profile qmcp \
     --tunnel-id "$TUNNEL_ID" --mcp-command "/absolute/path/to/qmcp"
   tunnel-client doctor --profile qmcp --explain
   tunnel-client run --profile qmcp
   ```

3. In [ChatGPT Plugins](https://chatgpt.com/plugins), choose **+ > Add custom MCP server**,
   name it `qmcp`, select **Connection: Tunnel**, and choose your tunnel. Select
   **No authentication** for this private stdio connection and create/install it.
   Tunnel access controls the connection; leave `QMCP_BEARER_TOKEN` and
   `QMCP_OAUTH_CLIENT_SECRET` unset in the qmcp process's environment.
4. Select the plugin with `@` in a chat and ask: **"Use qmcp to list QueryMT profiles."**
   Keep QueryMT and `tunnel-client` running. No public qmcp endpoint is needed.

## Embedded OAuth on macOS (ChatGPT)

qmcp runs the single-owner authorization server on the Mac. TLS terminates at
your trusted HTTPS proxy; the canonical public resource must end in `/mcp` with
no userinfo, query, or fragment. Its origin is the issuer.

Generate a credential only when preparing deployment (these commands do not
print it and refuse to overwrite an existing file):

```sh
umask 077
mkdir -p "$HOME/.config/qmcp"
chmod 700 "$HOME/.config/qmcp"
(set -C; openssl rand -hex 32 > "$HOME/.config/qmcp/owner-secret")
chmod 600 "$HOME/.config/qmcp/owner-secret"
```

Use only 32..64 cryptographically random bytes encoded as lowercase hex, never
a password. Keep the value in a trusted password manager for browser login, not
URLs, arguments, environment, logs, or source control. The absolute secret path
must be an owned Unix regular file, mode `0600`, without symlinks or hard links;
protect its parent directory too. qmcp neither generates nor prints the secret.

Leave `QMCP_BEARER_TOKEN` and `QMCP_OAUTH_CLIENT_SECRET` unset, then run:

```sh
qmcp --transport http --permission cancel \
  --oauth-local-resource https://mcp.example.com/mcp \
  --oauth-owner-secret-file "$HOME/.config/qmcp/owner-secret"
```

The default listener is `127.0.0.1:3031`. For a separate proxy, use the
[Nginx/VPN template](#separate-nginx-server-to-a-mac-over-vpn). Forward `/mcp`,
`/.well-known/oauth-authorization-server`, both protected-resource discovery
paths, and `/oauth/register`, `/oauth/authorize`, `/oauth/token`. Preserve Host,
Authorization, Origin, and queries. The public resource Host is automatically
allowed; local/external OAuth and static Bearer modes are mutually exclusive.

In ChatGPT, add the public `/mcp` URL, choose **OAuth**, and use DCR. Do not put
the owner credential in client ID/secret fields. During sign-in verify the domain,
unverified client name, and exact callback. Enter the credential on qmcp's owner
page and explicitly approve or deny, then click **Continue to ChatGPT**.
Registration alone grants nothing. Custom MCP servers must be enabled in your
workspace; live sign-in still needs deployment validation.

Security/lifetime constraints:

- Public clients use authorization-code + PKCE `S256`; DCR may additionally request
  `refresh_token`. Exact client, redirect, resource, and scope are bound to grants.
  Metadata URLs are never fetched. Login requires an issuer-Origin form POST,
  a browser cookie, CSRF token, and explicit owner consent. Other routes reject Origin.
- Approval grants all tools on this backend (`qmcp:access`), not per-user isolation.
  `--permission cancel` controls agent approvals, not MCP authentication.
- Access lasts up to 30 minutes; rotating one-use refresh tokens have an absolute
  24-hour family deadline. Replay revokes the entire family. Serialize refreshes:
  concurrent refreshes or retrying a lost successful response can revoke the winner.
- Credentials are stored as digests; state is bounded and volatile. Restart invalidates client IDs and tokens;
  ChatGPT may require removing/re-adding the server. Approved clients survive until
  restart; unapproved registrations expire after one hour. No persistence is supplied.
- Capacity/rate errors do not evict replay evidence or consume valid credentials.
  A family allows at most 127 rotations; exhaustion requires owner authorization
  again. Keep proxy connection/body/rate limits and private logs: application bounds
  do not prevent all resource exhaustion. Never log OAuth queries, bodies, or tokens.

## External OAuth Provider (Optional)

For an existing identity provider, use an external [OAuth provider](https://developers.openai.com/plugins/build/auth)
with authorization-code + PKCE (`S256`) and ChatGPT client registration
(pre-registered, CIMD, or DCR). qmcp provides discovery and token introspection;
the provider handles login, consent, token issuance, and revocation.

Create `oauth.json` with your actual provider values:

```json
{
  "resource": "https://mcp.example.com/mcp",
  "issuer": "https://auth.example.com/",
  "introspection_url": "https://auth.example.com/introspect",
  "client_id": "qmcp-resource-server",
  "scope": "qmcp:access"
}
```

Supply `QMCP_OAUTH_CLIENT_SECRET` through service secret settings, leave
`QMCP_BEARER_TOKEN` unset, and run behind your HTTPS proxy:

```sh
qmcp --transport http --oauth-config oauth.json --allowed-host mcp.example.com
```

The provider must publish OAuth discovery metadata, honor the `resource` parameter,
and return `active`, `iss`, `aud`, `exp`, `scope`, and `token_type: Bearer` from
RFC 7662 introspection authenticated with `client_secret_post`. `aud` must include
`resource` exactly; `iss` must match `issuer`. If `nbf` is present it is enforced.
The introspection credentials belong to qmcp, not ChatGPT's OAuth client.
Forward `/mcp` and both `/.well-known/oauth-protected-resource` and
`/.well-known/oauth-protected-resource/mcp` through the HTTPS proxy.

In ChatGPT, add a custom MCP server with your public `/mcp` URL and select **OAuth**.
Configure the provider's ChatGPT client and exact callback URL shown by ChatGPT,
then create/install the plugin and sign in. Select it with `@` and ask:
**"Use qmcp to list QueryMT profiles."** Workspace permissions apply.

The default `qmcp:access` scope grants all tools on this backend, not isolated
per-user workspaces. Tokens are checked on every request without caching;
provider outages deny access. Live ChatGPT sign-in depends on your provider
configuration and has not been verified by the project's mock-provider tests.

## Separate Nginx server to a Mac over VPN

Topology: ChatGPT -> public HTTPS Nginx -> encrypted VPN -> qmcp on Mac:3031
-> local QueryMT. Replace the example domain, VPN address, and certificate paths.
Keep QueryMT's ACP port private. On the Mac, use the protected owner file above:

```sh
qmcp --transport http --bind 10.0.0.42:3031 --permission cancel \
  --oauth-local-resource https://mcp.example.com/mcp \
  --oauth-owner-secret-file /absolute/private/path/to/owner-secret
```

On the separate proxy host (not deployment instructions to execute during review):

```nginx
server {
    listen 443 ssl;
    server_name mcp.example.com;
    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;
    location / {
        proxy_pass http://10.0.0.42:3031;
        proxy_http_version 1.1;
        proxy_set_header Host $http_host;
        proxy_set_header Authorization $http_authorization;
        proxy_set_header Origin $http_origin;
        proxy_set_header Connection "";
        access_log off; # OAuth queries contain codes/state.
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_cache off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
```

The upstream has no URI suffix, so discovery and authorization paths reach qmcp
unchanged. Never strip Origin to bypass validation. Firewall Mac port 3031 to the
proxy's VPN source only; do not expose it or ACP publicly. Plain HTTP assumes the
encrypted VPN hop, not an untrusted LAN. Keep the Mac awake and VPN reachable.
Validate adapted Nginx configuration before deployment. Source tests do not prove
real ChatGPT sign-in and must not restart installed services.

## Remote Access Checklist

- Use HTTPS: qmcp itself does not terminate TLS. Never send tokens over public plaintext HTTP.
- Keep qmcp's backend port private to the proxy with a firewall/private network.
- Forward Authorization, Host and Origin unchanged. MCP rejects browser Origin;
  only embedded OAuth consent POSTs accept the exact public issuer Origin.
- Non-loopback binds require Bearer or OAuth auth. Wildcard binds require an
  explicit Host allowlist (`--allowed-host`, repeatable, optionally `host:port`);
  embedded OAuth supplies its canonical resource Host automatically.
- Use `--bind` only when the proxy needs another interface. Keep the default
  loopback listener when the proxy runs on the same host.
- `--permission` controls QueryMT tool approval, not MCP client authentication.
  Credentials authorize powerful agent tools; share them only with trusted users.

Run `qmcp --help` for all options. Set `RUST_LOG=info` for connection diagnostics.
