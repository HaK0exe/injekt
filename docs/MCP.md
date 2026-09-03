# injekt as an MCP server

`injekt mcp` starts a [Model Context Protocol](https://modelcontextprotocol.io/) server
over **stdio**, exposing injekt's capabilities as tools for LLM agents
(Claude Code, Codex, OpenCode, Cursor, VS Code).

All tools return **structured JSON**. Logging goes to **stderr** — stdout is the
JSON-RPC channel and is never polluted.

## Tools

| Tool | Description |
|------|-------------|
| `scan` | Scan a target URL for SQL injection. Full CLI flag mapping (techniques, tampers, proxy, rate-limit, jitter, headers, cookies, dbms, extract, dbs/tables/columns/dump, banner/current-user/current-db/hostname, db/table/column/start/stop/count, output, oob, hpp, chunked, allow-private, no-redact). |
| `recon_crawl` | Crawl a target, return discovered parameters (no testing). |
| `recon_scan` | Crawl + test each discovered parameter. |
| `info` | Capabilities, techniques, tampers, supported DBMS. |

`replay` is intentionally **not** exposed yet. `raw_file` (Burp/ZAP raw
bodies), `marker` (`*`/`§` modes), `method` override and `import` are also
CLI-only on purpose: they need local file access or ad-hoc request shaping
that does not map cleanly to a stdio tool surface. Use the CLI for those.

## Output redaction

`scan`, `recon_crawl` and `recon_scan` return **scrubbed** reports (same
`Scrubber` as the CLI: `Authorization`/`Cookie` headers, JWT/Bearer/AWS/PEM
patterns redacted). `no_redact=true` disables this (local debugging only)
and logs a server-side `warn`.

## Client configuration

Build/install the binary first (`cargo build --release`, binary at
`target/release/injekt`, or `cargo install --path .`), then register it.

### OpenCode — `opencode.json`

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "injekt": {
      "type": "local",
      "command": ["injekt", "mcp"],
      "enabled": true
    }
  }
}
```

### Claude Code — `.mcp.json` (project) or `claude mcp add`

```json
{
  "mcpServers": {
    "injekt": {
      "type": "stdio",
      "command": "injekt",
      "args": ["mcp"]
    }
  }
}
```

### Codex — `~/.codex/config.toml` (stdio only)

```toml
[mcp_servers.injekt]
enabled = true
command = "injekt"
args = ["mcp"]
```

### Cursor — `.cursor/mcp.json`

```json
{
  "mcpServers": {
    "injekt": {
      "command": "injekt",
      "args": ["mcp"]
    }
  }
}
```

### VS Code — `.vscode/mcp.json`

```json
{
  "servers": {
    "injekt": {
      "type": "stdio",
      "command": "injekt",
      "args": ["mcp"]
    }
  }
}
```

## OPSEC / safety notes (load-bearing)

- **Authorization first.** Tool descriptions instruct the agent to test only
  systems it is authorized to test. The operator remains responsible.
- `--allow-private` equivalent (`allow_private`) defaults to `false`:
  private/loopback targets are rejected unless explicitly enabled (lab only).
- OOB stays **opt-in** (`oob_domain`); without `oob_poll_url` containing
  `{token}`, probes are never auto-confirmed — same semantics as the CLI.
- `export_encrypted` is **rejected in MCP mode** (protocol-level
  `invalid_params`): there is no TTY for the passphrase prompt. Results are
  returned inline as JSON; use the `output` param for opt-in disk reports.
- Disk writes only happen when the `output` param is explicitly set (opt-in),
  mirroring CLI zero-persistence defaults. In MCP mode `output` must be a
  **relative path without `..`** (absolute paths and traversal rejected with
  `invalid_params`); files are written `0o600` on Unix and a server-side
  `warn` is logged. `recon_crawl` has no `output` param (inline JSON only).
- Long scans can exceed client tool-call timeouts: prefer bounded
  `max_pages`/`depth`/`threads` for agent-driven runs.
- `recon import` semantics: `--test` (scan candidates, active probes) vs
  offline listing (no network). MCP has no `import` tool; CLI `recon import`
  without `--test` never sends probes.

## Smoke test

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
  | ./target/debug/injekt mcp 2>/dev/null
```

Automated coverage: `cargo test --test mcp_stdio`.
