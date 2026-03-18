# Sandcastle

An MCP server that gives AI agents access to sandboxed environments.

## The Idea

Running an LLM inside a sandbox is hard — you need to route its API calls, handle tool use, and manage the harness, all from within an isolated environment.

Sandcastle flips this around: **the LLM lives outside the sandbox and accesses it over MCP**. The agent connects to a Sandcastle instance and gets tools to interact with sandboxed environments — clone repos, read/write files, run commands, open PRs. The sandbox stays simple because it only needs to expose an interface, not host the model.

This works naturally with how LLMs operate: without tools, an LLM can only write text. With Sandcastle as the sole MCP server, what the agent can do is exactly what the sandbox allows — no more.

Because the agent is just an MCP client, it can run anywhere that supports MCP — Claude.ai, Slack, a CLI, a custom app. This means you can use your existing subscription (e.g. Claude Pro/Team) instead of paying for API usage, and you can trigger sandboxed tasks from interfaces like Slack without writing any API integration code.

```
┌─────────────────────────────────┐
│  Agent (Claude, GPT, etc.)      │
│  + Sandcastle MCP tools         │
└────────────────┬────────────────┘
                 │ MCP calls
         ┌───────▼───────┐
         │  Sandcastle   │
         │  MCP Server   │
         └───────┬───────┘
                 │
      ┌──────────▼──────────┐
      │  Sandbox Provider   │
      │  (GitHub, Docker,   │
      │   VMs, etc.)        │
      └─────────────────────┘
```

## Quick Start

### 1. Install

```bash
cargo install --path .
```

This builds and installs the `sandcastle` binary to your Cargo bin directory (usually `~/.cargo/bin`).

### 2. Run and follow the setup wizard

```bash
sandcastle
```

The wizard will walk you through configuration and connecting your agent.

> **Tip:** MCP clients like Claude.ai need to reach Sandcastle over HTTPS. Use [ngrok](https://ngrok.com) to get a public URL — when the wizard asks for a base URL, use the one ngrok provides (e.g. `https://abc123.ngrok-free.app`).

---

## Current Implementation: GitHub Sandbox

The current sandbox provider uses GitHub as the execution environment — clone a repo, make changes, run commands, and open a PR.

### Tools

| Tool | Description |
|------|-------------|
| `list_repositories` | List GitHub repos accessible with the configured token |
| `clone_repository` | Clone a repo to `/tmp/sandcastle/<owner>/<repo>` |
| `read_file` | Read a file from a cloned repo |
| `edit_file` | Write/replace a file's content |
| `run_command` | Run a shell command inside a repo directory |
| `create_pr` | Commit changes, push a branch, and open a GitHub PR |

### Setup

```bash
export GITHUB_TOKEN=<your-token>
export GITHUB_USER=<your-username>
export PORT=3000  # optional, defaults to 3000

cargo run
```

The server starts at `http://0.0.0.0:3000` and speaks the [MCP Streamable HTTP](https://spec.modelcontextprotocol.io/specification/2025-03-26/basic/transports/#streamable-http) transport.

### Connecting an Agent

Point your MCP client at the server URL. For Claude Desktop or Claude Code:

```json
{
  "mcpServers": {
    "sandcastle": {
      "url": "http://localhost:3000"
    }
  }
}
```

### Example Agent Workflow

Once connected, an agent can:

1. Call `list_repositories` to see available repos
2. Call `clone_repository` with `"owner/repo"` to get a local copy
3. Call `read_file` and `edit_file` to make changes
4. Call `run_command` to build, test, or lint
5. Call `create_pr` to ship the result

## Roadmap

- Pluggable sandbox providers (Docker containers, VMs, E2B, Daytona)
- Per-session isolation
- Resource limits and timeouts
- Provider registration API

## License

See [LICENSE](LICENSE).
