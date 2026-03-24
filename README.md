# Sandcastle

An MCP server that gives AI agents access to sandboxed environments.

## The Idea

Running an LLM inside a sandbox is hard — you need to route its API calls, handle tool use, and manage the harness, all from within an isolated environment.

Sandcastle flips this around: **the LLM lives outside the sandbox and accesses it over MCP**. The agent connects to a Sandcastle instance and gets tools to interact with sandboxed environments — read/write files, run commands, manage secrets. The sandbox stays simple because it only needs to expose an interface, not host the model.

This works naturally with how LLMs operate: without tools, an LLM can only write text. With Sandcastle as the sole MCP server, what the agent can do is exactly what the sandbox allows — no more.

Because the agent is just an MCP client, it can run anywhere that supports MCP — Claude.ai, Claude Desktop, a CLI, a custom app.

```
┌─────────────────────────────────┐
│  Agent (Claude, GPT, etc.)      │
│  + Sandcastle MCP tools         │
└────────────────┬────────────────┘
                 │ MCP
         ┌───────▼───────┐
         │  Sandcastle   │
         │  MCP Server   │
         └───────┬───────┘
                 │
      ┌──────────▼──────────┐
      │  Sandbox Provider   │
      │  local / Docker /   │
      │  Daytona            │
      └─────────────────────┘
```

## Quick Start

### 1. Run

```bash
docker run -p 3000:3000 \
  -e SANDCASTLE_NO_AUTH=1 \
  -e SANDCASTLE_PROVIDERS=local \
  ghcr.io/metalbear-co/sandcastle:nightly
```

Or build from source:

```bash
cargo install --path crates/sandcastle
SANDCASTLE_NO_AUTH=1 SANDCASTLE_PROVIDERS=local sandcastle
```

### 2. Connect your MCP client

```json
{
  "mcpServers": {
    "sandcastle": {
      "url": "http://localhost:3000"
    }
  }
}
```

> **Tip:** MCP clients like Claude.ai need to reach Sandcastle over HTTPS. Use [ngrok](https://ngrok.com) to expose a public URL and set `BASE_URL` to the ngrok address.

## Configuration

See [CONFIGURATION.md](CONFIGURATION.md) for all environment variables.

See [ARCHITECTURE.md](ARCHITECTURE.md) for a full description of components and deployment modes.

## License

See [LICENSE](LICENSE).
