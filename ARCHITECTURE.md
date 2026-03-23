# Architecture

Sandcastle is an MCP server that gives AI clients a set of tools to create and use sandboxes — isolated environments where they can read/write files and run shell commands. Clients connect over HTTP and interact exclusively through MCP tool calls.

## Components

```
┌──────────────────────┐        ┌───────────────────────────────────────────┐
│      MCP Client      │──────▶ │                MCP Server                 │
│  (Claude Desktop,    │        │                                           │
│   claude.ai,         │        │   ┌─────────┐      ┌───────────────────┐ │
│   ChatGPT, ...)      │        │   │  Auth   │─────▶│ Sandbox Providers │ │
└──────────────────────┘        │   └─────────┘  │   │  local / Docker / │ │
                                │                │   │     Daytona       │ │
                                │                │   └───────────────────┘ │
                                │                │   ┌───────────────────┐ │
                                │                └──▶│   Secret Store    │ │
                                │                    └───────────────────┘ │
                                └───────────────────────────────────────────┘
```

### MCP Server

The core of sandcastle. It exposes an MCP-compliant HTTP endpoint and translates incoming tool calls (`create_sandbox`, `run_command`, `read_file`, etc.) into operations on the other components. It also tracks which sandbox belongs to which client.

### Auth

Every request is authenticated before reaching any tool. Auth validates the client's identity and attaches it to the request so that sandbox and secret operations are always scoped to the correct owner. Sandcastle supports OAuth2 (with an optional approval password), a pre-shared token via environment variable, and a no-auth mode for local development.

### Sandbox Providers

Providers are pluggable backends that create and manage sandboxes. Each sandbox is an isolated environment that supports file operations and command execution. Three providers ship out of the box:

- **Local** — sandboxes are directories on the host filesystem; commands run as local processes.
- **Docker** — each sandbox is a container; operations execute via `docker exec`.
- **Daytona** — sandboxes are managed remotely by the Daytona cloud API.

All providers expose the same interface, so the rest of the server is backend-agnostic.

### Secret Store

Users can store sensitive values (API keys, tokens, etc.) without passing them through the AI client. The server issues a one-time URL; the user submits the secret value directly in their browser or via `curl`. Stored secrets can then be injected as environment variables when running a command, and are never returned in tool responses.
