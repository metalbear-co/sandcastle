# Configuration

Sandcastle is configured via environment variables.

## Server

| Variable | Values | Default | Purpose |
|----------|--------|---------|---------|
| `PORT` | number | `3000` | HTTP listen port |
| `BASE_URL` | URL | `http://localhost:PORT` | Public base URL for OAuth redirects |

## Sandbox Providers

| Variable | Values | Default | Purpose |
|----------|--------|---------|---------|
| `SANDCASTLE_PROVIDERS` | `local`, `docker`, `daytona` (comma-separated) | prompts interactively | Sandbox providers to enable |

## Auth

| Variable | Values | Default | Purpose |
|----------|--------|---------|---------|
| `SANDCASTLE_NO_AUTH` | any value | unset | Disable auth entirely (local dev) |
| `AUTH_PROVIDER` | `local`, `github`, `google` | `local` | OAuth identity provider |
| `MCP_TOKEN` | string | — | Pre-shared bearer token |
| `SANDCASTLE_PASSWORD` | string | — | Optional password for local OAuth approval |
| `GITHUB_OAUTH_CLIENT_ID` | string | — | Required when `AUTH_PROVIDER=github` |
| `GITHUB_OAUTH_CLIENT_SECRET` | string | — | Required when `AUTH_PROVIDER=github` |
| `GOOGLE_CLIENT_ID` | string | — | Required when `AUTH_PROVIDER=google` |
| `GOOGLE_CLIENT_SECRET` | string | — | Required when `AUTH_PROVIDER=google` |

## Storage

| Variable | Values | Default | Purpose |
|----------|--------|---------|---------|
| `STORAGE_BACKEND` | `memory`, `postgres` | `memory` | State store backend |
| `DATABASE_URL` | postgres connection string | — | Required when `STORAGE_BACKEND=postgres` |

## Secrets

| Variable | Values | Default | Purpose |
|----------|--------|---------|---------|
| `SECRET_BACKEND` | `memory`, `gcp` | `memory` | User secret backend |
| `GCP_PROJECT_ID` | string | — | Required when `SECRET_BACKEND=gcp` |
