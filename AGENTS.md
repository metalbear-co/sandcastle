## Validation

After making changes, run:

```
cargo fmt
cargo clippy
```

## Coding Guidelines

- Do NOT use .unwrap() in production code.
- Always handle errors gracefully using Result, Option, or safe fallbacks.
- Prefer .ok(), .map(), .and_then(), or explicit error propagation over panicking.
- All new code must avoid panics unless explicitly justified (e.g. tests or unreachable invariants).

## Architecture

Sandcastle's component model is documented in `ARCHITECTURE.md`.

- All changes must stay consistent with the architecture described there.
- If a change introduces a new component type or meaningfully alters how existing components relate, update `ARCHITECTURE.md` — but confirm with the user before doing so.
- Any abstraction that is generic and could have multiple backends (store, secrets, sandbox providers, etc.) must follow the split-crate pattern: one trait-only crate + one crate per implementation.

## Style

- Commit messages: short lowercase freeform phrase, no period (e.g. `list_secrets`, `cleanup docker containers`). No conventional-commit prefixes unless asked.
- Always run `cargo fmt && cargo clippy` after code changes.
- Do not add docstrings or comments to code you didn't change.
- Responses: terse. No preamble, no trailing summaries.
