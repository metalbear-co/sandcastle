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
