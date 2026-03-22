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
