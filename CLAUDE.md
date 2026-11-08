# traysis

Free, open-source (Apache-2.0) endpoint visibility tool for Linux and macOS
fleets: live inventory, CVE awareness, fast fleet queries. Written in Rust.

## Scope
- Linux first, then macOS. Windows is a non-goal for now.
- No P2P in core. Agents keep local state and push deltas to a server that
  holds a live inventory; live fan-out is only for ad hoc queries. Peer relay
  or caching is an optional later feature, justified by measurements.
- Read-only by default. No arbitrary remote command execution without a
  written design review.

## Architecture
- crates/proto: wire types. crates/agent: endpoint daemon. crates/server.
- Platform-specific collection lives only behind the `Collector` trait.
  Protocol and server code stay platform-agnostic.

## Security rules
- Agent-server channel uses mutual TLS; queries and commands are signed.
- Never log secrets; redact command lines.
- Code that parses untrusted input needs tests with malformed input.

## Code standards
- No `unwrap()` outside tests; `expect()` only with a message stating the invariant.
- `unsafe` is denied workspace-wide. Allowing it in a platform crate needs a
  `// SAFETY:` comment and a note in the PR.
- New dependencies must be justified in the PR and pass `cargo deny check`
  (permissive licenses only).
- Work on branches in small PRs. Never push directly to main.

## Before every PR (all must pass)
    cargo fmt --all
    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace
    cargo deny check

## Gotchas
- Create crates with `cargo new --vcs none` to avoid nested git repos.

## Cross-platform checks
- Anything gated with `cfg(target_os = "linux")` needs its test-only imports
  gated the same way. Otherwise the unused imports fail clippy on macOS.
- Before every PR we also run this (after `rustup target add aarch64-apple-darwin`):

      cargo clippy --workspace --exclude traysis-server --all-targets --target aarch64-apple-darwin -- -D warnings

  `traysis-server` is excluded because its bundled SQLite compiles C code for
  the target, which fails when cross-checking from Linux without a macOS C
  toolchain. CI's native macOS leg builds and lints the server crate.
