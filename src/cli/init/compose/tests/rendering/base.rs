//! Tests for the compose file the `init` apply phase writes. The
//! production writer lives in [`src/cli/init/compose/mod.rs`](super); this file
//! documents the shared setup. `src/cli/init/compose/tests/mod.rs` declares
//! the topic-specific suites.
//! The `render` helper that turns the writer's bytes into a
//! `serde_json::Value` lives next to the production writer in
//! `src/cli/init/compose/mod.rs` so every test reaches it through `super::render`.
