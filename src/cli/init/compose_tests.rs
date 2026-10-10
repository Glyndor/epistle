//! Tests for the compose file the `init` apply phase writes. The
//! production writer lives in [`compose.rs`](super); this file
//! keeps the topic-split siblings wired up and hosts nothing else.
//! The `render` helper that turns the writer's bytes into a
//! `serde_json::Value` lives next to the production writer in
//! `compose.rs` so every test reaches it through `super::render`.
