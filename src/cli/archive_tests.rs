//! Placeholder tests for the archive CLI. The behaviour is covered by
//! `imap::archive::tests` (the underlying module) and `api::v1::archive::tests`
//! (the HTTP surface); the CLI is a thin wrapper that the dispatch logic
//! delegates to. Real CLI integration tests would invoke the binary end-to-end
//! through the `Command` enum in `cli::tests`, which already covers every
//! other subcommand.
