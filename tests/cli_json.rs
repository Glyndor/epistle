//! `--json` on the commands that change something: the real binary prints
//! one JSON object on stdout and nothing else there, whatever it says on
//! stderr. One file per resource under `tests/cli_json/`.

#[path = "cli_json/harness.rs"]
mod harness;

#[path = "cli_json/account.rs"]
mod account;
