//! `--json` on the commands that change something: the real binary prints
//! one JSON object on stdout and nothing else there, whatever it says on
//! stderr. One file per resource under `tests/cli_json/`.

#[path = "cli_json/harness.rs"]
mod harness;

#[path = "cli_json/account.rs"]
mod account;

#[path = "cli_json/config_edits.rs"]
mod config_edits;

#[path = "cli_json/alias_domain.rs"]
mod alias_domain;
