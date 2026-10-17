//! `--json` on the commands that change something: the real binary prints
//! one JSON object on stdout and nothing else there, whatever it says on
//! stderr. One file per resource under `tests/cli_json/`.

#[path = "cli_json/harness.rs"]
mod harness;

#[path = "cli_json/account.rs"]
mod account;

#[path = "cli_json/config_edits.rs"]
mod config_edits;

#[path = "cli_json/attachments.rs"]
mod attachments;

#[path = "cli_json/alias_domain.rs"]
mod alias_domain;

#[path = "cli_json/stores.rs"]
mod stores;

#[path = "cli_json/stack.rs"]
mod stack;

#[path = "cli_json/top_level.rs"]
mod top_level;

#[path = "cli_json/exit_codes.rs"]
mod exit_codes;

#[path = "cli_json/ban.rs"]
mod ban;

#[path = "cli_json/legacy.rs"]
mod legacy;

#[path = "cli_json/dkim.rs"]
mod dkim;

#[path = "cli_json/default_actions.rs"]
mod default_actions;

#[path = "cli_json/limits.rs"]
mod limits;

#[path = "cli_json/integrity.rs"]
mod integrity;

#[path = "cli_json/init.rs"]
mod init;

#[path = "cli_json/sweep.rs"]
mod sweep;

#[path = "cli_json/domain_state.rs"]
mod domain_state;
