//! `--json` on the commands that change something: the real binary prints
//! one JSON object on stdout and nothing else there, whatever it says on
//! stderr. One file per resource under `tests/cli/json/cli_json/`.

#[path = "cli_json/harness.rs"]
mod harness;

#[path = "cli_json/accounts/account.rs"]
mod account;

#[path = "cli_json/operator/config_edits.rs"]
mod config_edits;

#[path = "cli_json/delivery/attachments.rs"]
mod attachments;

#[path = "cli_json/accounts/alias_domain.rs"]
mod alias_domain;

#[path = "cli_json/operator/stores.rs"]
mod stores;

#[path = "cli_json/delivery/evidence.rs"]
mod evidence;

#[path = "cli_json/operator/stack.rs"]
mod stack;

#[path = "cli_json/operator/top_level.rs"]
mod top_level;

#[path = "cli_json/operator/exit_codes.rs"]
mod exit_codes;

#[path = "cli_json/accounts/ban.rs"]
mod ban;

#[path = "cli_json/delivery/learning.rs"]
mod learning;

#[path = "cli_json/operator/legacy.rs"]
mod legacy;

#[path = "cli_json/delivery/dkim.rs"]
mod dkim;

#[path = "cli_json/operator/default_actions.rs"]
mod default_actions;

#[path = "cli_json/operator/limits.rs"]
mod limits;

#[path = "cli_json/operator/integrity.rs"]
mod integrity;

#[path = "cli_json/operator/init.rs"]
mod init;

#[path = "cli_json/operator/sweep.rs"]
mod sweep;

#[path = "cli_json/accounts/domain_state.rs"]
mod domain_state;

#[path = "cli_json/accounts/domain_set.rs"]
mod domain_set;

#[path = "cli_json/operator/alert_state.rs"]
mod alert_state;

#[path = "cli_json/delivery/webhook_state.rs"]
mod webhook_state;

#[path = "cli_json/delivery/relay_state.rs"]
mod relay_state;

#[path = "cli_json/delivery/suppression_b.rs"]
mod suppression_b;

#[path = "cli_json/accounts/app_password_b.rs"]
mod app_password_b;

#[path = "cli_json/delivery/delivery_b.rs"]
mod delivery_b;

#[path = "cli_json/operator/db_status.rs"]
mod db_status;

#[path = "cli_json/delivery/queue_webhook.rs"]
mod queue_webhook;

#[path = "cli_json/accounts/domain_disabled_use.rs"]
mod domain_disabled_use;
