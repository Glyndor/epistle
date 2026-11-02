//! The commands that steer or read outbound delivery: `queue`, `warmup`,
//! `delivery` and `suppression`. Split from `mod.rs`, which keeps the
//! exhaustive match over `Command`.

use std::path::Path;
use std::process::ExitCode;

use crate::cli::{delivery, queue, style, suppression, warmup};
use crate::config::Config;

pub(super) fn queue(config: &Path, json: bool, action: Option<queue::QueueCli>) -> ExitCode {
	match Config::load(config) {
		Ok(config) => {
			let webhook = queue::webhook_for(&config);
			queue::run(
				&config.data_dir,
				config.storage.as_ref(),
				config.delivery_log_days(),
				action,
				json,
				queue::now_epoch(),
				webhook.as_ref(),
				&mut std::io::stdout().lock(),
			)
		}
		Err(error) => {
			style::error(error);
			ExitCode::FAILURE
		}
	}
}

pub(super) fn warmup(config: &Path, action: warmup::WarmupCli) -> ExitCode {
	match Config::load(config) {
		Ok(config) => warmup::run(
			&config.data_dir,
			config.storage.as_ref(),
			config.delivery_log_days(),
			&crate::queue::warmup::relay_hosts(&config.transport),
			action,
			queue::now_epoch(),
			&mut std::io::stdout().lock(),
		),
		Err(error) => {
			style::error(error);
			ExitCode::FAILURE
		}
	}
}

pub(super) fn delivery(args: delivery::DeliveryConfig) -> ExitCode {
	match Config::load(&args.config) {
		Ok(config) => delivery::run(
			&config.data_dir,
			config.delivery_log_days(),
			args.into_action(),
			queue::now_epoch(),
			&mut std::io::stdout().lock(),
		),
		Err(error) => {
			style::error(error);
			ExitCode::FAILURE
		}
	}
}

pub(super) fn suppression(
	config: &Path,
	json: bool,
	action: Option<suppression::SuppressionCli>,
	remove: Option<String>,
	account: Option<String>,
) -> ExitCode {
	match Config::load(config) {
		Ok(config) => match suppression::SuppressionCli::with_json(
			action,
			json,
			remove.clone(),
			account.clone(),
		) {
			Some(action) => suppression::run(&config, action, &mut std::io::stdout().lock()),
			None => suppression::run_legacy(
				&config,
				remove.as_deref(),
				account.as_deref(),
				&mut std::io::stdout().lock(),
			),
		},
		Err(error) => {
			style::error(error);
			ExitCode::FAILURE
		}
	}
}
