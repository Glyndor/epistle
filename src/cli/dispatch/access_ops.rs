//! The commands that decide who gets in and over what channel: `ban`,
//! `masked` and `tls`. Split from `mod.rs`, which keeps the exhaustive
//! match over `Command`.

use std::path::Path;
use std::process::ExitCode;

use crate::cli::term::live;
use crate::cli::tls::cli as tls_cli;
use crate::cli::{ban, masked, style};
use crate::config::Config;

pub(super) fn ban(config: &Path, json: bool, action: ban::BanCli) -> ExitCode {
	match Config::load(config) {
		Ok(config) => ban::run(
			&config,
			action,
			json,
			ban::now_epoch(),
			&mut std::io::stdout().lock(),
			&mut style::stderr(),
		),
		Err(error) => {
			style::error(error);
			ExitCode::FAILURE
		}
	}
}

pub(super) fn masked(config: &Path, json: bool, action: masked::MaskedCli) -> ExitCode {
	match Config::load(config) {
		Ok(config) => masked::run(
			&config,
			action,
			json,
			ban::now_epoch(),
			&mut std::io::stdout().lock(),
			&mut style::stderr(),
		),
		Err(error) => {
			style::error(error);
			ExitCode::FAILURE
		}
	}
}

pub(super) fn tls(config: &Path, json: bool, action: tls_cli::TlsCli) -> ExitCode {
	match Config::load(config) {
		Ok(config) => match action {
			action @ tls_cli::TlsCli::Renew { .. } => live::run("tls renew", json, |mut out| {
				tls_cli::run(&config, action, json, &mut out)
			}),
			action => tls_cli::run(&config, action, json, &mut std::io::stdout().lock()),
		},
		Err(error) => {
			style::error(error);
			ExitCode::FAILURE
		}
	}
}
