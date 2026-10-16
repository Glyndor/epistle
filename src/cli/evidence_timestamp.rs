//! `epistle evidence timestamp show|enable|disable`.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use serde_json::json;

use super::evidence::TimestampCli;
use super::term::sanitize;
use crate::evidence::ack::Operator;
use crate::evidence::tsa::settings::{self, Authority, Settings};

/// Run one timestamp action.
pub(super) fn run(root: &Path, action: TimestampCli, out: &mut impl Write) -> ExitCode {
	match action {
		TimestampCli::Show { json } => show(root, json, out),
		TimestampCli::Enable {
			urls,
			anchors,
			policy,
			token_file,
			json,
		} => {
			let settings = match urls.is_empty() {
				true => Settings::default(),
				false => Settings {
					enabled: true,
					authorities: urls
						.into_iter()
						.map(|url| Authority {
							url,
							anchors: anchors
								.iter()
								.map(|anchor| anchor.to_ascii_lowercase())
								.collect(),
							policy: policy.clone(),
							local_test: false,
							token_file: token_file.clone(),
						})
						.collect(),
				},
			};
			change(root, &settings, json, out)
		}
		TimestampCli::Disable { yes, json } => {
			let question = "Disable timestamps? Days sealed from now on rest on the evidence key alone, \
			                which the operator holds. The change is recorded in the evidence. [y/N] ";
			if let Err(code) =
				super::prompt::confirm_destructive("disabling timestamps", question, yes)
			{
				return code;
			}
			let authorities = settings::load(root)
				.map(|kept| kept.authorities)
				.unwrap_or_default();
			change(
				root,
				&Settings {
					enabled: false,
					authorities,
				},
				json,
				out,
			)
		}
	}
}

fn hosts(settings: &Settings) -> Vec<String> {
	settings
		.authorities
		.iter()
		.map(Authority::display)
		.collect()
}

fn show(root: &Path, as_json: bool, out: &mut impl Write) -> ExitCode {
	let current = match settings::load(root) {
		Ok(current) => current,
		Err(error) => {
			super::style::error(format_args!("timestamp settings refused: {}", error.kind()));
			return ExitCode::FAILURE;
		}
	};
	if as_json {
		let authorities: Vec<_> = current
			.authorities
			.iter()
			.map(|authority| {
				json!({
					"host": authority.display(),
					"anchors": authority.anchors,
					"policy": authority.policy,
					"token_file": authority.token_file.is_some(),
				})
			})
			.collect();
		return super::evidence::json(
			out,
			&json!({ "enabled": current.enabled, "authorities": authorities }),
		);
	}
	let _ = writeln!(
		out,
		"timestamps {}; authorities: {}",
		if current.enabled {
			"enabled"
		} else {
			"DISABLED"
		},
		sanitize(&hosts(&current).join(", "))
	);
	ExitCode::SUCCESS
}

fn change(root: &Path, settings: &Settings, as_json: bool, out: &mut impl Write) -> ExitCode {
	if let Err(error) = settings.validate() {
		return super::exit::refused(sanitize(&error.0));
	}
	let operator = match Operator::current(root) {
		Ok(operator) => operator,
		Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
			return super::exit::refused(error);
		}
		Err(error) => {
			super::style::error(format_args!("evidence: {}", error.kind()));
			return ExitCode::FAILURE;
		}
	};
	if let Err(error) = settings::record_change(root, settings, operator.as_str()) {
		super::style::error(format_args!("timestamp settings: {}", error.kind()));
		return ExitCode::FAILURE;
	}
	if as_json {
		return super::evidence::json(
			out,
			&json!({ "enabled": settings.enabled, "authorities": hosts(settings) }),
		);
	}
	let _ = match settings.enabled {
		true => writeln!(
			out,
			"timestamps enabled: {}",
			sanitize(&hosts(settings).join(", "))
		),
		false => writeln!(out, "timestamps disabled; recorded in the evidence"),
	};
	ExitCode::SUCCESS
}
