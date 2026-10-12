//! `epistle dkim`: show the signing key in service and force a rotation.
//!
//! Rotation is never done here. The running server is the only writer of the
//! key files, the DNS records and the rotation state, so `dkim rotate`
//! validates the same preconditions the server enforces and then drops a
//! request file the server serves within a minute (see `dkim::rotate`).

use std::process::ExitCode;

use clap::Subcommand;

use super::serve_tasks::{DkimRotationPlan, decide_dkim_rotation};
use crate::config::Config;
use crate::dkim::rotate::{self, selector_for};

/// Actions of `epistle dkim`.
#[derive(Debug, Subcommand)]
pub enum DkimCli {
	/// Show the signing key in service and its next rotation.
	///
	/// Show the signing key in service, the next rotation and whether the
	/// published TXT records match it.
	Show {
		/// Print one JSON object instead of text lines.
		#[arg(long)]
		json: bool,
	},
	/// Rotate the signing key now.
	///
	/// Rotate the signing key now, publishing the new TXT record for every
	/// signing domain before the server switches to it.
	Rotate {
		/// Check the preconditions and print what would happen; change nothing.
		#[arg(long)]
		dry_run: bool,
	},
}

pub(super) fn now_epoch() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}

/// Run one `dkim` action.
pub(super) fn run(config: &Config, action: DkimCli, out: &mut impl std::io::Write) -> ExitCode {
	match action {
		DkimCli::Show { json } => show(config, json, out),
		DkimCli::Rotate { dry_run } => rotate_now(config, dry_run, now_epoch(), out),
	}
}

fn show(config: &Config, json: bool, out: &mut impl std::io::Write) -> ExitCode {
	let dns = match crate::spf::SystemDns::from_system() {
		Ok(dns) => dns,
		Err(error) => {
			super::style::error(format_args!("cannot start resolver: {error}"));
			return ExitCode::FAILURE;
		}
	};
	let runtime = match tokio::runtime::Runtime::new() {
		Ok(runtime) => runtime,
		Err(error) => {
			super::style::error(format_args!("cannot start async runtime: {error}"));
			return ExitCode::FAILURE;
		}
	};
	show_with(config, json, &dns, &runtime, out)
}

pub(super) fn show_with(
	config: &Config,
	json: bool,
	dns: &dyn crate::spf::DnsLookup,
	runtime: &tokio::runtime::Runtime,
	out: &mut impl std::io::Write,
) -> ExitCode {
	match runtime.block_on(super::dkim_show::build(config, Some(dns))) {
		Ok(view) => super::dkim_show::render(&view, json, out),
		Err(error) => {
			super::style::error(error);
			ExitCode::FAILURE
		}
	}
}

/// What a forced rotation would do, after the server's own preconditions.
pub(super) struct Plan {
	active: String,
	next: String,
	names: Vec<String>,
	retires: Option<String>,
}

/// The rules the server applies before it rotates, checked up front so the
/// operator hears a refusal now instead of finding it in the server log.
pub(super) fn preflight(config: &Config, now: u64) -> Result<Plan, String> {
	let dkim = config.dkim.as_ref().ok_or("[dkim] is not configured")?;
	let dns = config
		.dns
		.as_ref()
		.ok_or("[dns] is not configured: the new key could not be published")?;
	let DkimRotationPlan::Run {
		signing_domains,
		out_of_zone,
		..
	} = decide_dkim_rotation(config)
	else {
		return Err("rotation is off for this configuration".to_string());
	};
	if !out_of_zone.is_empty() {
		return Err(format!(
			"signing domain(s) {} lie outside the [dns] zone {}: their TXT records cannot be kept in sync",
			out_of_zone.join(", "),
			dns.zone
		));
	}
	if signing_domains.is_empty() {
		return Err("no signing domain is configured, so nothing could be published".to_string());
	}
	if dns.build().is_none() {
		return Err(
			"the [dns] provider cannot be built (missing or empty credentials)".to_string(),
		);
	}
	let active = rotate::active_ed25519(dkim, &config.data_dir).map_err(|e| e.to_string())?;
	let next = selector_for(now);
	if next == active.selector {
		return Err(format!(
			"selector {next} is already active; a second rotation on the same UTC day would reuse its name"
		));
	}
	let retires = rotate::read_state(&config.data_dir)
		.map_err(|e| e.to_string())?
		.and_then(|state| state.previous)
		.map(|previous| previous.selector);
	Ok(Plan {
		names: signing_domains
			.iter()
			.map(|domain| format!("{next}._domainkey.{domain}"))
			.collect(),
		active: active.selector,
		next,
		retires,
	})
}

pub(super) fn rotate_now(
	config: &Config,
	dry_run: bool,
	now: u64,
	out: &mut impl std::io::Write,
) -> ExitCode {
	let plan = match preflight(config, now) {
		Ok(plan) => plan,
		Err(reason) => {
			super::style::error(format_args!("dkim rotate refused: {reason}"));
			return ExitCode::FAILURE;
		}
	};
	let _ = writeln!(out, "rotate {} -> {}", plan.active, plan.next);
	for name in &plan.names {
		let _ = writeln!(out, "publish TXT {name}");
	}
	if let Some(previous) = &plan.retires {
		let _ = writeln!(
			out,
			"retire {previous} now (older than the selector being replaced)"
		);
	}
	if dry_run {
		let _ = writeln!(out, "dry run: nothing changed");
		return ExitCode::SUCCESS;
	}
	if let Err(error) = rotate::request_rotation(&config.data_dir, now) {
		super::style::error(format_args!("cannot write the rotation request: {error}"));
		return ExitCode::FAILURE;
	}
	let _ = writeln!(
		out,
		"queued: the running server rotates within a minute (at its next start if it is stopped); follow it with `epistle dkim show`"
	);
	ExitCode::SUCCESS
}

#[cfg(test)]
#[path = "dkim_cli_tests.rs"]
mod tests;
