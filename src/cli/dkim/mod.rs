//! `epistle dkim`: show the signing key in service, force a rotation and
//! clean up what old rotations left behind.
//!
//! Rotation is never done here. The running server is the only writer of the
//! key files, the DNS records and the rotation state, so `dkim rotate`
//! validates the same preconditions the server enforces and then drops a
//! request file the server serves within a minute (see `dkim::rotate`).

use std::process::ExitCode;

use clap::Subcommand;

use super::serve::tasks::{DkimRotationPlan, decide_dkim_rotation};
use crate::config::Config;
use crate::dkim::rotate::{self, rsa_selector_for, selector_for};

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
	/// signing domain before the server switches to it. With RSA dual
	/// signing the RSA key rotates in the same step, under `rsa<day>`.
	Rotate {
		/// Check the preconditions and print what would happen; change nothing.
		#[arg(long)]
		dry_run: bool,
		/// Always refused: a `[[dkim.domain]]` key does not rotate. The
		/// refusal says how to replace it, or that the domain signs with
		/// the default key, which `dkim rotate` without `--domain` rotates.
		#[arg(long)]
		domain: Option<String>,
	},
	/// Remove DKIM keys and TXT records no rotation uses.
	///
	/// List the `dkim-ed<day>.key` and `dkim-rsa<day>.key` files and the
	/// `ed<day>._domainkey` and `rsa<day>._domainkey` TXT records that
	/// neither the active, the previous nor a pending rotation names, then
	/// ask the running server to remove them.
	Cleanup {
		/// List what would be removed; change nothing.
		#[arg(long)]
		dry_run: bool,
		/// Do not ask for confirmation.
		#[arg(long)]
		yes: bool,
	},
}

pub(super) fn now_epoch() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}

/// Run one `dkim` action.
pub(super) fn run(
	config: &Config,
	action: DkimCli,
	json: bool,
	out: &mut impl std::io::Write,
) -> ExitCode {
	match action {
		DkimCli::Show { json: leaf } => show(config, leaf || json, out),
		DkimCli::Rotate { dry_run, domain } => {
			rotate_now(config, dry_run, now_epoch(), domain, json, out)
		}
		DkimCli::Cleanup { dry_run, yes } => cleanup::cleanup(config, dry_run, yes, json, out),
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
	match runtime.block_on(show::build(config, Some(dns))) {
		Ok(view) => show::render(&view, json, out),
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
	/// The RSA selector in service and the one it rotates to.
	rsa: Option<(String, String)>,
	names: Vec<String>,
	retires: Option<String>,
}

/// The rules the server applies before it rotates, checked up front so the
/// operator hears a refusal now instead of finding it in the server log.
pub(super) fn preflight(config: &Config, now: u64) -> Result<Plan, String> {
	let dkim = config.dkim.as_ref().ok_or("[dkim] is not configured")?;
	if config.dns.is_empty() {
		return Err("[dns] is not configured: the new key could not be published".into());
	}
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
			config.dns.zones().join(", ")
		));
	}
	if signing_domains.is_empty() {
		return Err("no signing domain is configured, so nothing could be published".to_string());
	}
	// Every signing domain is published through the entry of its own zone,
	// so each of those entries has to build.
	for domain in &signing_domains {
		let buildable = config
			.dns
			.entry_for(domain)
			.is_some_and(|dns| dns.build().is_some());
		if !buildable {
			return Err(
				"the [dns] provider cannot be built (missing or empty credentials)".to_string(),
			);
		}
	}
	let active = rotate::active_ed25519(dkim, &config.data_dir).map_err(|e| e.to_string())?;
	let next = selector_for(now);
	if next == active.selector {
		return Err(format!(
			"selector {next} is already active; a second rotation on the same UTC day would reuse its name"
		));
	}
	let rsa = rotate::active_rsa(dkim, &config.data_dir)
		.map_err(|e| e.to_string())?
		.map(|rsa| (rsa.selector, rsa_selector_for(now)));
	let retires = rotate::read_state(&config.data_dir)
		.map_err(|e| e.to_string())?
		.and_then(|state| state.previous)
		.map(|previous| match previous.rsa {
			Some(rsa) => format!("{} and {}", previous.selector, rsa.selector),
			None => previous.selector,
		});
	let selectors = std::iter::once(next.as_str()).chain(rsa.as_ref().map(|(_, n)| n.as_str()));
	let names = selectors
		.flat_map(|selector| {
			signing_domains
				.iter()
				.map(move |domain| format!("{selector}._domainkey.{domain}"))
		})
		.collect();
	Ok(Plan {
		names,
		active: active.selector,
		next,
		rsa,
		retires,
	})
}

pub(super) fn rotate_now(
	config: &Config,
	dry_run: bool,
	now: u64,
	domain: Option<String>,
	json: bool,
	out: &mut impl std::io::Write,
) -> ExitCode {
	rotate_now_with(
		config,
		dry_run,
		now,
		domain,
		json,
		&mut super::style::stderr(),
		out,
	)
}

/// The real `rotate_now`, with a caller-supplied error writer. Lives
/// separately so a test can assert on the exact refusal text without
/// going through the process boundary.
pub(super) fn rotate_now_with(
	config: &Config,
	dry_run: bool,
	now: u64,
	domain: Option<String>,
	json: bool,
	err: &mut impl std::io::Write,
	out: &mut impl std::io::Write,
) -> ExitCode {
	if let Some(name) = domain.as_deref() {
		// A `[[dkim.domain]]` key is not rotated (the rotation journal
		// covers the default key only), so refuse instead of rotating the
		// default under a name the operator did not mean.
		let has_override = config
			.dkim
			.as_ref()
			.is_some_and(|dkim| dkim.override_for(name).is_some());
		let reason = if has_override {
			format!(
				"per-domain keys do not rotate; replace the key of [[dkim.domain]] {name} in the \
				 configuration file, publish its record (epistle dns-records) and restart the server"
			)
		} else {
			format!(
				"{name} has no [[dkim.domain]] key and signs with the [dkim] default; \
				 rotate that with `epistle dkim rotate`"
			)
		};
		super::style::error_to(err, format_args!("dkim rotate --domain {name}: {reason}"));
		return ExitCode::FAILURE;
	}
	let plan = match preflight(config, now) {
		Ok(plan) => plan,
		Err(reason) => {
			super::style::error_to(err, format_args!("dkim rotate refused: {reason}"));
			return ExitCode::FAILURE;
		}
	};
	let mut report = super::json_out::Report::new(out, json);
	report.line(format_args!("rotate {} -> {}", plan.active, plan.next));
	if let Some((active, next)) = &plan.rsa {
		report.line(format_args!("rotate {active} -> {next}"));
	}
	for name in &plan.names {
		report.line(format_args!("publish TXT {name}"));
	}
	if let Some(previous) = &plan.retires {
		report.line(format_args!(
			"retire {previous} now (older than the selector being replaced)"
		));
	}
	let mut result = serde_json::json!({
		"result": "queued", "action": "rotate", "active": plan.active, "next": plan.next,
		"rsa": plan.rsa.as_ref().map(|(active, next)| serde_json::json!({ "active": active, "next": next })),
		"publish": plan.names, "retires": plan.retires,
	});
	if dry_run {
		report.line("dry run: nothing changed");
		result["result"] = "dry-run".into();
		return report.object(result);
	}
	if let Err(error) = rotate::request_rotation(&config.data_dir, now) {
		super::style::error_to(
			err,
			format_args!("cannot write the rotation request: {error}"),
		);
		return ExitCode::FAILURE;
	}
	report.line(
		"queued: the running server rotates within a minute (at its next start if it is stopped); follow it with `epistle dkim show`",
	);
	report.object(result)
}

mod cleanup;
mod show;

#[cfg(test)]
mod tests;
