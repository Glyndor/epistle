//! `epistle dkim rotate --domain D`: rotate one domain's own key now.
//!
//! Like `dkim rotate`, it never rotates by itself. It checks what the server
//! checks before rotating that domain and leaves a request in the domain's
//! key directory, which the server's rotation of the domain serves within a
//! minute (`dkim::domain_rotate`).

use std::process::ExitCode;

use crate::cli::serve::tasks::DnsWrite;
use crate::config::Config;
use crate::dkim::domain_rotate;

/// What a requested rotation of one domain would do.
#[derive(Debug, PartialEq, Eq)]
pub(in crate::cli) struct DomainPlan {
	/// The selector in service and the one it rotates to.
	ed: (String, String),
	/// The RSA selector in service and the one it rotates to.
	rsa: Option<(String, String)>,
	/// The records published before the domain switches.
	names: Vec<String>,
	/// The replaced selector retired first, its overlap already over.
	retires: Option<String>,
}

/// The server's rules for rotating `name`'s key, checked up front.
pub(in crate::cli) fn preflight(
	config: &Config,
	name: &str,
	now: u64,
) -> Result<DomainPlan, String> {
	let dkim = config.dkim.as_ref().ok_or("[dkim] is not configured")?;
	let Some(entry) = dkim.override_for(name) else {
		return Err(format!(
			"{name} has no [[dkim.domain]] key and signs with the [dkim] default; rotate that with `epistle dkim rotate`"
		));
	};
	let domain = entry.name.to_ascii_lowercase();
	let plan =
		super::super::serve::tasks::decide_domain_rotation(config, &DnsWrite::for_install(config));
	if !plan.rotating.contains(&domain) {
		return Err(format!(
			"no [dns] entry can publish records at {domain} (none covers it, or its entry is manual or has no credential): its key does not rotate"
		));
	}
	let dir = domain_rotate::state_dir(&config.data_dir, &domain).map_err(|e| e.to_string())?;
	let state = domain_rotate::read_state(&dir).map_err(|e| e.to_string())?;
	let active = domain_rotate::active_keys(entry, &config.data_dir).map_err(|e| e.to_string())?;
	let mut retires = None;
	if let Some(previous) = state.as_ref().and_then(|s| s.previous.as_ref()) {
		if now < previous.retire_at {
			return Err(format!(
				"{} is still published until {} for mail signed before the last rotation; rotating before then would retire it early",
				previous.selector,
				crate::clock::rfc3339_or_epoch(previous.retire_at)
			));
		}
		retires = Some(previous.selector.clone());
	}
	let mut reserved = dkim.kept_selectors();
	reserved.extend(crate::dkim::domain_keys::reserved_selectors(config)?);
	let (next, next_rsa) =
		domain_rotate::next_selectors(entry, state.as_ref(), &reserved, active.rsa.is_some(), now);
	let rsa = active
		.rsa
		.map(|rsa| (rsa.selector, next_rsa.unwrap_or_default()));
	let names = std::iter::once(next.as_str())
		.chain(rsa.as_ref().map(|(_, next)| next.as_str()))
		.map(|selector| format!("{selector}._domainkey.{domain}"))
		.collect();
	Ok(DomainPlan {
		ed: (active.ed.selector, next),
		rsa,
		names,
		retires,
	})
}

/// Run `dkim rotate --domain name`.
pub(in crate::cli) fn rotate_domain(
	config: &Config,
	name: &str,
	dry_run: bool,
	now: u64,
	json: bool,
	err: &mut impl std::io::Write,
	out: &mut impl std::io::Write,
) -> ExitCode {
	let plan = match preflight(config, name, now) {
		Ok(plan) => plan,
		Err(reason) => {
			crate::cli::style::error_to(err, format_args!("dkim rotate --domain {name}: {reason}"));
			return ExitCode::FAILURE;
		}
	};
	let mut report = crate::cli::json_out::Report::new(out, json);
	if let Some(previous) = &plan.retires {
		report.line(format_args!(
			"retire {previous} first (its overlap is over)"
		));
	}
	report.line(format_args!("rotate {} -> {}", plan.ed.0, plan.ed.1));
	if let Some((active, next)) = &plan.rsa {
		report.line(format_args!("rotate {active} -> {next}"));
	}
	for record in &plan.names {
		report.line(format_args!("publish TXT {record}"));
	}
	let mut result = serde_json::json!({
		"result": "queued", "action": "rotate", "domain": name.to_ascii_lowercase(),
		"active": plan.ed.0, "next": plan.ed.1,
		"rsa": plan.rsa.as_ref().map(|(active, next)| serde_json::json!({ "active": active, "next": next })),
		"publish": plan.names, "retires": plan.retires,
	});
	if dry_run {
		report.line("dry run: nothing changed");
		result["result"] = "dry-run".into();
		return report.object(result);
	}
	if let Err(error) = domain_rotate::request_rotation(&config.data_dir, name, now) {
		crate::cli::style::error_to(
			err,
			format_args!("cannot write the rotation request: {error}"),
		);
		return ExitCode::FAILURE;
	}
	report.line(
		"queued: the running server rotates the domain's key within a minute (at its next start if it is stopped); follow it with `epistle dkim show`",
	);
	report.object(result)
}

#[cfg(test)]
mod tests;
