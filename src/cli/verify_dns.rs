//! `epistle verify-dns`: query the live DNS for each configured domain and
//! report drift from the records epistle expects. Read-only.

use std::process::ExitCode;

use anstyle::Style;

use crate::cli::term::live::{Steps, quiet};
use crate::cli::term::{self, Decor};
use crate::config::Config;
use crate::dns::{self, Status};
use crate::spf::{DnsLookup, SystemDns};

/// Run the DNS check against the system resolver.
pub(super) fn run(config: &Config, out: &mut impl std::io::Write) -> ExitCode {
	run_with_writers(config, out, &mut super::style::stderr())
}

/// Same as [`run`], but writes the startup warnings (and any errors
/// during resolver construction) to a caller-supplied stream. Lives
/// separately so a test can assert on the warning text without forking
/// the process.
pub(super) fn run_with_writers(
	config: &Config,
	out: &mut impl std::io::Write,
	err: &mut impl std::io::Write,
) -> ExitCode {
	emit_single_signature_warning(config, err);
	let dns = match SystemDns::from_system() {
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
	let selectors = match dkim_selectors(config) {
		Ok(selectors) => selectors,
		Err(error) => {
			super::style::error(format_args!("{error}"));
			return ExitCode::FAILURE;
		}
	};
	let progress = crate::cli::style::Progress::start("checking");
	runtime.block_on(report(
		&config.domains,
		&config.hostname,
		config.public_ipv4,
		config.public_ipv6,
		&selectors,
		&dns,
		out,
		progress,
	))
}

/// Write the single-signature DKIM warning to `err` when the configuration
/// would otherwise sign outbound mail with one key only. Lives here so
/// `verify-dns` and `config-check` can share the call site, and so a
/// test can capture it through an in-memory writer without going through
/// the process boundary.
pub(super) fn emit_single_signature_warning(config: &Config, err: &mut impl std::io::Write) {
	if let Some(warning) = super::serve_tasks::single_signature_dkim_warning(config) {
		super::style::warn_to(err, warning);
	}
}

/// The DKIM selectors epistle publishes (the Ed25519 selector plus an optional
/// RSA selector), used to locate the `_domainkey` records. The Ed25519
/// selector is the one the rotator currently has in service when the
/// rotation state file exists, falling back to the configured selector at
/// startup before the first tick has run. The RSA selector follows the same
/// rule through [`crate::dkim::rotate::active_rsa`].
pub(super) fn dkim_selectors(
	config: &Config,
) -> Result<Vec<String>, crate::dkim::rotate::RotateError> {
	let Some(dkim) = &config.dkim else {
		return Ok(Vec::new());
	};
	let mut selectors = vec![crate::dkim::rotate::active_ed25519(dkim, &config.data_dir)?.selector];
	if let Some(rsa) = crate::dkim::rotate::active_rsa(dkim, &config.data_dir)? {
		selectors.push(rsa.selector);
	}
	Ok(selectors)
}

/// Check the hostname's addresses and their reverse DNS first, then every
/// domain. The exit code is failure if any expected record is missing (lookup
/// errors are inconclusive, not failures). Each check rewrites the progress
/// line on stderr so a long run does not look stuck.
#[allow(clippy::too_many_arguments)]
async fn report(
	domains: &[String],
	hostname: &str,
	public_ipv4: Option<std::net::Ipv4Addr>,
	public_ipv6: Option<std::net::Ipv6Addr>,
	selectors: &[String],
	dns: &dyn DnsLookup,
	out: &mut impl std::io::Write,
	mut progress: crate::cli::style::Progress,
) -> ExitCode {
	let decor = crate::cli::term::stdout(false);
	let labels: Vec<&str> = std::iter::once(hostname)
		.chain(domains.iter().map(String::as_str))
		.collect();
	let mut steps = Steps::start(&labels, false);
	steps.begin(hostname);
	let host_checks = dns::check_host(hostname, public_ipv4, public_ipv6, dns).await;
	steps.clear();
	let mut all_ok = dns::all_ok(&host_checks);
	print_group(out, hostname, &host_checks, ":", decor);
	let mut done = 0;
	for _ in &host_checks {
		done += 1;
		if !steps.is_live() {
			progress.tick(done);
		}
	}
	for domain in domains {
		steps.begin(domain);
		let checks = dns::check_domain(domain, hostname, selectors, dns).await;
		steps.clear();
		print_group(out, domain, &checks, " \u{2014}", decor);
		for _ in &checks {
			done += 1;
			if !steps.is_live() {
				progress.tick(done);
			}
		}
		all_ok &= dns::all_ok(&checks);
	}
	let summary = if all_ok {
		format!("verified {done} records across {} domains", domains.len())
	} else {
		"DNS drift detected".to_string()
	};
	if steps.is_live() {
		steps.conclude(all_ok, &summary);
	} else {
		progress.finish(&summary);
	}
	if all_ok {
		ExitCode::SUCCESS
	} else {
		ExitCode::FAILURE
	}
}

/// Write one group (`name:` and a line per record) in one go, with any
/// spinner row erased first so the group starts on a clean line.
fn print_group(
	out: &mut impl std::io::Write,
	name: &str,
	checks: &[dns::Check],
	separator: &str,
	decor: Option<Decor>,
) {
	let mut text = format!("{}\n", group(name, decor));
	for check in checks {
		let record = match decor {
			Some(decor) => line(check, separator, decor),
			None => format!(
				"  {} {}{separator} {}",
				symbol(&check.status),
				check.kind,
				check.detail
			),
		};
		text.push_str(&record);
		text.push('\n');
	}
	let _ = quiet(|| out.write_all(text.as_bytes()));
}

/// The `name:` line that opens a group, bold on a terminal.
fn group(name: &str, decor: Option<Decor>) -> String {
	let text = format!("{name}:");
	match decor {
		Some(decor) => term::paint(
			Style::new().bold(),
			&term::fit(&text, decor.width),
			decor.colour,
		),
		None => text,
	}
}

/// One record on a terminal (`  ✘ missing  MX` and its detail), cut to the width
/// and painted after the cut.
fn line(check: &dns::Check, separator: &str, decor: Decor) -> String {
	// A lookup error is inconclusive, not a failure, so it is yellow.
	let (word, tone) = match check.status {
		Status::Ok => ("ok", term::Tone::Good),
		Status::Missing => ("missing", term::Tone::Bad),
		Status::LookupError => ("error", term::Tone::Warn),
	};
	let state = format!("{} {word}", tone.mark());
	// Padded to the longest state, `✘ missing`, so the records line up.
	let padding = " ".repeat(9usize.saturating_sub(term::columns(&state)));
	let rest = term::sanitize(&format!("{}{separator} {}", check.kind, check.detail));
	let room = decor.width.saturating_sub(4 + 9);
	let painted = term::paint(tone.style(), &state, decor.colour);
	format!("  {painted}{padding}  {}", term::fit(&rest, room))
}

/// A status glyph for the report line.
fn symbol(status: &Status) -> &'static str {
	match status {
		Status::Ok => "ok  ",
		Status::Missing => "MISS",
		Status::LookupError => "err ",
	}
}

#[cfg(test)]
#[path = "verify_dns_tests.rs"]
mod tests;
