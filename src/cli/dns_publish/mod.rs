//! `epistle dns publish`: compare the zones with the records the
//! configuration needs, show the plan, ask, and publish; `--undo` withdraws
//! what earlier runs published. The comparison and the writes live in
//! [`crate::dns::reconcile`], which the server's reconcile loop runs too;
//! this module reads the configuration, prints and asks.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::Args;

use crate::cli::style;
use crate::config::Config;
use crate::dns::provider::DnsProvider;
use crate::dns::reconcile::{self, apply, store, survey};

mod render;
#[cfg(test)]
mod tests;

/// How long one provider call may take.
const NET_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the command waits for the server's reconcile loop to finish
/// before it gives up.
const LOCK_WAIT: Duration = Duration::from_secs(60);

/// `epistle dns publish [<DOMAIN>] [--yes] [--json] [--undo]`; `--dry-run`
/// is the `dns` flag.
#[derive(Debug, Args)]
pub struct PublishArgs {
	/// Only this hosted domain. Defaults to every domain in `domains`.
	#[arg(value_name = "DOMAIN")]
	domain: Option<String>,
	/// Publish without asking.
	#[arg(long, short = 'y')]
	yes: bool,
	/// Print the plan as JSON.
	#[arg(long)]
	json: bool,
	/// Withdraw what earlier runs published, as their ledgers list it.
	#[arg(long)]
	undo: bool,
}

/// The provider `[dns]` configures, `None` when nothing can publish.
pub(super) type Built = Result<Option<Arc<dyn DnsProvider>>, String>;

/// What the command talks to; tests hand in a zone in memory.
pub(super) struct Deps<'a> {
	/// The configured provider.
	pub(super) provider: &'a dyn Fn(&Config) -> Built,
	/// The current time, seconds since the epoch.
	pub(super) now: u64,
}

/// Run `epistle dns publish`.
pub fn run(path: &Path, args: PublishArgs, dry_run: bool, json: bool) -> ExitCode {
	let deps = Deps {
		provider: &|config| Ok(config.dns.build_for_host(&config.hostname)),
		now: std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_secs())
			.unwrap_or(0),
	};
	execute(
		path,
		&args,
		dry_run,
		json,
		&deps,
		&mut std::io::stdout().lock(),
		&mut style::stderr(),
	)
}

/// The command proper: the plan on `out`, everything else on `err`.
pub(super) fn execute(
	path: &Path,
	args: &PublishArgs,
	dry_run: bool,
	json: bool,
	deps: &Deps<'_>,
	out: &mut impl Write,
	err: &mut impl Write,
) -> ExitCode {
	match prepare(path, args, deps) {
		Ok((config, provider, domain)) => {
			let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
				.enable_all()
				.build()
			else {
				style::error_to(err, "cannot start the async runtime");
				return ExitCode::FAILURE;
			};
			let _lock = match store::lock(&config.data_dir, LOCK_WAIT) {
				Ok(Some(lock)) => lock,
				Ok(None) => {
					style::error_to(
						err,
						"another publish holds the DNS ledger (the server's reconcile loop or a second command); try again",
					);
					return ExitCode::FAILURE;
				}
				Err(message) => {
					style::error_to(err, message);
					return ExitCode::FAILURE;
				}
			};
			let request = Request {
				config: &config,
				provider: provider.as_ref(),
				domain: domain.as_deref(),
				args,
				dry_run,
				json: json || args.json,
				now: deps.now,
			};
			if args.undo {
				return undo(&runtime, &request, out, err);
			}
			publish(&runtime, &request, out, err)
		}
		Err(message) => {
			style::error_to(err, message);
			ExitCode::FAILURE
		}
	}
}

/// What [`prepare`] settles: the configuration, the provider and the domain.
type Prepared = (Config, Arc<dyn DnsProvider>, Option<String>);

/// Load the configuration, settle the domain and build the provider. Every
/// refusal here happens before a zone is read.
fn prepare(path: &Path, args: &PublishArgs, deps: &Deps<'_>) -> Result<Prepared, String> {
	let config = Config::load(path).map_err(|error| error.to_string())?;
	let domain = match &args.domain {
		None => None,
		Some(raw) => {
			let domain = crate::domain::normalize(raw.trim().trim_end_matches('.'))
				.map_err(|_| format!("{raw} is not a valid domain name"))?;
			if !config
				.domains
				.iter()
				.any(|d| crate::dns::names::canonical_name(d) == domain)
			{
				return Err(format!("{domain} is not a domain this server hosts"));
			}
			Some(domain)
		}
	};
	let provider = (deps.provider)(&config)?.ok_or(
		"no [dns] provider can publish; `epistle dns-records` prints the records to add by hand",
	)?;
	Ok((config, provider, domain))
}

/// One run of the command.
struct Request<'a> {
	config: &'a Config,
	provider: &'a dyn DnsProvider,
	domain: Option<&'a str>,
	args: &'a PublishArgs,
	dry_run: bool,
	json: bool,
	now: u64,
}

/// Read, plan, print, ask, publish.
fn publish(
	runtime: &tokio::runtime::Runtime,
	request: &Request<'_>,
	out: &mut impl Write,
	err: &mut impl Write,
) -> ExitCode {
	let config = request.config;
	let desired = match crate::dns::desired::from_config(config) {
		Ok(desired) => desired,
		Err(errors) => {
			for error in errors {
				style::error_to(err, error);
			}
			return ExitCode::FAILURE;
		}
	};
	for warning in &desired.warnings {
		style::warn_to(err, warning);
	}
	let incomplete = desired.incomplete();
	let context = survey::Context {
		config,
		provider: request.provider,
		needed: &desired.records,
		domain: request.domain,
		timeout: NET_TIMEOUT,
		incomplete: incomplete.as_deref(),
	};
	let survey = match runtime.block_on(survey::survey(&context)) {
		Ok(survey) => survey,
		Err(message) => {
			style::error_to(err, message);
			return ExitCode::FAILURE;
		}
	};
	let printed = if request.json {
		serde_json::to_string_pretty(&render::plan_json(&survey)).map(|text| text + "\n")
	} else {
		Ok(render::plan_text(&survey))
	};
	match printed {
		Ok(text) if out.write_all(text.as_bytes()).is_ok() => {}
		_ => {
			style::error_to(err, "cannot write the plan");
			return ExitCode::FAILURE;
		}
	}
	// A zone that could not be read is told to the operator before the
	// question: the plan above does not cover it.
	for failure in &survey.failures {
		style::error_to(err, &failure.reason);
	}
	if !survey.changes() {
		if survey.failures.is_empty() {
			let _ = writeln!(err, "nothing to change");
			return ExitCode::SUCCESS;
		}
		return ExitCode::FAILURE;
	}
	if request.dry_run {
		let _ = writeln!(err, "dry run: nothing was published");
		return if survey.failures.is_empty() {
			ExitCode::SUCCESS
		} else {
			ExitCode::FAILURE
		};
	}
	let question = format!("Apply these {} changes to DNS?", survey.writes());
	if let Err(code) =
		crate::cli::prompt::confirm_destructive("dns publish", &question, request.args.yes)
	{
		return code;
	}
	let target = apply::Target {
		provider: request.provider,
		data_dir: &config.data_dir,
		hostname: &config.hostname,
		timeout: NET_TIMEOUT,
		now: request.now,
	};
	let report = runtime.block_on(apply::apply(&target, survey.zones));
	let _ = writeln!(
		err,
		"{} changes applied; `epistle dns publish --undo` withdraws what epistle published",
		report.applied.len()
	);
	match (report.failure, survey.failures.is_empty()) {
		(None, true) => ExitCode::SUCCESS,
		(Some(failure), _) => {
			style::error_to(err, failure);
			ExitCode::FAILURE
		}
		(None, false) => ExitCode::FAILURE,
	}
}

/// Withdraw what the ledgers list.
fn undo(
	runtime: &tokio::runtime::Runtime,
	request: &Request<'_>,
	out: &mut impl Write,
	err: &mut impl Write,
) -> ExitCode {
	// A first pass reads only, so the operator sees what would go before
	// anything does.
	let preview = runtime.block_on(reconcile::undo::undo(
		request.config,
		request.provider,
		request.domain,
		true,
		NET_TIMEOUT,
	));
	let preview = match preview {
		Ok(report) => report,
		Err(message) => {
			style::error_to(err, message);
			return ExitCode::FAILURE;
		}
	};
	let _ = out.write_all(render::undo_text(&preview, request.json).as_bytes());
	let removals = preview
		.entries
		.iter()
		.filter(|e| e.outcome == "remove")
		.count();
	if preview.entries.iter().all(|e| e.outcome == "left") {
		let _ = writeln!(err, "nothing to undo");
		return ExitCode::SUCCESS;
	}
	if request.dry_run {
		let _ = writeln!(err, "dry run: nothing was removed");
		return ExitCode::SUCCESS;
	}
	let question = format!("Remove these {removals} records from DNS?");
	if let Err(code) =
		crate::cli::prompt::confirm_destructive("dns publish --undo", &question, request.args.yes)
	{
		return code;
	}
	let done = runtime.block_on(reconcile::undo::undo(
		request.config,
		request.provider,
		request.domain,
		false,
		NET_TIMEOUT,
	));
	match done {
		Ok(report) => {
			let removed = report
				.entries
				.iter()
				.filter(|e| e.outcome == "remove")
				.count();
			let _ = writeln!(err, "{removed} records removed");
			match report.failure {
				None => ExitCode::SUCCESS,
				Some(failure) => {
					style::error_to(err, failure);
					ExitCode::FAILURE
				}
			}
		}
		Err(message) => {
			style::error_to(err, message);
			ExitCode::FAILURE
		}
	}
}
