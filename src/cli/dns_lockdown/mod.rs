//! `epistle dns lockdown`: publish the anti-spoofing records for a domain
//! (DMARC one step stricter, a null SPF and null MX on names that send no
//! mail, a wildcard null SPF) and `--undo` them. The plan and the provider
//! work live in [`crate::dns::lockdown`]; this module reads the config,
//! keeps the journal file, prints, and asks before writing.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use clap::Args;

use crate::cli::style;
use crate::config::Config;
use crate::dns::provider::{DnsProvider, DnsRecord, ProviderError, RecordKind};
use crate::dns::{
	lockdown, lockdown::DmarcInputs, lockdown::DmarcStep, lockdown::Journal, lockdown::Plan,
	lockdown::PlanInput, lockdown::ServedNames,
};
use crate::spf::DnsLookup;

pub(super) mod render;
mod target;
mod undo;

/// How long one provider read may take.
const NET_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// `--dmarc`: the only accepted value is `reject`, the explicit jump.
fn parse_dmarc_jump(value: &str) -> Result<DmarcStep, String> {
	match value {
		"reject" => Ok(DmarcStep::Reject),
		other => Err(format!(
			"\"{other}\" is not a DMARC jump; the only one is --dmarc reject"
		)),
	}
}

/// `epistle dns lockdown [<DOMAIN>] [--yes] [--json] [--undo] [--dmarc
/// reject]`; `--dry-run` is the `dns` flag.
#[derive(Debug, Args)]
pub struct LockdownArgs {
	/// The domain to lock down. Defaults to the `[dns]` zone, or the first
	/// `[domains]` entry without a provider.
	#[arg(value_name = "DOMAIN")]
	domain: Option<String>,
	/// Publish without asking.
	#[arg(long, short = 'y')]
	yes: bool,
	/// Print the plan as JSON.
	#[arg(long, conflicts_with = "undo")]
	json: bool,
	/// Remove what earlier runs published, as their journal lists it.
	#[arg(long)]
	undo: bool,
	/// `--dmarc reject`: go straight to p=reject instead of one step.
	#[arg(long, value_name = "POLICY", value_parser = parse_dmarc_jump, conflicts_with = "undo")]
	dmarc: Option<DmarcStep>,
}

/// The provider `[dns]` configures, `None` without one (or with
/// `manual`), or why it cannot be built.
pub(super) type Built = Result<Option<Arc<dyn DnsProvider>>, String>;

/// What the command talks to; tests hand in fakes.
pub(super) struct Deps<'a> {
	/// The configured provider.
	pub(super) provider: &'a dyn Fn(&Config) -> Built,
	/// The resolver that reads the live DMARC record without a provider.
	pub(super) resolver: &'a dyn Fn() -> Result<Box<dyn DnsLookup>, String>,
	/// The current time, Unix seconds, for the report window.
	pub(super) now: u64,
}

/// Run `epistle dns lockdown`.
pub fn run(path: &Path, args: LockdownArgs, dry_run: bool) -> ExitCode {
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	let deps = Deps {
		provider: &configured_provider,
		resolver: &|| {
			crate::spf::SystemDns::from_system()
				.map(|dns| Box::new(dns) as Box<dyn DnsLookup>)
				.map_err(|error| format!("cannot start the resolver: {error}"))
		},
		now,
	};
	execute(
		path,
		&args,
		dry_run,
		&deps,
		&mut std::io::stdout().lock(),
		&mut style::stderr(),
	)
}

/// The command proper: plan output on `out`, everything else on `err`.
pub(super) fn execute(
	path: &Path,
	args: &LockdownArgs,
	dry_run: bool,
	deps: &Deps<'_>,
	out: &mut impl Write,
	err: &mut impl Write,
) -> ExitCode {
	match prepare(path, args, deps) {
		Ok(Prepared {
			config,
			zone,
			domain,
			journal_path,
			journal,
			provider,
		}) => {
			let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
				.enable_all()
				.build()
			else {
				style::error_to(err, "cannot start the async runtime");
				return ExitCode::FAILURE;
			};
			let target = Target {
				zone: &zone,
				domain: &domain,
				journal_path: &journal_path,
			};
			if args.undo {
				return undo::run(
					&runtime, provider, &target, journal, args.yes, dry_run, out, err,
				);
			}
			match provider {
				Some(provider) => publish(
					&runtime, &config, provider, &target, journal, args, dry_run, deps, out, err,
				),
				None => manual(&runtime, &config, &domain, args, deps, out, err),
			}
		}
		Err(message) => {
			style::error_to(err, message);
			ExitCode::FAILURE
		}
	}
}

/// Where the command writes: the provider zone, the domain, the journal.
pub(super) struct Target<'a> {
	pub(super) zone: &'a str,
	pub(super) domain: &'a str,
	pub(super) journal_path: &'a Path,
}

struct Prepared {
	config: Config,
	zone: String,
	domain: String,
	journal_path: PathBuf,
	journal: Option<Journal>,
	provider: Option<Arc<dyn DnsProvider>>,
}

/// Load the config, settle the domain and zone, read the journal and build
/// the provider. Every refusal here happens before anything is read from
/// or written to the zone.
fn prepare(path: &Path, args: &LockdownArgs, deps: &Deps<'_>) -> Result<Prepared, String> {
	let config = Config::load(path).map_err(|error| error.to_string())?;
	let settled = target::settle(&config, args.domain.as_deref())?;
	let (domain, zone) = (settled.domain, settled.zone);
	let journal_path = config
		.data_dir
		.join("dns-lockdown")
		.join(format!("{domain}.json"));
	let journal = load_journal(&journal_path, &domain)?;
	let provider = (deps.provider)(&config)?;
	// An entry set to `manual` leaves its zone to the operator even when
	// another zone has a provider.
	let provider = provider.filter(|_| !settled.manual_zone);
	Ok(Prepared {
		zone,
		config,
		domain,
		journal_path,
		journal,
		provider,
	})
}

/// The provider `[dns]` configures; `None` without one or for `manual`.
fn configured_provider(config: &Config) -> Built {
	let Some(dns) = config.dns.first() else {
		return Ok(None);
	};
	if config
		.dns
		.iter()
		.all(|dns| dns.provider.eq_ignore_ascii_case("manual"))
	{
		return Ok(None);
	}
	config
		.dns
		.build_for_host(&config.hostname)
		.map(Some)
		.ok_or_else(|| {
		format!(
			"the {} credentials in [dns] could not be read; check that the token file or environment variable is available to this user",
			dns.provider
		)
	})
}

/// The journal at `path`, `None` when there is none. A journal that cannot
/// be read stops the command: running on would overwrite it and lose what
/// `--undo` needs.
pub(super) fn load_journal(path: &Path, domain: &str) -> Result<Option<Journal>, String> {
	let text = match std::fs::read_to_string(path) {
		Ok(text) => text,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
		Err(error) => {
			return Err(format!(
				"cannot read the journal {}: {error}",
				path.display()
			));
		}
	};
	let journal: Journal = serde_json::from_str(&text).map_err(|error| {
		format!(
			"the journal {} is not readable ({error}); move it aside to start over",
			path.display()
		)
	})?;
	if journal.domain != domain {
		return Err(format!(
			"the journal {} is for {}, not {domain}",
			path.display(),
			journal.domain
		));
	}
	Ok(Some(journal))
}

/// Write the journal through a temporary file and a rename, so a crash
/// never leaves half a journal.
pub(super) fn store_journal(path: &Path, journal: &Journal) -> Result<(), String> {
	let parent = path.parent().unwrap_or(Path::new("."));
	std::fs::create_dir_all(parent)
		.map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
	let text = serde_json::to_string_pretty(journal)
		.map_err(|error| format!("cannot encode the journal: {error}"))?;
	let staging = path.with_extension("json.new");
	std::fs::write(&staging, text)
		.and_then(|()| std::fs::rename(&staging, path))
		.map_err(|error| format!("cannot write {}: {error}", path.display()))
}

/// Print the plan: JSON or text.
fn print_plan(plan: &Plan, json: bool, out: &mut impl Write) -> Result<(), String> {
	let text = if json {
		serde_json::to_string_pretty(plan).map_err(|error| error.to_string())? + "\n"
	} else {
		render::plan_text(plan)
	};
	out.write_all(text.as_bytes())
		.map_err(|error| format!("cannot write the plan: {error}"))
}

/// The aggregate-report inputs for the plan.
fn dmarc_inputs(config: &Config, domain: &str, args: &LockdownArgs, now: u64) -> DmarcInputs {
	let (failing_sources, has_reports) =
		lockdown::recent_dmarc_failures(&config.data_dir, domain, now);
	DmarcInputs {
		jump_to: args.dmarc,
		has_reports,
		failing_sources,
	}
}

/// With a provider: read the zone, plan, print, ask, publish.
#[allow(clippy::too_many_arguments)]
fn publish(
	runtime: &tokio::runtime::Runtime,
	config: &Config,
	provider: Arc<dyn DnsProvider>,
	target: &Target<'_>,
	journal: Option<Journal>,
	args: &LockdownArgs,
	dry_run: bool,
	deps: &Deps<'_>,
	out: &mut impl Write,
	err: &mut impl Write,
) -> ExitCode {
	let listed = runtime
		.block_on(async { tokio::time::timeout(NET_TIMEOUT, provider.list(target.zone)).await });
	let existing = match listed {
		Ok(Ok(existing)) => existing,
		// A provider that cannot list the zone leaves the lockdown blind to
		// the delegations and the records it must not write over.
		Ok(Err(ProviderError::Unsupported)) => {
			style::error_to(
				err,
				format_args!(
					"this DNS provider cannot list the {} zone, so the lockdown cannot see its delegations or its records; nothing was written",
					target.zone
				),
			);
			return ExitCode::FAILURE;
		}
		Ok(Err(error)) => {
			style::error_to(
				err,
				format_args!("reading the {} zone failed: {error}", target.zone),
			);
			return ExitCode::FAILURE;
		}
		Err(_) => {
			style::error_to(
				err,
				format_args!(
					"reading the {} zone timed out after {} seconds",
					target.zone,
					NET_TIMEOUT.as_secs()
				),
			);
			return ExitCode::FAILURE;
		}
	};
	let served = ServedNames::new(&config.domains, &config.hostname, &existing);
	let dmarc = dmarc_inputs(config, target.domain, args, deps.now);
	let plan = lockdown::build_plan(&PlanInput {
		zone: target.zone,
		domain: target.domain,
		served: &served,
		existing: &existing,
		journal: journal.as_ref(),
		dmarc: &dmarc,
		zone_listed: true,
	});
	if let Err(message) = print_plan(&plan, args.json, out) {
		style::error_to(err, message);
		return ExitCode::FAILURE;
	}
	if plan.entries.is_empty() {
		let _ = writeln!(err, "nothing to change");
		return ExitCode::SUCCESS;
	}
	if dry_run {
		let _ = writeln!(err, "dry run: nothing was published");
		return ExitCode::SUCCESS;
	}
	let question = format!(
		"Publish these {} records to the {} zone?",
		plan.entries.len(),
		target.zone
	);
	if let Err(code) = crate::cli::prompt::confirm_destructive("dns lockdown", &question, args.yes)
	{
		return code;
	}
	let mut persist = |journal: &Journal| store_journal(target.journal_path, journal);
	let published = runtime.block_on(lockdown::publish_plan(
		provider.as_ref(),
		target.zone,
		&plan,
		journal.as_ref(),
		&mut persist,
	));
	match published {
		Ok(_) => {
			let _ = writeln!(
				err,
				"published {} records; `epistle dns lockdown --undo` removes them",
				plan.entries.len()
			);
			ExitCode::SUCCESS
		}
		Err(failure) => {
			let saved = store_journal(target.journal_path, &failure.journal);
			style::error_to(err, &failure.message);
			if let Err(message) = saved {
				style::error_to(err, message);
			} else {
				let _ = writeln!(
					err,
					"the journal lists the {} records that were published; `epistle dns lockdown --undo` removes them",
					failure.journal.entries.len()
				);
			}
			ExitCode::FAILURE
		}
	}
}

/// Without a provider: plan from the live DMARC record alone and print
/// the records to add by hand. Nothing is written, the journal included.
fn manual(
	runtime: &tokio::runtime::Runtime,
	config: &Config,
	domain: &str,
	args: &LockdownArgs,
	deps: &Deps<'_>,
	out: &mut impl Write,
	err: &mut impl Write,
) -> ExitCode {
	let name = format!("_dmarc.{domain}");
	let resolver = match (deps.resolver)() {
		Ok(resolver) => resolver,
		Err(message) => {
			style::error_to(err, message);
			return ExitCode::FAILURE;
		}
	};
	let existing: Vec<DnsRecord> = match runtime.block_on(resolver.txt(&name)) {
		Ok(values) => values
			.into_iter()
			.map(|value| DnsRecord::new(name.clone(), RecordKind::Txt, value, lockdown::TTL))
			.collect(),
		Err(_) => {
			style::error_to(
				err,
				format_args!(
					"cannot read {name} through the system resolver, so the DMARC step is unknown; try again when DNS answers"
				),
			);
			return ExitCode::FAILURE;
		}
	};
	let served = ServedNames::new(&config.domains, &config.hostname, &existing);
	let dmarc = dmarc_inputs(config, domain, args, deps.now);
	let plan = lockdown::build_plan(&PlanInput {
		zone: domain,
		domain,
		served: &served,
		existing: &existing,
		journal: None,
		dmarc: &dmarc,
		zone_listed: false,
	});
	if let Err(message) = print_plan(&plan, args.json, out) {
		style::error_to(err, message);
		return ExitCode::FAILURE;
	}
	let _ = writeln!(
		err,
		"no DNS provider is configured: add the records above by hand. The null SPF and null MX for each name need the zone's record list, which only a configured provider can read."
	);
	ExitCode::SUCCESS
}

#[cfg(test)]
mod tests;
