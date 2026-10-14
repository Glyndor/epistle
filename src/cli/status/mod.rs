//! `epistle status` and `epistle check`: answer "is my mail server working?"
//! without reading logs.
//!
//! Every check is bounded (network operations time out after
//! [`NET_TIMEOUT`], a whole area after [`AREA_DEADLINE`]) and none of them
//! sends mail or authenticates. `status` runs every check; `check <area>`
//! runs one and lists its findings.

mod antispam_area;
mod av_area;
mod clock;
mod config_area;
mod db_area;
mod disk_area;
mod dns_area;
mod dns_dkim;
#[cfg(test)]
pub(crate) mod dns_fake;
mod in_stack;
mod ports;
mod queue_area;
mod report;
mod subid_area;
#[cfg(test)]
mod test_support;
mod tls_area;
mod tls_tlsa;

pub(crate) use dns_area::TimeoutDns;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use clap::ValueEnum;

use crate::config::Config;
pub(in crate::cli) use clock::parse_rfc3339;
use report::{AreaReport, any_failed, render_json, render_table};

/// Upper bound for one network operation (connect, read, query).
pub(super) const NET_TIMEOUT: Duration = Duration::from_secs(5);

/// Upper bound for one whole area, so a stuck check cannot hang `status`.
const AREA_DEADLINE: Duration = Duration::from_secs(60);

/// What `epistle check` can examine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CheckArea {
	/// The configuration file loads.
	Config,
	/// Every enabled listener answers with its protocol greeting.
	Ports,
	/// The served certificate is valid, not close to expiry, and covers the hostname.
	Tls,
	/// Published DNS records match what epistle expects, including the DKIM key.
	Dns,
	/// The configured database answers `SELECT 1`.
	Db,
	/// The configured clamd answers `PING`.
	Antivirus,
	/// Antispam engine state: which features are on, which are off and why.
	Antispam,
	/// The outbound queue is draining: count, oldest age, deferred.
	Queue,
	/// The data filesystem has room.
	Disk,
	/// The service account's subordinate id ranges overlap no other account's.
	Subid,
}

impl CheckArea {
	/// Every area, in the order `status` prints them.
	const ALL: &'static [CheckArea] = &[
		CheckArea::Config,
		CheckArea::Ports,
		CheckArea::Tls,
		CheckArea::Dns,
		CheckArea::Db,
		CheckArea::Antivirus,
		CheckArea::Antispam,
		CheckArea::Queue,
		CheckArea::Disk,
		CheckArea::Subid,
	];

	/// The name used on the command line and as the JSON key.
	pub(super) fn name(self) -> &'static str {
		match self {
			CheckArea::Config => "config",
			CheckArea::Ports => "ports",
			CheckArea::Tls => "tls",
			CheckArea::Dns => "dns",
			CheckArea::Db => "db",
			CheckArea::Antivirus => "antivirus",
			CheckArea::Antispam => "antispam",
			CheckArea::Queue => "queue",
			CheckArea::Disk => "disk",
			CheckArea::Subid => "subid",
		}
	}
}

/// What every check can look at: the config path, its parsed form and the
/// clock, injectable so thresholds are testable.
pub(super) struct Ctx {
	pub(super) path: PathBuf,
	pub(super) config: Result<Config, String>,
	pub(super) now: SystemTime,
	/// The `podup` program that reports the stack's container state.
	pub(super) podup: String,
}

impl Ctx {
	/// The loaded configuration, or the report every area gives when it did
	/// not load.
	fn loaded(&self) -> Result<&Config, AreaReport> {
		self.config
			.as_ref()
			.map_err(|_| AreaReport::fail("not checked: the configuration did not load"))
	}

	fn load(path: &Path) -> Self {
		Ctx {
			path: path.to_path_buf(),
			config: Config::load(path).map_err(|error| error.to_string()),
			now: SystemTime::now(),
			podup: "podup".to_string(),
		}
	}
}

/// `epistle status [--json]`: every area, one line each.
pub(super) fn run_status(path: &Path, json: bool, out: &mut impl Write) -> ExitCode {
	execute(path, CheckArea::ALL, json, false, out)
}

/// `epistle check <area> [--json]`: one area with its findings.
pub(super) fn run_check(
	path: &Path,
	area: CheckArea,
	json: bool,
	out: &mut impl Write,
) -> ExitCode {
	execute(path, &[area], json, true, out)
}

/// Run `areas`, print the result to `out` and map it to an exit code: 0 when
/// nothing failed, 1 otherwise.
fn execute(
	path: &Path,
	areas: &[CheckArea],
	json: bool,
	show_items: bool,
	out: &mut impl Write,
) -> ExitCode {
	let runtime = match tokio::runtime::Runtime::new() {
		Ok(runtime) => runtime,
		Err(error) => {
			super::style::error(format_args!("cannot start async runtime: {error}"));
			return ExitCode::FAILURE;
		}
	};
	let ctx = Arc::new(Ctx::load(path));
	let reports = runtime.block_on(run_areas(areas, ctx));
	let written = if json {
		render_json(&reports, out)
	} else {
		render_table(&reports, show_items, super::term::stdout(json), out)
	};
	if let Err(error) = written {
		super::style::error(format_args!("cannot write the report: {error}"));
		return ExitCode::FAILURE;
	}
	if any_failed(&reports) {
		ExitCode::FAILURE
	} else {
		ExitCode::SUCCESS
	}
}

/// Run the areas concurrently, each under [`AREA_DEADLINE`], and return the
/// reports in the order requested.
/// The areas among `areas` that fail for the config at `path`, as
/// `(name, detail)`; used by `stack update` to judge a restart.
pub(in crate::cli) fn failing(
	path: &Path,
	areas: &[CheckArea],
) -> Result<Vec<(String, String)>, String> {
	let runtime = tokio::runtime::Runtime::new()
		.map_err(|error| format!("cannot start async runtime: {error}"))?;
	let reports = runtime.block_on(run_areas(areas, Arc::new(Ctx::load(path))));
	Ok(reports
		.into_iter()
		.filter(|(_, report)| report.status == report::Level::Fail)
		.map(|(area, report)| (area.name().to_string(), report.detail))
		.collect())
}

async fn run_areas(areas: &[CheckArea], ctx: Arc<Ctx>) -> Vec<(CheckArea, AreaReport)> {
	let mut set = tokio::task::JoinSet::new();
	for (index, area) in areas.iter().copied().enumerate() {
		let ctx = Arc::clone(&ctx);
		set.spawn(async move {
			let report = match tokio::time::timeout(AREA_DEADLINE, check_area(area, &ctx)).await {
				Ok(report) => report,
				Err(_) => AreaReport::fail(format!("timed out after {}s", AREA_DEADLINE.as_secs())),
			};
			(index, area, report)
		});
	}
	let mut done = Vec::with_capacity(areas.len());
	while let Some(joined) = set.join_next().await {
		match joined {
			Ok(entry) => done.push(entry),
			Err(error) => tracing::error!(%error, "status check task failed"),
		}
	}
	done.sort_by_key(|(index, _, _)| *index);
	done.into_iter()
		.map(|(_, area, report)| (area, report))
		.collect()
}

/// Run one area. Every area except `config` starts from [`Ctx::loaded`], so
/// an unreadable configuration is reported instead of guessed at.
async fn check_area(area: CheckArea, ctx: &Ctx) -> AreaReport {
	match area {
		CheckArea::Config => config_area::check(ctx).await,
		CheckArea::Ports => ports::check(ctx).await,
		CheckArea::Tls => tls_area::check(ctx).await,
		CheckArea::Dns => dns_area::check(ctx).await,
		CheckArea::Db => db_area::check(ctx).await,
		CheckArea::Antivirus => av_area::check(ctx).await,
		CheckArea::Antispam => antispam_area::check(ctx).await,
		CheckArea::Queue => queue_area::check(ctx).await,
		CheckArea::Disk => disk_area::check(ctx).await,
		CheckArea::Subid => subid_area::check(ctx).await,
	}
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
