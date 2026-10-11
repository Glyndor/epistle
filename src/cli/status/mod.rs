//! `epistle status` and `epistle check`: answer "is my mail server working?"
//! without reading logs.
//!
//! Every check is bounded (network operations time out after
//! [`NET_TIMEOUT`], a whole area after [`AREA_DEADLINE`]) and none of them
//! sends mail or authenticates. `status` runs every check; `check <area>`
//! runs one and lists its findings.

mod config_area;
mod report;
#[cfg(test)]
mod test_support;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use clap::ValueEnum;

use crate::config::Config;
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
}

impl CheckArea {
	/// Every area, in the order `status` prints them.
	const ALL: &'static [CheckArea] = &[CheckArea::Config];

	/// The name used on the command line and as the JSON key.
	pub(super) fn name(self) -> &'static str {
		match self {
			CheckArea::Config => "config",
		}
	}
}

/// What every check can look at: the config path, its parsed form and the
/// clock, injectable so thresholds are testable.
pub(super) struct Ctx {
	pub(super) path: PathBuf,
	pub(super) config: Result<Config, String>,
	pub(super) now: SystemTime,
}

impl Ctx {
	fn load(path: &Path) -> Self {
		Ctx {
			path: path.to_path_buf(),
			config: Config::load(path).map_err(|error| error.to_string()),
			now: SystemTime::now(),
		}
	}
}

/// `epistle status [--json]`: every area, one line each.
pub(super) fn run_status(path: &Path, json: bool) -> ExitCode {
	execute(
		path,
		CheckArea::ALL,
		json,
		false,
		&mut std::io::stdout().lock(),
	)
}

/// `epistle check <area> [--json]`: one area with its findings.
pub(super) fn run_check(path: &Path, area: CheckArea, json: bool) -> ExitCode {
	execute(path, &[area], json, true, &mut std::io::stdout().lock())
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
		render_table(&reports, show_items, out)
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

/// Run one area. Areas other than `config` need a loaded configuration; when
/// it did not load they report that instead of guessing.
async fn check_area(area: CheckArea, ctx: &Ctx) -> AreaReport {
	if area == CheckArea::Config {
		return config_area::check(ctx).await;
	}
	match &ctx.config {
		Ok(_config) => AreaReport::ok("nothing to check"),
		Err(_) => AreaReport::fail("not checked: the configuration did not load"),
	}
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
