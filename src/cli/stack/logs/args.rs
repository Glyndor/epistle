//! What the operator can say to `epistle stack logs`.

use clap::Args;

/// The lines each service shows when `--tail` is not given.
pub(super) const DEFAULT_TAIL: u32 = 200;

/// The flags and the optional service of `epistle stack logs`.
#[derive(Debug, Clone, Default, Args)]
pub struct LogsArgs {
	/// Follow the log output as it is produced.
	///
	/// The services are interleaved in the order the lines arrive, so
	/// `--merge` is already what this does and `--no-merge` is refused.
	#[arg(long)]
	pub follow: bool,
	/// How many lines from the end of each service's log to show (default 200).
	#[arg(long, value_name = "N", conflicts_with = "all")]
	pub tail: Option<u32>,
	/// Show the whole log of each service instead of its last lines.
	#[arg(long)]
	pub all: bool,
	/// Only lines since this time: a duration such as `10m` or `1h30m`, or a
	/// time such as `2026-11-15T08:00:00`.
	#[arg(long, value_name = "WHEN")]
	pub since: Option<String>,
	/// Only lines before this time, written like `--since`.
	#[arg(long, value_name = "WHEN")]
	pub until: Option<String>,
	/// Interleave the services in time order. This is the default when more
	/// than one service is shown.
	#[arg(long, conflicts_with = "no_merge")]
	pub merge: bool,
	/// Show one service after the other instead of interleaving them.
	#[arg(long, conflicts_with = "follow")]
	pub no_merge: bool,
	/// Print every line whole; by default a line longer than 500 characters
	/// is cut and says how much was left out.
	#[arg(long)]
	pub raw: bool,
	/// Show only this service.
	#[arg(value_name = "SERVICE")]
	pub service: Option<String>,
}

impl LogsArgs {
	/// The value of podup's `--tail`: a number of lines or `all`.
	pub(super) fn tail_argument(&self) -> String {
		if self.all {
			"all".to_string()
		} else {
			self.tail.unwrap_or(DEFAULT_TAIL).to_string()
		}
	}

	/// The words after `logs` that every podup call shares: the tail and the
	/// time range. The services and `-t` are added by the caller.
	pub(super) fn range_argv(&self) -> Vec<String> {
		let mut argv = vec!["-n".to_string(), self.tail_argument()];
		if let Some(since) = &self.since {
			argv.push("--since".to_string());
			argv.push(since.clone());
		}
		if let Some(until) = &self.until {
			argv.push("--until".to_string());
			argv.push(until.clone());
		}
		argv
	}

	/// Whether the services are interleaved in time order: when asked, or
	/// when more than one is shown and `--no-merge` did not say otherwise.
	pub(super) fn merges(&self, services: usize) -> bool {
		self.merge || (!self.no_merge && services > 1)
	}
}
