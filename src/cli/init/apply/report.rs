//! What `apply` did: the step list, its outcome and the report the operator reads.

use std::io::Write;
use std::path::PathBuf;

use super::ApplyError;

/// What `apply` actually did: a step list the operator can scan, with
/// every `reused: true` line meaning "the file was already there and
/// was not touched`.
#[derive(Debug, Default)]
pub struct Report {
	/// Every step the apply phase carried out, in order.
	pub steps: Vec<ReportStep>,
}

/// The outcome of a single `apply` call: the steps that completed plus,
/// when a step failed after effects were already on disk, the error
/// that stopped the run. The report is always populated with whatever
/// steps ran before the failure, so the operator can see exactly what
/// landed on their machine.
#[derive(Debug, Default)]
pub struct ApplyOutcome {
	/// Every step that completed, including the step that failed when
	/// it made partial progress.
	pub report: Report,
	/// Set when the apply phase stopped early. `None` means every step
	/// succeeded.
	pub error: Option<ApplyError>,
}

/// One line of the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportStep {
	/// A file already existed and was left byte-for-byte untouched.
	Reused(PathBuf),
	/// A file was newly written.
	Wrote(PathBuf),
	/// A file was rewritten with new bytes.
	Updated(PathBuf),
	/// The config matched the desired one byte for byte and was not
	/// touched (the file's mtime did not change).
	ConfigIdentical(PathBuf),
	/// A directory was created (typically the parent of `config_path`,
	/// which never existed on a fresh install).
	CreatedDir(PathBuf),
	/// The first mail account was created.
	AccountCreated {
		/// The account name.
		name: String,
		/// The account's address.
		address: String,
	},
	/// A role address was made an alias of the first account.
	AliasAdded {
		/// The role address.
		address: String,
		/// The address it delivers to.
		target: String,
	},
	/// A key was moved out of data_dir to where it now lives.
	Moved {
		/// Where it was.
		from: PathBuf,
		/// Where it is now.
		to: PathBuf,
	},
	/// A step was skipped because its precondition did not hold.
	Skipped {
		/// Operator-facing name of what was skipped.
		name: String,
		/// Operator-facing reason it was skipped.
		reason: String,
	},
	/// A published listener was moved off every address of the host by the
	/// generated file this run wrote.
	Narrowed(crate::cli::init::Narrowed),
}

impl Report {
	/// Write the report to `out` as one line per entry.
	pub fn write_to(&self, out: &mut impl Write) -> std::io::Result<()> {
		for step in &self.steps {
			match step {
				ReportStep::Reused(p) => writeln!(out, "  reused: {}", p.display())?,
				ReportStep::Wrote(p) => writeln!(out, "  wrote:  {}", p.display())?,
				ReportStep::Updated(p) => writeln!(out, "  updated: {}", p.display())?,
				ReportStep::ConfigIdentical(p) => {
					writeln!(out, "  config identical: {}", p.display())?
				}
				ReportStep::CreatedDir(p) => writeln!(out, "  created dir: {}", p.display())?,
				ReportStep::Moved { from, to } => {
					writeln!(out, "  moved:  {} to {}", from.display(), to.display())?
				}
				ReportStep::Skipped { name, reason } => {
					writeln!(out, "  skipped: {name} ({reason})")?
				}
				ReportStep::Narrowed(one) => writeln!(out, "  narrowed: {one}")?,
				ReportStep::AccountCreated { name, address } => {
					writeln!(out, "  account: {name} <{address}>")?
				}
				ReportStep::AliasAdded { address, target } => {
					writeln!(out, "  alias:  {address} -> {target}")?
				}
			}
		}
		Ok(())
	}
}
