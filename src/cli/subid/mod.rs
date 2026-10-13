//! Moving the service account's subordinate id block off another account's.
//!
//! Packages up to 0.10.1 gave `glyndor-epistle` the block `useradd` also
//! gives the first regular user. The postinst of later packages finds that
//! overlap on upgrade, picks a free block with the same allocator a fresh
//! install uses, and hands it to `epistle move-subids`, which moves the
//! account and the files its containers own onto it.

use std::path::PathBuf;
use std::process::ExitCode;

mod host;
mod journal;
mod mover;
mod shift;
pub(crate) mod table;

/// Arguments of `epistle move-subids`. The postinst computes the targets with
/// the allocator a fresh install uses; the command checks they are free.
#[derive(Debug, clap::Args)]
pub struct MoveArgs {
	/// First id of the new subuid block.
	#[arg(long, value_name = "ID")]
	uid_start: u64,
	/// First id of the new subgid block.
	#[arg(long, value_name = "ID")]
	gid_start: u64,
	/// Configuration file, read for `data_dir` when it lies outside the
	/// account's home.
	#[arg(long, value_name = "FILE", default_value = super::DEFAULT_CONFIG)]
	pub(super) config: PathBuf,
}

/// Run `epistle move-subids`: refuse unless root, then move.
pub(super) fn run(args: MoveArgs) -> ExitCode {
	// SAFETY: geteuid takes no arguments and cannot fail.
	if unsafe { libc::geteuid() } != 0 {
		super::style::error(
			"move-subids rewrites /etc/subuid and /etc/subgid and must run as root",
		);
		return ExitCode::FAILURE;
	}
	let mut system = match host::System::new(&args.config) {
		Ok(system) => system,
		Err(error) => {
			super::style::error(format_args!("cannot move the subordinate ids: {error}"));
			return ExitCode::FAILURE;
		}
	};
	let targets = mover::Targets {
		uid: args.uid_start,
		gid: args.gid_start,
	};
	match mover::run(&mut system, targets) {
		Ok(summary) => {
			eprintln!("epistle: {summary}");
			ExitCode::SUCCESS
		}
		Err(error) => {
			super::style::error(format_args!("could not move the subordinate ids: {error}"));
			ExitCode::FAILURE
		}
	}
}
