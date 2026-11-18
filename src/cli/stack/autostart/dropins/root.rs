//! The root half: the system drop-in, written by the process that delegates.
//!
//! `sudo epistle stack up` runs as root only until it hands over to the
//! service account, so the account's own process can never write a file under
//! `/etc/systemd/system`. The delegating process does, once the account has
//! done its work, and only when that work succeeded.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use super::{Change, Host, Live, ensure_system, remove_system};
use crate::cli::Command;
use crate::cli::stack::StackCli;
use crate::config::Config;

/// What the root process does for a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Plan {
	/// Leave the system drop-in as the configuration at this path says.
	Ensure(PathBuf),
	/// Remove it: the stack is down.
	Remove,
}

/// The plan for `command`, `None` for a command that leaves the drop-in alone.
pub(super) fn plan(command: &Command) -> Option<Plan> {
	match command {
		Command::Stack { config, action, .. } => match action {
			StackCli::Update
			| StackCli::Up
			| StackCli::Apply
			| StackCli::Restart { .. }
			| StackCli::Start { .. }
			| StackCli::Certs { .. } => Some(Plan::Ensure(config.clone())),
			StackCli::Down => Some(Plan::Remove),
			_ => None,
		},
		Command::Init {
			dry_run: false,
			print_answers: false,
			..
		} => Some(Plan::Ensure(PathBuf::from(crate::cli::DEFAULT_CONFIG))),
		_ => None,
	}
}

/// Carry out `plan` for the user manager of `uid`, whose home is `home`.
/// `None` when there was nothing to do: `Ensure` waits for the account's boot
/// unit to exist, so a command that installed none leaves the host alone.
pub(super) fn apply(
	host: &mut impl Host,
	plan: &Plan,
	uid: u32,
	home: &Path,
	load: impl FnOnce(&Path) -> Result<Config, String>,
) -> Result<Option<Change>, String> {
	match plan {
		Plan::Remove => remove_system(host, uid).map(Some),
		Plan::Ensure(config) => {
			let unit = home.join(".config/systemd/user").join(super::super::UNIT);
			if host.read(&unit)?.is_none() {
				return Ok(None);
			}
			let config = load(config)?;
			ensure_system(host, uid, &config.boot, &config.data_dir).map(Some)
		}
	}
}

/// The configuration as root reads it. A file that validation refuses still
/// says whether the drop-in is wanted.
fn load(path: &Path) -> Result<Config, String> {
	let text = crate::cli::config_edit::read_through_link(path)?;
	Config::parse_text_lenient(&text, path).map_err(|error| error.to_string())
}

/// After the account's process finished with `code`: write or remove the
/// system drop-in. The exit code is the account's own: the command has done
/// what it was asked, so a drop-in that could not be written is a warning that
/// names the repair, never a failure of the command.
pub(in crate::cli) fn after_delegation(command: &Command, code: ExitCode) -> ExitCode {
	if code != ExitCode::SUCCESS {
		return code;
	}
	let Some(plan) = plan(command) else {
		return code;
	};
	let user = match crate::cli::rootless::lookup_user() {
		Ok(Some(user)) => user,
		_ => return code,
	};
	if let Err(error) = apply(&mut Live, &plan, user.uid, &user.home, load) {
		crate::cli::style::warn(format_args!(
			"the user manager of glyndor-epistle is not ordered after the network at boot: {error}; run `sudo epistle stack start` once it is fixed"
		));
	}
	code
}
