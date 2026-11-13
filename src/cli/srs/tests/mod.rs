use std::process::ExitCode;

use clap::Parser;

use super::{StackAction, execute_with};
use crate::cli::resource::Run;
use crate::config::Config;
use crate::test_support::fixtures::fresh_secret;

mod edit;
mod reference;

fn no_restart(_: &Config, _: StackAction) -> ExitCode {
	panic!("a test host has no compose file, so nothing may be restarted")
}

/// Run `epistle srs <args>` on a configuration made of the usual header
/// and `body`.
fn run_srs(body: &str, args: &[&str], dry_run: bool) -> Run {
	let dir = tempfile::tempdir_in(".").unwrap();
	let file = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
	std::fs::write(
		file.path(),
		format!(
			"hostname = 'mail.example.org'\ndata_dir = {:?}\n{body}",
			dir.path().canonicalize().unwrap()
		),
	)
	.unwrap();
	let before = std::fs::read_to_string(file.path()).unwrap();
	let mut full = vec!["epistle", "srs"];
	full.extend_from_slice(args);
	let crate::cli::Command::Srs { action, .. } =
		crate::cli::Cli::try_parse_from(full).unwrap().command
	else {
		unreachable!("srs arguments must select the srs command")
	};
	let (mut out, mut status) = (Vec::new(), Vec::new());
	let result = execute_with(
		file.path(),
		action,
		dry_run,
		false,
		&mut out,
		&mut status,
		no_restart,
	);
	Run {
		result,
		out: String::from_utf8(out).unwrap(),
		status: String::from_utf8(status).unwrap(),
		after: std::fs::read_to_string(file.path()).unwrap(),
		before,
	}
}

fn two_domains_on(global: &str) -> String {
	format!("domains = ['a.example', 'b.example']\nsrs_secret = '{global}'\n")
}

fn loaded(run: &Run) -> Config {
	let dir = tempfile::tempdir_in(".").unwrap();
	let path = dir.path().join("after.toml");
	std::fs::write(&path, &run.after).unwrap();
	std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
	Config::load(&path).expect("the edited file loads")
}

fn fresh() -> String {
	fresh_secret()
}
