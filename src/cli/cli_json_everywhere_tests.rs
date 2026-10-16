//! Every leaf command takes `--json`, so a script can drive the whole CLI
//! without scraping human text. The few commands whose stdout is already a
//! data stream or a long-running process are named below with the reason.
//! The hidden flat commands kept for old scripts are held to the same rule,
//! because those scripts are the ones that scrape text today.

use clap::CommandFactory;

use crate::cli::Cli;

/// Leaves that never print a JSON result, with the reason. A new entry
/// here needs the same kind of reason: stdout is the product, or the
/// command never returns a result.
const JSON_EXEMPT: &[(&str, &str)] = &[
	(
		"epistle serve",
		"runs the mail server until it is stopped; it has no result",
	),
	(
		"epistle local",
		"runs a loopback test server until it is stopped",
	),
	(
		"epistle mta-sts-serve",
		"serves the MTA-STS policy until it is stopped",
	),
	(
		"epistle stack logs",
		"streams the services' raw log lines; refuses --json",
	),
	(
		"epistle completions",
		"stdout is the shell completion script itself",
	),
	(
		"epistle export",
		"stdout is the mbox stream, or nothing with --maildir",
	),
	("epistle backup", "stdout is the gzip tar archive"),
	(
		"epistle report-abuse",
		"stdout is the RFC 5965 report message to send",
	),
	(
		"epistle mobileconfig",
		"stdout is the Apple profile the user installs",
	),
	(
		"epistle autoconfig",
		"stdout is the Thunderbird XML document to host",
	),
	(
		"epistle autodiscover",
		"stdout is the Autodiscover XML document to host",
	),
];

/// Hidden leaves that are not a user interface: the package's upgrade
/// hooks and a step the CLI re-runs as the service account. They print no
/// result a script reads.
const INTERNAL: &[(&str, &str)] = &[
	(
		"epistle move-subids",
		"run by the package on upgrade, as root; prints nothing a script reads",
	),
	(
		"epistle manpages",
		"run by the package build to write the man pages into a directory",
	),
	(
		"epistle stack rollback-db",
		"the database half of `stack rollback`, re-run as the service account",
	),
];

/// Every leaf command, as its path from the root: the visible ones, and
/// the hidden ones too when `hidden` is set.
fn leaves(hidden: bool) -> Vec<(String, clap::Command)> {
	fn walk(
		prefix: &str,
		command: &clap::Command,
		hidden: bool,
		out: &mut Vec<(String, clap::Command)>,
	) {
		for sub in command
			.get_subcommands()
			.filter(|sub| hidden || !sub.is_hide_set())
		{
			let path = format!("{prefix} {}", sub.get_name());
			if sub.has_subcommands() {
				walk(&path, sub, hidden, out);
			} else {
				out.push((path, sub.clone()));
			}
		}
	}
	let mut root = Cli::command();
	root.build();
	let mut out = Vec::new();
	walk("epistle", &root, hidden, &mut out);
	out
}

/// Every visible leaf command, as its path from the root.
fn visible_leaves() -> Vec<(String, clap::Command)> {
	leaves(false)
}

#[test]
fn every_leaf_takes_json_unless_exempt() {
	let missing: Vec<String> = visible_leaves()
		.into_iter()
		.filter(|(path, _)| !JSON_EXEMPT.iter().any(|(exempt, _)| exempt == path))
		.filter(|(_, command)| {
			!command
				.get_arguments()
				.any(|arg| arg.get_long() == Some("json"))
		})
		.map(|(path, _)| path)
		.collect();
	assert!(
		missing.is_empty(),
		"leaf commands without --json: {missing:#?}"
	);
}

#[test]
fn every_hidden_leaf_takes_json_unless_internal() {
	let visible: Vec<String> = visible_leaves().into_iter().map(|(path, _)| path).collect();
	let missing: Vec<String> = leaves(true)
		.into_iter()
		.filter(|(path, _)| !visible.contains(path))
		.filter(|(path, _)| !INTERNAL.iter().any(|(internal, _)| internal == path))
		.filter(|(_, command)| {
			!command
				.get_arguments()
				.any(|arg| arg.get_long() == Some("json"))
		})
		.map(|(path, _)| path)
		.collect();
	assert!(
		missing.is_empty(),
		"hidden leaf commands without --json: {missing:#?}"
	);
}

#[test]
fn every_internal_leaf_is_a_hidden_leaf_with_a_reason() {
	let visible: Vec<String> = visible_leaves().into_iter().map(|(path, _)| path).collect();
	let hidden = leaves(true);
	for (path, reason) in INTERNAL {
		assert!(
			!reason.is_empty(),
			"{path}: an internal leaf needs its reason"
		);
		assert!(
			!visible.iter().any(|leaf| leaf == path),
			"{path} is listed as internal but is visible"
		);
		assert!(
			hidden.iter().any(|(leaf, _)| leaf == path),
			"{path} is listed as internal but is not a leaf command"
		);
	}
}

#[test]
fn every_exemption_names_a_real_leaf_without_its_own_json() {
	let leaves = visible_leaves();
	for (path, reason) in JSON_EXEMPT {
		assert!(!reason.is_empty(), "{path}: an exemption needs its reason");
		let Some((_, command)) = leaves.iter().find(|(leaf, _)| leaf == path) else {
			panic!("{path} is exempt but is not a visible leaf command");
		};
		let local_json = command
			.get_arguments()
			.any(|arg| arg.get_long() == Some("json") && !arg.is_global_set());
		assert!(!local_json, "{path} is exempt but declares its own --json");
	}
}
