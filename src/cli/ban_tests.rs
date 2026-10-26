//! Parsing and the no-database path of `epistle ban`. The actions against
//! PostgreSQL are covered by `tests/database_bans_admin.rs`.

use super::*;
use crate::cli::{Cli, Command};
use clap::Parser;

fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
	let mut argv = vec!["epistle", "ban"];
	argv.extend(args);
	Cli::try_parse_from(argv)
}

#[test]
fn durations_take_a_unit_and_reject_nonsense() {
	for (text, secs) in [
		("90", 90),
		("45s", 45),
		("90m", 5_400),
		("24h", 86_400),
		("7d", 604_800),
		("2w", 1_209_600),
	] {
		assert_eq!(parse_duration(text), Ok(secs), "{text}");
	}
	for text in ["", "h", "0", "0h", "-5m", "1.5h", "3y", "99999d", "5 m"] {
		assert!(parse_duration(text).is_err(), "{text:?} must be rejected");
	}
}

#[test]
fn targets_normalise_to_one_subject_each() {
	let ip = BanTarget::parse("203.0.113.9").expect("ip");
	assert_eq!(ip.subject(), "ip:203.0.113.9");
	assert_eq!(ip.to_string(), "203.0.113.9");
	// A /32 is the same ban as the bare address.
	assert_eq!(BanTarget::parse("203.0.113.9/32").expect("host"), ip);
	assert_eq!(
		BanTarget::parse("2001:db8::1/128")
			.expect("v6 host")
			.subject(),
		"ip:2001:db8::1"
	);
	// Host bits are zeroed, so two spellings of a block are one row.
	let net = BanTarget::parse("203.0.113.77/24").expect("net");
	assert_eq!(net.subject(), "cidr:203.0.113.0/24");
	assert_eq!(net.to_string(), "203.0.113.0/24");
}

#[test]
fn targets_reject_junk_and_the_whole_internet() {
	assert!(BanTarget::parse("not-an-ip").is_err());
	assert!(BanTarget::parse("203.0.113.0/33").is_err());
	assert_eq!(
		BanTarget::parse("0.0.0.0/0").expect_err("everything"),
		"refusing to ban every address (prefix length 0)"
	);
	assert!(BanTarget::parse("::/0").is_err());
}

#[test]
fn every_form_parses_and_a_bad_argument_does_not() {
	for args in [
		vec!["list"],
		vec!["list", "--json"],
		vec!["add", "203.0.113.9"],
		vec!["add", "203.0.113.0/24", "--for", "24h"],
		vec!["remove", "203.0.113.9"],
		vec!["remove", "pair:alice|10.0.2.15"],
		vec!["remove", "pair:alice|unknown"],
		vec!["remove", "account:alice"],
		vec!["remove", "--account", "alice", "--ip", "10.0.2.15"],
		vec!["allow", "list"],
		vec!["allow", "list", "--json"],
		vec!["allow", "add", "10.0.0.0/8"],
		vec!["allow", "remove", "10.0.0.0/8"],
		vec!["--config", "/tmp/x.toml", "list"],
		vec!["list", "--config", "/tmp/x.toml"],
	] {
		let cli = parse(&args).unwrap_or_else(|e| panic!("{args:?}: {e}"));
		assert!(matches!(cli.command, Command::Ban { .. }), "{args:?}");
	}
	for args in [
		vec![],
		vec!["add"],
		vec!["add", "nope"],
		vec!["add", "1.2.3.4", "--for", "0"],
		vec!["add", "1.2.3.4", "--for", "forever"],
		vec!["remove"],
		vec!["remove", "--account", "alice"],
		vec!["remove", "--ip", "10.0.2.15"],
		vec!["remove", "--account", "alice", "--ip", "nope"],
		vec![
			"remove",
			"10.0.2.15",
			"--account",
			"alice",
			"--ip",
			"10.0.2.15",
		],
		vec!["remove", "pair:alice"],
		vec!["remove", "pair:|10.0.2.15"],
		vec!["remove", "pair:alice|nope"],
		vec!["remove", "account:"],
		vec!["add", "pair:alice|10.0.2.15"],
		vec!["add", "account:alice"],
		vec!["allow"],
		vec!["allow", "add", "nope"],
		vec!["allow", "add"],
	] {
		assert!(parse(&args).is_err(), "{args:?} must not parse");
	}
}

#[test]
fn without_a_database_every_action_says_bans_are_not_manageable() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = crate::cli::tests_b::config_at(dir.path());
	let config = Config::load(config.path()).expect("config");
	assert!(config.database.is_none());
	for args in [
		vec!["list"],
		vec!["add", "203.0.113.9"],
		vec!["allow", "list"],
	] {
		let Command::Ban { action, .. } = parse(&args).expect("parse").command else {
			panic!("not a ban command");
		};
		let (mut out, mut err) = (Vec::new(), Vec::new());
		let code = run(&config, action, false, 100, &mut out, &mut err);
		assert_eq!(code, ExitCode::FAILURE, "{args:?}");
		assert!(out.is_empty(), "{args:?}");
		let err = String::from_utf8(err).expect("utf8");
		assert!(
			err.contains(
				"bans are kept in memory by the running server and are not manageable from the CLI"
			),
			"{args:?}: {err}"
		);
	}
}
