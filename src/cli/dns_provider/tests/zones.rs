//! Several zones, one credential each: `set --zone` adds or replaces one entry,
//! `unset --zone` removes one, and the generated compose file keeps the
//! credential of every entry that still reads it.

use super::write::{TOKEN, mail_mounts, mounted, stack_with};
use super::*;
use clap::Parser;

const OTHER: &str = "/etc/epistle/secrets/other.token";
const THIRD: &str = "/etc/epistle/secrets/third.token";

fn command(args: &[&str]) -> DnsCli {
	let mut full = vec!["epistle", "dns", "provider"];
	full.extend_from_slice(args);
	let crate::cli::Command::Dns { action, .. } =
		crate::cli::Cli::try_parse_from(full).unwrap().command
	else {
		unreachable!("dns arguments must select the dns command")
	};
	action
}

fn run_on(path: &std::path::Path, args: &[&str]) -> Result<ExitCode, resource::ResourceError> {
	let (mut out, mut status) = (Vec::new(), Vec::new());
	execute_with(
		path,
		command(args),
		false,
		false,
		&mut out,
		&mut status,
		|_, _| ExitCode::SUCCESS,
	)
}

fn one_zone(file: &str) -> String {
	format!(
		"hostname = 'mail.example.org'\ndata_dir = {{data:?}}\n[dns]\nprovider = 'cloudflare'\nzone = 'example.org'\ntoken_file = '{file}'\n"
	)
}

#[test]
fn a_second_zone_turns_the_table_into_a_list_and_keeps_the_first() {
	let (_dir, path, _compose) = stack_with(&one_zone(TOKEN), &[(TOKEN, TOKEN)]);
	run_on(
		&path,
		&[
			"set",
			"desec",
			"--zone",
			"example.net",
			"--token-file",
			OTHER,
		],
	)
	.unwrap();
	let text = std::fs::read_to_string(&path).unwrap();
	assert!(
		text.contains("[[dns]]") && !text.contains("\n[dns]"),
		"{text}"
	);
	let config = Config::load(&path).unwrap();
	assert_eq!(config.dns.zones(), vec!["example.org", "example.net"]);
	let first = config.dns.for_zone("example.org").unwrap();
	assert_eq!(first.provider, "cloudflare");
	assert_eq!(
		first.token_file.as_deref(),
		Some(std::path::Path::new(TOKEN))
	);
	let second = config.dns.for_zone("example.net").unwrap();
	assert_eq!(second.provider, "desec");
	assert_eq!(
		second.token_file.as_deref(),
		Some(std::path::Path::new(OTHER))
	);
}

#[test]
fn setting_a_zone_that_exists_replaces_only_that_entry() {
	let (_dir, path, _compose) = stack_with(&one_zone(TOKEN), &[(TOKEN, TOKEN)]);
	let add = [
		"set",
		"desec",
		"--zone",
		"example.net",
		"--token-file",
		OTHER,
	];
	run_on(&path, &add).unwrap();
	run_on(
		&path,
		&[
			"set",
			"bunny",
			"--zone",
			"EXAMPLE.net",
			"--token-file",
			THIRD,
		],
	)
	.unwrap();
	let config = Config::load(&path).unwrap();
	assert_eq!(config.dns.len(), 2, "replacing must not add a third entry");
	let replaced = config.dns.for_zone("example.net").unwrap();
	assert_eq!(replaced.provider, "bunny");
	assert_eq!(
		replaced.token_file.as_deref(),
		Some(std::path::Path::new(THIRD))
	);
	let kept = config.dns.for_zone("example.org").unwrap();
	assert_eq!(kept.provider, "cloudflare");
	assert_eq!(
		kept.token_file.as_deref(),
		Some(std::path::Path::new(TOKEN))
	);
}

#[test]
fn each_zone_credential_is_mounted_and_replacing_one_keeps_the_others() {
	let (_dir, path, compose) = stack_with(&one_zone(TOKEN), &[(TOKEN, TOKEN)]);
	run_on(
		&path,
		&[
			"set",
			"desec",
			"--zone",
			"example.net",
			"--token-file",
			OTHER,
		],
	)
	.unwrap();
	assert!(mounted(&compose, TOKEN) && mounted(&compose, OTHER));
	// The second zone moves to another file: its old mount goes, the first
	// zone's stays.
	run_on(
		&path,
		&[
			"set",
			"desec",
			"--zone",
			"example.net",
			"--token-file",
			THIRD,
		],
	)
	.unwrap();
	assert!(mounted(&compose, TOKEN), "the first zone lost its token");
	assert!(mounted(&compose, THIRD));
	assert!(!mounted(&compose, OTHER), "a replaced token stayed mounted");
}

#[test]
fn a_token_file_that_two_zones_read_stays_mounted_once() {
	let (_dir, path, compose) = stack_with(&one_zone(TOKEN), &[(TOKEN, TOKEN)]);
	// The second zone reads the same file as the first.
	run_on(
		&path,
		&[
			"set",
			"desec",
			"--zone",
			"example.net",
			"--token-file",
			TOKEN,
		],
	)
	.unwrap();
	assert_eq!(
		mail_mounts(&compose)
			.iter()
			.filter(|mount| mount["source"] == TOKEN)
			.count(),
		1,
		"one file must be mounted once"
	);
	// The first zone moves away; the second still needs the file.
	run_on(
		&path,
		&[
			"set",
			"cloudflare",
			"--zone",
			"example.org",
			"--token-file",
			OTHER,
		],
	)
	.unwrap();
	assert!(
		mounted(&compose, TOKEN),
		"a token another zone reads was unmounted"
	);
	assert!(mounted(&compose, OTHER));
}

#[test]
fn unset_with_a_zone_removes_only_that_entry() {
	let (_dir, path, _compose) = stack_with(&one_zone(TOKEN), &[(TOKEN, TOKEN)]);
	run_on(
		&path,
		&[
			"set",
			"desec",
			"--zone",
			"example.net",
			"--token-file",
			OTHER,
		],
	)
	.unwrap();
	run_on(&path, &["unset", "--zone", "example.org"]).unwrap();
	let config = Config::load(&path).unwrap();
	assert_eq!(config.dns.zones(), vec!["example.net"]);
}

#[test]
fn unset_with_a_zone_nobody_configured_changes_nothing() {
	let (_dir, path, _compose) = stack_with(&one_zone(TOKEN), &[(TOKEN, TOKEN)]);
	let before = std::fs::read_to_string(&path).unwrap();
	let result = run_on(&path, &["unset", "--zone", "example.com"]);
	assert!(result.is_err(), "a zone with no entry is not a removal");
	assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
	// The lone table of another zone is no match either.
	assert!(run_on(&path, &["unset", "--zone", "example.org.evil"]).is_err());
}

#[test]
fn unset_without_a_zone_removes_every_entry() {
	let (_dir, path, _compose) = stack_with(&one_zone(TOKEN), &[(TOKEN, TOKEN)]);
	run_on(
		&path,
		&[
			"set",
			"desec",
			"--zone",
			"example.net",
			"--token-file",
			OTHER,
		],
	)
	.unwrap();
	run_on(&path, &["unset"]).unwrap();
	assert!(Config::load(&path).unwrap().dns.is_empty());
}

#[test]
fn show_lists_every_entry_and_no_secret() {
	let (_dir, path, _compose) = stack_with(&one_zone(TOKEN), &[(TOKEN, TOKEN)]);
	run_on(
		&path,
		&[
			"set",
			"desec",
			"--zone",
			"example.net",
			"--token-file",
			OTHER,
		],
	)
	.unwrap();
	let mut out = Vec::new();
	let mut status = Vec::new();
	execute_with(
		&path,
		command(&["show", "--json"]),
		false,
		false,
		&mut out,
		&mut status,
		|_, _| ExitCode::SUCCESS,
	)
	.unwrap();
	let listed: serde_json::Value = serde_json::from_slice(&out).unwrap();
	let zones: Vec<&str> = listed
		.as_array()
		.expect("several entries print a list")
		.iter()
		.map(|entry| entry["zone"].as_str().unwrap())
		.collect();
	assert_eq!(zones, vec!["example.org", "example.net"]);
}

#[test]
fn stored_tokens_get_a_file_each_once_there_is_a_second_zone() {
	let (_dir, path, _compose) = stack_with(&one_zone(TOKEN), &[(TOKEN, TOKEN)]);
	let config = Config::load(&path).unwrap();
	let args = ProviderArgs {
		store_token: true,
		..ProviderArgs::default()
	};
	let alone = super::super::write::store_destination(&config, &args, "example.org");
	let second = super::super::write::store_destination(&config, &args, "example.net");
	assert_eq!(alone.unwrap().file_name().unwrap(), "dns_provider_token");
	assert_eq!(
		second.unwrap().file_name().unwrap(),
		"dns_provider_token_example_net"
	);
}
