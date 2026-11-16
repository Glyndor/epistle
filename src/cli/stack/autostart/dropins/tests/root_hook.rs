//! Which commands the root process writes the system drop-in for, and what
//! it does when the account's own process already ran.

use std::path::{Path, PathBuf};

use clap::Parser;

use super::super::root::{Plan, apply, plan};
use super::fake::Fake;
use super::*;
use crate::cli::{Cli, Command};
use crate::config::Config;

fn command(args: &[&str]) -> Command {
	let mut argv = vec!["epistle"];
	argv.extend_from_slice(args);
	Cli::try_parse_from(argv).expect("parse").command
}

fn config(extra: &str) -> Result<Config, String> {
	let text = format!("hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n{extra}");
	Config::parse_text(&text, Path::new("mail.toml")).map_err(|error| error.to_string())
}

fn unit() -> PathBuf {
	PathBuf::from("/var/lib/glyndor/epistle/.config/systemd/user/podup-epistle.service")
}

const HOME: &str = "/var/lib/glyndor/epistle";

#[test]
fn the_commands_that_leave_the_stack_running_ensure_the_drop_in() {
	for args in [
		&["stack", "up"][..],
		&["stack", "update"],
		&["stack", "apply"],
		&["stack", "restart"],
		&["stack", "restart", "mail"],
		&["stack", "start"],
		&["stack", "start", "mail"],
		&["stack", "certs", "enable", "--yes"],
		&["init"],
	] {
		assert!(
			matches!(plan(&command(args)), Some(Plan::Ensure(_))),
			"{args:?}"
		);
	}
}

#[test]
fn stack_down_removes_the_drop_in() {
	assert_eq!(plan(&command(&["stack", "down"])), Some(Plan::Remove));
}

#[test]
fn stop_and_the_reads_leave_the_drop_in_alone() {
	for args in [
		&["stack", "stop"][..],
		&["stack", "stop", "mail"],
		&["stack", "ps"],
		&["stack", "logs"],
		&["stack", "resources"],
		&["init", "--dry-run"],
		&["init", "--print-answers"],
		&["status"],
	] {
		assert_eq!(plan(&command(args)), None, "{args:?}");
	}
}

#[test]
fn the_plan_carries_the_configuration_the_operator_named() {
	let plan = plan(&command(&["stack", "up", "--config", "/srv/mail.toml"]));
	assert_eq!(plan, Some(Plan::Ensure(PathBuf::from("/srv/mail.toml"))));
}

#[test]
fn an_ensure_writes_the_drop_in_once_the_unit_exists() {
	let mut host = Fake::new(true);
	host.files.insert(unit(), "[Service]\n".into());
	let plan = Plan::Ensure(PathBuf::from("/etc/epistle/mail.toml"));
	let change = apply(&mut host, &plan, 996, Path::new(HOME), |_| config(""));
	assert_eq!(change, Ok(Some(Change::Written)));
	assert!(host.files.contains_key(&system_path(996)));
}

#[test]
fn an_ensure_without_a_boot_unit_leaves_the_host_alone() {
	let mut host = Fake::new(true);
	let plan = Plan::Ensure(PathBuf::from("/etc/epistle/mail.toml"));
	let change = apply(&mut host, &plan, 996, Path::new(HOME), |_| config(""));
	assert_eq!(change, Ok(None));
	assert!(host.untouched());
}

#[test]
fn an_ensure_that_is_not_root_writes_nothing_and_says_why() {
	let mut host = Fake::new(false);
	host.files.insert(unit(), "[Service]\n".into());
	let plan = Plan::Ensure(PathBuf::from("/etc/epistle/mail.toml"));
	let error = apply(&mut host, &plan, 996, Path::new(HOME), |_| config("")).unwrap_err();
	assert!(error.contains("only root writes it"), "{error}");
	assert!(host.untouched());
}

#[test]
fn the_configuration_switch_reaches_the_root_process() {
	let mut host = Fake::new(true);
	host.files.insert(unit(), "[Service]\n".into());
	host.files
		.insert(system_path(996), system_text(None).unwrap());
	let plan = Plan::Ensure(PathBuf::from("/etc/epistle/mail.toml"));
	let off = "[boot]\norder_after_network = false\n";
	let change = apply(&mut host, &plan, 996, Path::new(HOME), |_| config(off));
	assert_eq!(change, Ok(Some(Change::Removed)));
	assert!(!host.files.contains_key(&system_path(996)));
}

#[test]
fn an_unreadable_configuration_changes_nothing() {
	let mut host = Fake::new(true);
	host.files.insert(unit(), "[Service]\n".into());
	host.files
		.insert(system_path(996), system_text(None).unwrap());
	let plan = Plan::Ensure(PathBuf::from("/etc/epistle/mail.toml"));
	let error = apply(&mut host, &plan, 996, Path::new(HOME), |_| {
		Err("cannot read".to_string())
	})
	.unwrap_err();
	assert!(error.contains("cannot read"), "{error}");
	assert!(host.untouched());
}

#[test]
fn a_remove_needs_no_configuration_and_no_unit() {
	let mut host = Fake::new(true);
	host.files
		.insert(system_path(996), system_text(None).unwrap());
	let change = apply(&mut host, &Plan::Remove, 996, Path::new(HOME), |_| {
		Err("the configuration is gone".to_string())
	});
	assert_eq!(change, Ok(Some(Change::Removed)));
	assert!(host.files.is_empty());
}
