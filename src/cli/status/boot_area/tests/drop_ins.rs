//! The drop-in items and the services item against a fake host.

use std::path::{Path, PathBuf};

use super::base::{Fake, config, good, item, run};
use super::*;
use crate::cli::stack::autostart::dropins;

fn user_file() -> PathBuf {
	PathBuf::from("/home/u/.config/systemd/user/podup-epistle.service.d/10-epistle.conf")
}

fn config_with(extra: &str) -> Config {
	let text = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"/data\"\ndomains = [\"example.org\"]\n\n[[listeners]]\nkind = \"smtp\"\naddr = \"0.0.0.0\"\nport = 25\n{extra}"
	);
	Config::parse_text(&text, Path::new("/etc/epistle/mail.toml")).expect("config")
}

fn judged(host: &mut Fake, extra: &str) -> AreaReport {
	check_with(host, &config_with(extra))
}

#[test]
fn both_drop_ins_in_place_are_ok_and_say_what_they_do() {
	let mut host = good();
	let report = run(&mut host);
	let retry = item(&report, "retry drop-in");
	assert_eq!(retry.status, Level::Ok, "{retry:?}");
	assert!(retry.detail.contains("every 30 seconds"), "{retry:?}");
	let order = item(&report, "order drop-in");
	assert_eq!(order.status, Level::Ok, "{order:?}");
	assert!(order.detail.contains("user@1001.service"), "{order:?}");
}

#[test]
fn a_missing_user_drop_in_is_a_warning_with_the_command_that_writes_it() {
	let mut host = good();
	host.files.remove(&user_file());
	let report = run(&mut host);
	let retry = item(&report, "retry drop-in");
	assert_eq!(retry.status, Level::Warn, "{retry:?}");
	assert!(retry.detail.contains("10-epistle.conf"), "{retry:?}");
	assert!(
		retry.detail.contains("sudo epistle stack start"),
		"{retry:?}"
	);
}

#[test]
fn a_user_drop_in_that_is_not_what_epistle_writes_is_a_warning() {
	let mut host = good();
	host.files
		.insert(user_file(), "[Service]\nRestart=no\n".into());
	let report = run(&mut host);
	assert_eq!(item(&report, "retry drop-in").status, Level::Warn);
}

#[test]
fn a_missing_system_drop_in_is_a_warning_that_says_root_writes_it() {
	let mut host = good();
	host.files.remove(&dropins::system_path(1001));
	let report = run(&mut host);
	let order = item(&report, "order drop-in");
	assert_eq!(order.status, Level::Warn, "{order:?}");
	assert!(order.detail.contains("user@1001.service.d"), "{order:?}");
	assert!(order.detail.contains("only root can"), "{order:?}");
}

#[test]
fn a_system_drop_in_without_the_mount_the_data_dir_needs_is_stale() {
	let mut host = good();
	host.files.insert(
		PathBuf::from("/proc/self/mountinfo"),
		"1 0 8:1 / / rw - ext4 /dev/sda1 rw\n2 1 8:2 / /data rw - ext4 /dev/sdb1 rw\n".into(),
	);
	let report = run(&mut host);
	assert_eq!(item(&report, "order drop-in").status, Level::Warn);
	host.files.insert(
		dropins::system_path(1001),
		dropins::system_text(Some(Path::new("/data"))).unwrap(),
	);
	let report = run(&mut host);
	assert_eq!(item(&report, "order drop-in").status, Level::Ok);
}

#[test]
fn the_configuration_turns_each_drop_in_off_and_the_items_say_so() {
	let mut host = good();
	host.files.remove(&user_file());
	host.files.remove(&dropins::system_path(1001));
	let report = judged(
		&mut host,
		"[boot]\nrestart_on_failure = false\norder_after_network = false\n",
	);
	for name in ["retry drop-in", "order drop-in"] {
		let found = item(&report, name);
		assert_eq!(found.status, Level::Ok, "{found:?}");
		assert!(found.detail.contains("turned off"), "{found:?}");
	}
}

#[test]
fn a_drop_in_left_behind_after_it_was_turned_off_is_a_warning() {
	let mut host = good();
	let report = judged(
		&mut host,
		"[boot]\nrestart_on_failure = false\norder_after_network = false\n",
	);
	for name in ["retry drop-in", "order drop-in"] {
		let found = item(&report, name);
		assert_eq!(found.status, Level::Warn, "{found:?}");
		assert!(found.detail.contains("removes it"), "{found:?}");
	}
}

#[test]
fn a_systemd_that_refuses_the_retry_is_named() {
	let mut host = good();
	host.version = Some(243);
	let report = run(&mut host);
	let retry = item(&report, "retry drop-in");
	assert_eq!(retry.status, Level::Warn, "{retry:?}");
	assert!(retry.detail.contains("243"), "{retry:?}");
	assert!(retry.detail.contains("244"), "{retry:?}");
}

#[test]
fn every_service_running_is_ok() {
	let mut host = good();
	let report = run(&mut host);
	assert_eq!(item(&report, "services").status, Level::Ok);
}

#[test]
fn a_service_that_is_down_is_named_with_its_error_and_the_command_that_starts_it() {
	let mut host = good();
	host.ps = Ok(r#"[{"Service":"mail","State":"exited","ExitCode":126},{"Service":"db","State":"running","ExitCode":0}]"#.into());
	host.log =
		"Starting epistle\nepistle-mail-1: OCI runtime error: bind: address in use\nStarted\n"
			.into();
	let report = run(&mut host);
	let services = item(&report, "services");
	assert_eq!(services.status, Level::Warn, "{services:?}");
	assert!(
		services.detail.contains("mail is exited with status 126"),
		"{services:?}"
	);
	assert!(
		services.detail.contains("bind: address in use"),
		"{services:?}"
	);
	assert!(
		services.detail.contains("`sudo epistle stack start mail`"),
		"{services:?}"
	);
	assert!(!services.detail.contains("db is"), "{services:?}");
}

#[test]
fn a_service_with_no_container_is_started_by_up_which_creates_it() {
	let mut host = good();
	host.ps = Ok(r#"[{"Service":"db","State":"running","ExitCode":0}]"#.into());
	let report = run(&mut host);
	let services = item(&report, "services");
	assert!(
		services.detail.contains("mail has no container"),
		"{services:?}"
	);
	assert!(
		services.detail.contains("`sudo epistle stack up`"),
		"{services:?}"
	);
}

#[test]
fn a_service_that_is_down_after_the_unit_failed_is_a_fail() {
	let mut host = good();
	host.ps = Ok(r#"[{"Service":"mail","State":"exited","ExitCode":1},{"Service":"db","State":"running","ExitCode":0}]"#.into());
	host.user.insert(
		"show podup-epistle.service -p ActiveState -p Result".into(),
		"ActiveState=failed\nResult=exit-code".into(),
	);
	let report = run(&mut host);
	assert_eq!(item(&report, "services").status, Level::Fail);
	assert_eq!(report.status, Level::Fail);
}

#[test]
fn a_unit_still_starting_does_not_judge_the_services() {
	let mut host = good();
	host.ps = Ok(r#"[]"#.into());
	host.user.insert(
		"show podup-epistle.service -p ActiveState -p Result".into(),
		"ActiveState=activating\nResult=success".into(),
	);
	let report = run(&mut host);
	let services = item(&report, "services");
	assert_eq!(services.status, Level::Warn, "{services:?}");
	assert!(services.detail.contains("still starting"), "{services:?}");
}

#[test]
fn a_job_that_finished_and_is_not_meant_to_restart_is_not_down() {
	let mut host = good();
	host.files.insert(
		PathBuf::from("/data/compose/compose.yaml"),
		serde_json::json!({"services": {
			"mail": {"image": "ghcr.io/glyndor/epistle:1", "restart": "unless-stopped"},
			"db": {"image": "postgres:18", "restart": "unless-stopped"},
			"setup": {"image": "postgres:18"},
		}})
		.to_string(),
	);
	host.images.insert("postgres:18".into());
	host.ps = Ok(r#"[{"Service":"mail","State":"running","ExitCode":0},{"Service":"db","State":"running","ExitCode":0},{"Service":"setup","State":"exited","ExitCode":0}]"#.into());
	let report = run(&mut host);
	assert_eq!(item(&report, "services").status, Level::Ok);
}

#[test]
fn a_service_behind_a_profile_is_not_expected_to_run() {
	let mut host = good();
	host.files.insert(
		PathBuf::from("/data/compose/compose.yaml"),
		serde_json::json!({"services": {
			"mail": {"image": "ghcr.io/glyndor/epistle:1", "restart": "unless-stopped"},
			"db": {"image": "postgres:18", "restart": "unless-stopped"},
			"clamav": {"image": "postgres:18", "restart": "unless-stopped", "profiles": ["scan"]},
		}})
		.to_string(),
	);
	let report = run(&mut host);
	assert_eq!(item(&report, "services").status, Level::Ok);
}

#[test]
fn podup_that_cannot_answer_is_a_warning_not_a_guess() {
	let mut host = good();
	host.ps = Err("cannot run podup: not found".into());
	let report = run(&mut host);
	assert_eq!(item(&report, "services").status, Level::Warn);
}

#[test]
fn the_summary_leaves_out_what_is_written_or_asked_after_it() {
	let mut host = good();
	host.files.remove(&dropins::system_path(1001));
	host.ps = Err("podup must not be asked".into());
	let report = judge(&mut host, &config(), true);
	let names: Vec<&str> = report.items.iter().map(|item| item.name.as_str()).collect();
	assert_eq!(report.items.len(), 11, "{names:?}");
	assert!(!names.contains(&"services") && !names.contains(&"order drop-in"));
	assert_eq!(report.status, Level::Ok, "{report:?}");
}
