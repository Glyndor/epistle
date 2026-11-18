//! The content of both drop-ins and the way they are written and removed.

use std::path::{Path, PathBuf};

use super::fake::Fake;
use super::*;
use crate::config::Boot;

fn data_dir() -> PathBuf {
	PathBuf::from("/var/lib/glyndor/epistle/data")
}

fn user_file() -> PathBuf {
	user_path(Path::new("/home/a/.config"))
}

fn off() -> Boot {
	Boot {
		restart_on_failure: false,
		order_after_network: false,
	}
}

#[test]
fn the_user_drop_in_retries_a_failed_start_without_giving_up() {
	let text = user_text();
	assert!(text.contains("[Unit]\nStartLimitIntervalSec=0\n"), "{text}");
	assert!(text.contains("[Service]\nRestart=on-failure\n"), "{text}");
	assert!(text.contains("RestartSec=30s\n"), "{text}");
	assert!(text.contains("TimeoutStartSec=15min\n"), "{text}");
}

#[test]
fn the_start_limit_is_in_the_unit_section_where_systemd_reads_it() {
	let text = user_text();
	let unit = text.find("[Unit]").expect("unit section");
	let service = text.find("[Service]").expect("service section");
	let limit = text.find("StartLimitIntervalSec=0").expect("limit");
	assert!(unit < limit && limit < service, "{text}");
}

#[test]
fn the_system_drop_in_orders_the_user_manager_after_the_network_and_the_sysctl() {
	let text = system_text(None).unwrap();
	assert!(text.contains("[Unit]\n"), "{text}");
	assert!(text.contains("Wants=network-online.target\n"), "{text}");
	assert!(
		text.contains("After=network-online.target systemd-sysctl.service\n"),
		"{text}"
	);
	assert!(!text.contains("RequiresMountsFor"), "{text}");
}

#[test]
fn a_data_dir_on_its_own_mount_is_waited_for() {
	let text = system_text(Some(&data_dir())).unwrap();
	assert!(
		text.contains("RequiresMountsFor=/var/lib/glyndor/epistle/data\n"),
		"{text}"
	);
}

/// The hard rule: a reboot only brings existing containers up. An `Exec` line
/// in a drop-in would replace or add to what the unit runs, and the unit's own
/// `up -d --no-build --pull never` is what keeps a reboot from building,
/// pulling or recreating.
#[test]
fn neither_drop_in_runs_anything() {
	for text in [
		user_text(),
		system_text(None).unwrap(),
		system_text(Some(&data_dir())).unwrap(),
	] {
		for line in text.lines() {
			assert!(!line.trim_start().starts_with("Exec"), "{line}");
		}
		for word in ["podup", "podman", "--pull", "--build", "up -d", "ExecStart"] {
			assert!(!text.contains(word), "{word} in {text}");
		}
	}
}

#[test]
fn the_paths_are_the_ones_systemd_reads() {
	assert_eq!(
		user_file(),
		Path::new("/home/a/.config/systemd/user/podup-epistle.service.d/10-epistle.conf")
	);
	assert_eq!(
		system_path(996),
		Path::new("/etc/systemd/system/user@996.service.d/glyndor-epistle-boot.conf")
	);
}

#[test]
fn a_mount_of_its_own_is_found_in_the_mount_table() {
	let table = "20 1 8:1 / / rw - ext4 /dev/sda1 rw\n40 20 8:2 / /var/lib/glyndor rw - ext4 /dev/sda2 rw\n";
	assert_eq!(own_mount(table, &data_dir()), Some(data_dir()));
	assert_eq!(own_mount(table, Path::new("/srv/data")), None);
	assert_eq!(own_mount(table, Path::new("/var/lib/glyndorx")), None);
	let only_root = "20 1 8:1 / / rw - ext4 /dev/sda1 rw\n";
	assert_eq!(own_mount(only_root, &data_dir()), None);
}

#[test]
fn a_mount_point_with_a_space_is_unescaped() {
	let table = "40 20 8:2 / /srv/my\\040disk rw - ext4 /dev/sda2 rw\n";
	let path = Path::new("/srv/my disk/data");
	assert_eq!(own_mount(table, path), Some(path.to_path_buf()));
}

#[test]
fn the_user_drop_in_is_written_once_and_a_second_run_changes_nothing() {
	let mut host = Fake::new(false);
	let first = ensure_user(&mut host, &user_file(), &Boot::default()).unwrap();
	assert_eq!(first, Outcome::Done(Change::Written));
	assert_eq!(host.files[&user_file()], user_text());
	assert_eq!(host.reloads, vec![Scope::User]);
	let again = ensure_user(&mut host, &user_file(), &Boot::default()).unwrap();
	assert_eq!(again, Outcome::Done(Change::Unchanged));
	assert_eq!(host.writes.len(), 1, "the second run wrote again");
	assert_eq!(host.reloads.len(), 1, "the second run reloaded again");
}

#[test]
fn a_stale_user_drop_in_is_rewritten() {
	let mut host = Fake::new(false);
	host.files
		.insert(user_file(), "[Service]\nRestart=no\n".into());
	let outcome = ensure_user(&mut host, &user_file(), &Boot::default()).unwrap();
	assert_eq!(outcome, Outcome::Done(Change::Written));
	assert_eq!(host.files[&user_file()], user_text());
}

#[test]
fn the_user_drop_in_is_not_written_on_a_systemd_that_refuses_it() {
	let mut host = Fake::new(false);
	host.version = Some(243);
	let outcome = ensure_user(&mut host, &user_file(), &Boot::default()).unwrap();
	assert_eq!(outcome, Outcome::TooOld(243));
	assert!(host.untouched());
	host.version = Some(244);
	let outcome = ensure_user(&mut host, &user_file(), &Boot::default()).unwrap();
	assert_eq!(outcome, Outcome::Done(Change::Written));
}

#[test]
fn an_unreadable_systemd_version_is_an_error_not_a_guess() {
	let mut host = Fake::new(false);
	host.version = None;
	assert!(ensure_user(&mut host, &user_file(), &Boot::default()).is_err());
	assert!(host.untouched());
}

#[test]
fn the_configuration_turns_the_user_drop_in_off_and_removes_it() {
	let mut host = Fake::new(false);
	host.files.insert(user_file(), user_text());
	let outcome = ensure_user(&mut host, &user_file(), &off()).unwrap();
	assert_eq!(outcome, Outcome::Done(Change::Removed));
	assert!(host.files.is_empty());
	assert_eq!(host.reloads, vec![Scope::User]);
	let again = ensure_user(&mut host, &user_file(), &off()).unwrap();
	assert_eq!(again, Outcome::Done(Change::Unchanged));
	assert_eq!(host.removals.len(), 1);
}

#[test]
fn stack_down_removes_the_user_drop_in() {
	let mut host = Fake::new(false);
	host.files.insert(user_file(), user_text());
	assert_eq!(remove_user(&mut host, &user_file()), Ok(Change::Removed));
	assert!(host.files.is_empty());
	assert_eq!(remove_user(&mut host, &user_file()), Ok(Change::Unchanged));
}

#[test]
fn nothing_is_written_to_the_system_without_root() {
	let mut host = Fake::new(false);
	let error = ensure_system(&mut host, 996, &Boot::default(), &data_dir()).unwrap_err();
	assert!(
		error.contains("only root writes it"),
		"the refusal must say who may write it"
	);
	assert!(
		error.contains("/etc/systemd/system/user@996.service.d"),
		"the refusal must name the drop-in directory"
	);
	assert!(host.untouched(), "something was done without root");
	assert!(remove_system(&mut host, 996).is_err());
	assert!(host.untouched());
}

#[test]
fn the_system_drop_in_is_written_once_by_root() {
	let mut host = Fake::new(true);
	let first = ensure_system(&mut host, 996, &Boot::default(), &data_dir()).unwrap();
	assert_eq!(first, Change::Written);
	assert_eq!(host.files[&system_path(996)], system_text(None).unwrap());
	assert_eq!(host.reloads, vec![Scope::System]);
	let again = ensure_system(&mut host, 996, &Boot::default(), &data_dir()).unwrap();
	assert_eq!(again, Change::Unchanged);
	assert_eq!(host.writes.len(), 1);
	assert_eq!(host.reloads.len(), 1);
}

#[test]
fn the_system_drop_in_waits_for_a_data_dir_on_its_own_mount() {
	let mut host = Fake::new(true);
	host.files.insert(
		PathBuf::from(MOUNTINFO),
		"20 1 8:1 / / rw - ext4 /dev/sda1 rw\n40 20 8:2 / /var/lib/glyndor rw - ext4 /dev/sda2 rw\n"
			.into(),
	);
	ensure_system(&mut host, 996, &Boot::default(), &data_dir()).unwrap();
	assert_eq!(
		host.files[&system_path(996)],
		system_text(Some(&data_dir())).unwrap()
	);
}

#[test]
fn the_configuration_turns_the_system_drop_in_off_and_removes_it() {
	let mut host = Fake::new(true);
	host.files
		.insert(system_path(996), system_text(None).unwrap());
	let change = ensure_system(&mut host, 996, &off(), &data_dir()).unwrap();
	assert_eq!(change, Change::Removed);
	assert!(!host.files.contains_key(&system_path(996)));
	assert_eq!(host.reloads, vec![Scope::System]);
}

#[test]
fn stack_down_removes_the_system_drop_in_and_only_that_one() {
	let mut host = Fake::new(true);
	host.files
		.insert(system_path(996), system_text(None).unwrap());
	host.files
		.insert(system_path(1001), system_text(None).unwrap());
	assert_eq!(remove_system(&mut host, 996), Ok(Change::Removed));
	assert!(host.files.contains_key(&system_path(1001)));
	assert_eq!(remove_system(&mut host, 996), Ok(Change::Unchanged));
}

#[test]
fn a_manager_that_cannot_reload_is_reported_with_the_file_it_wrote() {
	let mut host = Fake::new(true);
	host.fail_reload = true;
	let error = ensure_system(&mut host, 996, &Boot::default(), &data_dir()).unwrap_err();
	assert!(
		error.contains("glyndor-epistle-boot.conf"),
		"the error must name the drop-in file"
	);
	assert!(
		error.contains("Failed to connect to bus"),
		"the error must carry the bus failure"
	);
}

#[test]
fn the_version_is_read_from_the_first_line_of_systemctl() {
	use live::parse_version;
	assert_eq!(
		parse_version("systemd 255 (255.4-1ubuntu8)\n+PAM +AUDIT\n"),
		Some(255)
	);
	assert_eq!(parse_version("systemd 244 (244.3)\n"), Some(244));
	assert_eq!(parse_version("systemd\n"), None);
	assert_eq!(parse_version("something else 255\n"), None);
	assert_eq!(parse_version(""), None);
}

const HOSTILE: &[&str] = &[
	"/srv/x\nExecStartPre=/bin/true",
	"/srv/x\rExecStartPre=/bin/true",
	"/srv/x\\ny",
	"/srv/../etc",
	"/srv/./x",
	"/srv//x",
	"/srv/x/",
	"srv/x",
	"relative",
	"",
	"/srv/with space",
	"/srv/%h",
	"/srv/tab\tx",
	"/srv/x;y",
	"/srv/\u{7f}x",
	"/srv/\u{e9}",
];

#[test]
fn a_path_that_could_start_a_directive_is_refused_with_its_reason() {
	for path in HOSTILE {
		let error = system_text(Some(Path::new(path))).unwrap_err();
		assert!(
			error.contains("cannot go into a systemd unit"),
			"{path:?}: {error}"
		);
	}
	assert!(system_text(Some(Path::new("/var/lib/glyndor/epistle/data"))).is_ok());
	assert!(system_text(Some(Path::new("/srv/my-disk_1/data.d"))).is_ok());
}

#[test]
fn nothing_is_written_for_a_hostile_data_dir() {
	for path in HOSTILE {
		let mut host = Fake::new(true);
		// A mount that holds the whole tree makes the path its own mount.
		host.files.insert(
			PathBuf::from(MOUNTINFO),
			"40 20 8:2 / /srv rw - ext4 /dev/sda2 rw\n41 20 8:3 / /x rw - ext4 /dev/sda3 rw\n42 20 8:4 / /relative rw - ext4 /dev/sda4 rw\n43 20 8:5 / / rw - ext4 /dev/sda5 rw\n".into(),
		);
		let result = ensure_system(&mut host, 996, &Boot::default(), Path::new(path));
		if path.starts_with("/srv") {
			assert!(result.is_err(), "{path:?} was accepted: {result:?}");
			assert!(host.untouched(), "{path:?} wrote something");
		}
	}
}
