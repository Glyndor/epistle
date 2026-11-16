//! Items 8 to 10 of the `boot` area, the summary and the readers they use.

use std::path::{Path, PathBuf};

use super::base::{COMPOSE, assert_bad, compose_text, good, item, run};
use super::*;
use crate::cli::stack::autostart::dropins;

#[test]
fn item_8_a_floor_above_the_lowest_port_fails_now_and_at_the_next_boot() {
	let mut host = good();
	host.files.insert(
		PathBuf::from("/proc/sys/net/ipv4/ip_unprivileged_port_start"),
		"1024\n".into(),
	);
	assert_bad(
		&mut host,
		"port floor",
		Level::Fail,
		"net.ipv4.ip_unprivileged_port_start = 25",
	);
	// Applied by hand now, but the boot configuration sets 1024.
	let mut host = good();
	host.boot_sysctl = Ok(
		"net.ipv4.ip_unprivileged_port_start = 25\nnet.ipv4.ip_unprivileged_port_start=1024\n"
			.into(),
	);
	assert_bad(&mut host, "port floor", Level::Fail, "next boot sets 1024");
	// Nothing in the configuration sets it: the kernel default is 1024.
	let mut host = good();
	host.boot_sysctl = Ok("# nothing\nvm.swappiness = 10\n".into());
	assert_bad(&mut host, "port floor", Level::Fail, "next boot sets 1024");
}

#[test]
fn item_8_an_unreadable_boot_configuration_warns_instead_of_guessing() {
	let mut host = good();
	host.boot_sysctl = Err("cannot run systemd-analyze".into());
	assert_bad(&mut host, "port floor", Level::Warn, "could not be read");
}

#[test]
fn item_9_a_configured_mount_that_is_not_mounted_warns() {
	let mut host = good();
	host.files.insert(
		PathBuf::from("/etc/fstab"),
		"UUID=1 / ext4 defaults 0 1\n/dev/vdb1 /data ext4 defaults 0 2\n".into(),
	);
	assert_bad(&mut host, "mounts", Level::Warn, "which is not mounted");
	host.files.insert(
		PathBuf::from("/proc/self/mountinfo"),
		"1 0 8:1 / / rw - ext4 /dev/sda1 rw\n2 1 8:17 / /data rw - ext4 /dev/vdb1 rw\n".into(),
	);
	// A data_dir on its own mount is waited for by the user manager.
	host.files.insert(
		dropins::system_path(1001),
		dropins::system_text(Some(Path::new("/data"))).unwrap(),
	);
	let report = run(&mut host);
	assert_eq!(item(&report, "mounts").status, Level::Ok, "{report:?}");
	host.present.remove(Path::new("/data"));
	assert_bad(&mut host, "mounts", Level::Warn, "does not exist");
}

#[test]
fn item_10_a_missing_image_of_an_enabled_service_fails_with_stack_update() {
	let mut host = good();
	host.images.remove("postgres:18");
	let report = run(&mut host);
	let found = item(&report, "images");
	assert_eq!(found.status, Level::Fail, "{found:?}");
	assert!(found.detail.contains("db (postgres:18)"), "{found:?}");
	assert!(found.detail.contains("--pull never"), "{found:?}");
	assert!(
		found.detail.contains("sudo epistle stack update"),
		"{found:?}"
	);
	assert!(host.pulled.is_empty());
}

#[test]
fn item_10_the_images_all_present_are_ok_and_a_disabled_service_is_only_a_warning() {
	let mut host = good();
	assert_eq!(item(&run(&mut host), "images").status, Level::Ok);
	let mut doc: serde_json::Value = serde_json::from_str(&compose_text()).unwrap();
	doc["services"]["tools"] =
		serde_json::json!({"image": "example/tools:1", "profiles": ["debug"], "restart": "no"});
	host.files.insert(PathBuf::from(COMPOSE), doc.to_string());
	let report = run(&mut host);
	let found = item(&report, "images");
	assert_eq!(found.status, Level::Warn, "{found:?}");
	assert!(found.detail.contains("example/tools:1"));
	assert!(found.detail.contains("not enabled"));
	// And its restart policy `no` is not held against the stack either.
	assert_eq!(
		item(&report, "restart policy").status,
		Level::Ok,
		"{report:?}"
	);
}

#[test]
fn the_summary_names_the_failing_items() {
	let mut host = good();
	host.present
		.remove(Path::new("/var/lib/systemd/linger/glyndor-epistle"));
	host.images.clear();
	let report = run(&mut host);
	assert_eq!(report.status, Level::Fail);
	assert_eq!(
		report.detail,
		"the stack would not come back after a reboot: linger, images"
	);
}

#[test]
fn the_floor_reader_takes_the_last_setting_in_any_spelling() {
	assert_eq!(
		floor::configured("net.ipv4.ip_unprivileged_port_start = 100\n"),
		Some(100)
	);
	assert_eq!(
		floor::configured("-net/ipv4/ip_unprivileged_port_start=7\n"),
		Some(7)
	);
	assert_eq!(
		floor::configured("# net.ipv4.ip_unprivileged_port_start = 1\n"),
		None
	);
	assert_eq!(
		floor::configured(
			"net.ipv4.ip_unprivileged_port_start=1\nnet.ipv4.ip_unprivileged_port_start=2\n"
		),
		Some(2)
	);
}

#[test]
fn the_mount_reader_skips_noauto_swap_and_the_root() {
	let fstab =
		"/dev/a / ext4 defaults 0 1\n/dev/b /data ext4 noauto 0 0\n/dev/c none swap sw 0 0\n";
	assert_eq!(mounts::unmounted(fstab, "", Path::new("/data/x")), None);
}

#[test]
fn the_summary_lists_only_what_is_not_ok_with_its_fix_and_is_silent_without_a_stack() {
	let mut host = good();
	let mut out = Vec::new();
	summary::render(&run(&mut host), &mut out);
	assert_eq!(
		String::from_utf8(out).unwrap(),
		"epistle: boot: the stack comes back after a reboot\n"
	);
	host.present
		.remove(Path::new("/var/lib/systemd/linger/glyndor-epistle"));
	let mut out = Vec::new();
	summary::render(&run(&mut host), &mut out);
	let text = String::from_utf8(out).unwrap();
	assert!(
		text.starts_with("epistle: boot: the stack would not come back after a reboot: linger\n"),
		"{text}"
	);
	assert!(
		text.contains("epistle:   fail linger: ") && text.contains("sudo loginctl enable-linger"),
		"{text}"
	);
	assert_eq!(text.lines().count(), 2, "{text}");
	host.files.remove(Path::new(COMPOSE));
	let mut out = Vec::new();
	summary::render(&run(&mut host), &mut out);
	assert!(out.is_empty());
}
