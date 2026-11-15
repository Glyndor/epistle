//! Reading the file list back from the unit text podup writes.

use std::path::PathBuf;

use super::*;

const UNIT: &str = "[Unit]\nWants=podman-user-wait-network-online.service\nAfter=podman-user-wait-network-online.service\n\n[Service]\nType=oneshot\nExecStart=/usr/bin/podup -f /var/lib/glyndor/epistle/data/compose/compose.yaml -f /var/lib/glyndor/epistle/data/compose/compose.override.yaml -p epistle up -d --no-build --pull never\nExecStop=/usr/bin/podup -f /other/compose.yaml -p epistle stop\n";

fn paths(list: &[&str]) -> Vec<PathBuf> {
	list.iter().map(PathBuf::from).collect()
}

#[test]
fn the_files_are_the_f_arguments_of_exec_start_and_not_of_exec_stop() {
	assert_eq!(
		compose_files(UNIT),
		Some(paths(&[
			"/var/lib/glyndor/epistle/data/compose/compose.yaml",
			"/var/lib/glyndor/epistle/data/compose/compose.override.yaml"
		]))
	);
}

#[test]
fn a_quoted_path_with_a_space_and_escaped_specifiers_is_one_file() {
	let unit = "ExecStart=/usr/bin/podup -f \"/srv/my data/compose.yaml\" -f /srv/50%%/c.yaml up\n";
	assert_eq!(
		compose_files(unit),
		Some(paths(&["/srv/my data/compose.yaml", "/srv/50%/c.yaml"]))
	);
}

#[test]
fn a_unit_without_exec_start_has_no_file_list() {
	assert_eq!(compose_files("[Service]\nType=oneshot\n"), None);
}

#[test]
fn the_unit_flags_are_read_from_exec_start_only() {
	assert!(has_flag(UNIT, "--pull"));
	assert!(has_flag(UNIT, "--no-build"));
	assert!(!has_flag(UNIT, "--force-recreate"));
	assert!(orders_after(
		UNIT,
		"podman-user-wait-network-online.service"
	));
	assert!(!orders_after(UNIT, "network-online.target"));
}

#[test]
fn the_same_files_in_another_order_or_another_count_differ() {
	let a = paths(&["/x/compose.yaml", "/x/compose.override.yaml"]);
	assert!(same_files(&a, &a));
	assert!(!same_files(
		&a,
		&paths(&["/x/compose.override.yaml", "/x/compose.yaml"])
	));
	assert!(!same_files(&a, &paths(&["/x/compose.yaml"])));
}

#[test]
fn a_link_to_the_same_file_is_the_same_file() {
	let dir = tempfile::tempdir().expect("tempdir");
	let real = dir.path().join("real.yaml");
	std::fs::write(&real, "{}").expect("write");
	let link = dir.path().join("link.yaml");
	std::os::unix::fs::symlink(&real, &link).expect("link");
	assert!(same_files(&[real], &[link]));
}
