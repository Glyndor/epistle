//! Read-only root filesystems. Each service may write only to its volumes,
//! its bind mounts and the tmpfs listed here; `podman diff` of a running
//! stack after mail in, a submission, an IMAP read and an EICAR scan showed
//! nothing else written.

use super::render;
use super::*;
use serde_json::json;

#[test]
fn every_service_has_a_read_only_root_filesystem() {
	let value = render(&stack_answers(), true);
	for (name, service) in value["services"].as_object().expect("services") {
		assert_eq!(
			service["read_only"], true,
			"{name} must not write its image"
		);
	}
}

#[test]
fn mail_writes_only_to_its_mounts() {
	let value = render(&stack_answers(), true);
	assert!(
		value["services"]["mail"].get("tmpfs").is_none(),
		"serve wrote nothing outside data_dir"
	);
}

#[test]
fn clamd_scans_in_a_bounded_tmpfs() {
	let value = render(&minimal_answers(), false);
	assert_eq!(
		value["services"]["clamav"]["tmpfs"],
		json!(["/tmp:size=512m,mode=1777"]),
		"clamd writes each INSTREAM body and every extracted archive member under /tmp"
	);
}

#[test]
fn freshclam_logs_to_a_tmpfs_it_can_write() {
	let value = render(&minimal_answers(), false);
	assert_eq!(
		value["services"]["freshclam"]["tmpfs"],
		json!(["/var/log/clamav:size=16m,mode=1777"]),
		"UpdateLogFile is /var/log/clamav/freshclam.log, and a tmpfs without mode=1777 \
		 is root's, so clamav could not create it"
	);
}

#[test]
fn db_keeps_its_tmpfs() {
	let value = render(&stack_answers(), true);
	assert_eq!(value["services"]["db"]["tmpfs"], json!(["/tmp"]));
}
