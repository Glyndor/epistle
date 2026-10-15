//! Tests for the limits `init` picks from a fake `/proc/meminfo`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::*;
use crate::cli::init::resources::ServiceResources;

const KIB_PER_GIB: u64 = 1024 * 1024;

/// A `/proc/meminfo` whose `MemTotal` is `kib` KiB.
fn meminfo(dir: &Path, kib: u64) -> PathBuf {
	let path = dir.join("meminfo");
	std::fs::write(&path, format!("MemTotal:       {kib} kB\nMemFree: 1 kB\n")).expect("meminfo");
	path
}

fn answers(dir: &Path, database: bool) -> Answers {
	let mut answers = crate::cli::init::compose::minimal_answers();
	answers.data_dir = dir.join("data");
	answers.services.database = database;
	answers
}

fn memory(pairs: &[(&str, &str)]) -> BTreeMap<String, ServiceResources> {
	pairs
		.iter()
		.map(|(service, memory)| {
			(
				(*service).to_string(),
				ServiceResources {
					memory: Some((*memory).to_string()),
					pids: None,
				},
			)
		})
		.collect()
}

const EIGHT_GIB_SET: [(&str, &str); 4] = [
	("mail", "2g"),
	("db", "1g"),
	("clamav", "2g"),
	("freshclam", "1g"),
];

#[test]
fn hosts_of_4_8_and_16_gib_get_their_tier() {
	// A VPS sold as 4 GiB reports a little less, after the kernel's share.
	assert_eq!(
		for_host(3_900_000 * 1024),
		Sizing {
			memory: EIGHT_GIB_SET,
			antivirus: false
		}
	);
	for kib in [4 * KIB_PER_GIB, 8_000_000, 8 * KIB_PER_GIB] {
		assert_eq!(
			for_host(kib * 1024),
			Sizing {
				memory: EIGHT_GIB_SET,
				antivirus: true
			},
			"{kib} KiB"
		);
	}
	assert_eq!(
		for_host(16 * KIB_PER_GIB * 1024),
		Sizing {
			memory: [
				("mail", "2g"),
				("db", "1g"),
				("clamav", "3g"),
				("freshclam", "2g")
			],
			antivirus: true
		}
	);
	assert_eq!(
		for_host(32 * KIB_PER_GIB * 1024),
		Sizing {
			memory: [
				("mail", "4g"),
				("db", "2g"),
				("clamav", "3g"),
				("freshclam", "2g")
			],
			antivirus: true
		}
	);
}

#[test]
fn a_new_install_on_8_gib_gets_the_8_gib_limits() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut answers = answers(dir.path(), true);
	let notes = fill(&mut answers, &meminfo(dir.path(), 8 * KIB_PER_GIB));
	assert_eq!(
		notes,
		["container memory for a host with 8.0 GiB: mail 2g, db 1g, clamav 2g, freshclam 1g"]
	);
	assert_eq!(answers.resources, memory(&EIGHT_GIB_SET));
	assert_eq!(answers.services.antivirus, Some(true));
}

#[test]
fn a_new_install_under_4_gib_leaves_clamav_out_with_a_note() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut answers = answers(dir.path(), false);
	let notes = fill(&mut answers, &meminfo(dir.path(), 3_900_000));
	assert_eq!(
		notes,
		[
			"container memory for a host with 3.7 GiB: mail 2g",
			"the host has under 4 GiB of memory, so clamav and freshclam are left out and \
			 incoming mail is not scanned for viruses; set antivirus = true under [services] \
			 to keep them",
		]
	);
	assert_eq!(answers.resources, memory(&[("mail", "2g")]));
	assert_eq!(answers.services.antivirus, Some(false));
}

#[test]
fn what_the_operator_answered_is_kept() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut answers = answers(dir.path(), true);
	answers.services.antivirus = Some(true);
	answers.resources.insert(
		"mail".to_string(),
		ServiceResources {
			memory: Some("3g".to_string()),
			pids: Some(2000),
		},
	);
	answers.resources.insert(
		"db".to_string(),
		ServiceResources {
			memory: None,
			pids: Some(300),
		},
	);
	let notes = fill(&mut answers, &meminfo(dir.path(), 3_900_000));
	assert_eq!(
		notes,
		["container memory for a host with 3.7 GiB: db 1g, clamav 2g, freshclam 1g"]
	);
	assert_eq!(answers.services.antivirus, Some(true));
	assert_eq!(
		answers.resources["mail"],
		ServiceResources {
			memory: Some("3g".to_string()),
			pids: Some(2000)
		}
	);
	assert_eq!(
		answers.resources["db"],
		ServiceResources {
			memory: Some("1g".to_string()),
			pids: Some(300)
		}
	);
	assert_eq!(answers.resources["clamav"].memory.as_deref(), Some("2g"));
}

#[test]
fn an_existing_install_keeps_what_its_compose_file_records() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut before = answers(dir.path(), true);
	before.resources = memory(&[("clamav", "4g")]);
	let compose = crate::cli::init::compose::compose_file_path(&before.data_dir);
	std::fs::create_dir_all(compose.parent().expect("parent")).expect("dir");
	std::fs::write(
		&compose,
		crate::cli::init::compose::render_for(&before, true).expect("render"),
	)
	.expect("compose");
	let mut answers = answers(dir.path(), true);
	let notes = fill(&mut answers, &meminfo(dir.path(), 8 * KIB_PER_GIB));
	assert_eq!(
		notes,
		[format!(
			"kept the container limits {} records; `epistle status` suggests the ones a new \
			 install on this host would get",
			compose.display()
		)]
	);
	assert_eq!(answers.resources, memory(&[("clamav", "4g")]));
	assert_eq!(answers.services.antivirus, Some(true));
}

#[test]
fn an_existing_install_without_clamav_keeps_it_out() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut before = answers(dir.path(), false);
	before.services.antivirus = Some(false);
	let compose = crate::cli::init::compose::compose_file_path(&before.data_dir);
	std::fs::create_dir_all(compose.parent().expect("parent")).expect("dir");
	std::fs::write(
		&compose,
		crate::cli::init::compose::render_for(&before, false).expect("render"),
	)
	.expect("compose");
	let mut answers = answers(dir.path(), false);
	fill(&mut answers, &meminfo(dir.path(), 16 * KIB_PER_GIB));
	assert_eq!(answers.services.antivirus, Some(false));
	assert!(answers.resources.is_empty(), "{:?}", answers.resources);
}

#[test]
fn an_unreadable_meminfo_keeps_the_fixed_defaults() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut answers = answers(dir.path(), true);
	let absent = dir.path().join("no-meminfo");
	let notes = fill(&mut answers, &absent);
	assert_eq!(
		notes,
		[format!(
			"cannot read MemTotal from {}; the containers keep the fixed limits (mail 1g, db \
			 1g, clamav 3g, freshclam 2g)",
			absent.display()
		)]
	);
	assert!(answers.resources.is_empty());
	assert_eq!(answers.services.antivirus, None);
}
