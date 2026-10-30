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
	("db", "896m"),
	("clamav", "2g"),
	("freshclam", "1g"),
];

const SMALL_SET: [(&str, &str); 4] = [
	("mail", "1g"),
	("db", "384m"),
	("clamav", "1152m"),
	("freshclam", "896m"),
];

const UNDER_4_GIB_SET: [(&str, &str); 4] = [
	("mail", "1g"),
	("db", "512m"),
	("clamav", "1152m"),
	("freshclam", "896m"),
];

const LARGE_SET: [(&str, &str); 4] = [
	("mail", "4g"),
	("db", "2g"),
	("clamav", "3g"),
	("freshclam", "2g"),
];

#[test]
fn each_tier_starts_where_it_is_meant_to() {
	const GIB: u64 = 1024 * 1024 * 1024;
	let tier = |memory, antivirus| Sizing { memory, antivirus };
	for (mem_total, expected) in [
		// A VPS sold as 4 GiB reports a little less, after the kernel's share.
		(3_900_000 * 1024, tier(UNDER_4_GIB_SET, false)),
		(4 * GIB - 1, tier(UNDER_4_GIB_SET, false)),
		(4 * GIB, tier(SMALL_SET, true)),
		(7 * GIB - 1, tier(SMALL_SET, true)),
		(7 * GIB, tier(EIGHT_GIB_SET, true)),
		(8_000_000 * 1024, tier(EIGHT_GIB_SET, true)),
		(16 * GIB, tier(EIGHT_GIB_SET, true)),
		(16 * GIB + 1, tier(LARGE_SET, true)),
		(32 * GIB, tier(LARGE_SET, true)),
	] {
		assert_eq!(for_host(mem_total), expected, "{mem_total} bytes");
	}
}

#[test]
fn every_tier_fits_the_smallest_host_it_is_given_to() {
	// `epistle status` warns when the limits add up to more than 85% of
	// MemTotal, so a fresh install must start under that on every host its
	// tier covers. Under 4 GiB only mail and db run, and 75% of the
	// smallest host leaves the OS its own share.
	// The smallest host the tiers are sized for.
	const SMALLEST_HOST: u64 = 2 * 1024 * 1024 * 1024;
	for tier in TIERS {
		let smallest = tier.from.max(SMALLEST_HOST);
		let sum: u64 = tier
			.memory
			.iter()
			.filter(|(service, _)| tier.antivirus || !matches!(*service, "clamav" | "freshclam"))
			.map(|(_, memory)| crate::smtp::memory_fit::parse_memory(memory).expect("a size"))
			.sum();
		let (percent, within) = if tier.antivirus {
			(85, sum * 100 < smallest * 85)
		} else {
			(75, sum * 100 <= smallest * 75)
		};
		assert!(
			within,
			"the tier from {} MiB adds up to {} MiB, over {percent}% of {} MiB",
			tier.from >> 20,
			sum >> 20,
			smallest >> 20
		);
	}
}

#[test]
fn a_new_install_on_8_gib_gets_the_8_gib_limits() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut answers = answers(dir.path(), true);
	let notes = fill(&mut answers, &meminfo(dir.path(), 8 * KIB_PER_GIB));
	assert_eq!(
		notes,
		["container memory for a host with 8.0 GiB: mail 2g, db 896m, clamav 2g, freshclam 1g"]
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
			"container memory for a host with 3.7 GiB: mail 1g",
			"the host has under 4 GiB of memory, so clamav and freshclam are left out and \
			 incoming mail is not scanned for viruses; set antivirus = true under [services] \
			 to keep them",
		]
	);
	assert_eq!(answers.resources, memory(&[("mail", "1g")]));
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
		["container memory for a host with 3.7 GiB: db 512m, clamav 1152m, freshclam 896m"]
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
			memory: Some("512m".to_string()),
			pids: Some(300)
		}
	);
	assert_eq!(answers.resources["clamav"].memory.as_deref(), Some("1152m"));
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
