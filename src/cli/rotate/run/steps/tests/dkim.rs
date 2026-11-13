//! The DKIM steps: which keys are queued, and when a queued rotation counts
//! as done.

use crate::config::Config;

use super::super::super::journal::{Intent, Kind, Step};
use super::super::dkim::{apply, landed, plan, prepare};

const NOW: u64 = 20_000 * 86_400;

/// `shared.example.org` signs with `[dkim]`, `example.org` with a key of its
/// own inside the `[dns]` zone, and `other.net` with one no entry publishes.
fn config(dir: &std::path::Path) -> Config {
	let mut keys = Vec::new();
	for name in ["default", "org", "net"] {
		let (pem, _) = crate::dkim::generate_key().expect("key");
		let path = dir.join(format!("{name}.pem"));
		std::fs::write(&path, pem).expect("key file");
		keys.push(path);
	}
	toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {dir:?}\n\
		 domains = ['example.org', 'other.net', 'shared.example.org']\n\
		 [dkim]\nselector = 's1'\nkey_file = {:?}\n\
		 [[dkim.domain]]\nname = 'example.org'\nselector = 'own1'\nkey_file = {:?}\n\
		 [[dkim.domain]]\nname = 'other.net'\nselector = 'own1'\nkey_file = {:?}\n\
		 [dns]\nprovider = 'cloudflare'\nzone = 'example.org'\ntoken = '{}'\n",
		keys[0],
		keys[1],
		keys[2],
		uuid::Uuid::new_v4().simple()
	))
	.expect("config")
}

#[test]
fn every_key_a_dns_entry_publishes_is_queued_and_the_rest_is_a_note() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config(dir.path());
	let (steps, notes) = plan(&config, NOW).expect("plan");
	let planned: Vec<(Kind, &str)> = steps
		.iter()
		.map(|step| (step.kind, step.item.as_str()))
		.collect();
	assert_eq!(
		planned,
		[(Kind::DkimKey, ""), (Kind::DkimDomainKey, "example.org")]
	);
	assert_eq!(notes.len(), 1, "{notes:?}");
	assert!(notes[0].contains("other.net"), "{notes:?}");
}

#[test]
fn without_dkim_there_is_nothing_to_queue() {
	let dir = tempfile::tempdir().expect("dir");
	let config: Config = toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = ['example.org']\n",
		dir.path()
	))
	.expect("config");
	let (steps, notes) = plan(&config, NOW).expect("plan");
	assert!(steps.is_empty() && notes.is_empty());
}

#[test]
fn a_queued_rotation_counts_as_done_while_it_waits_or_once_the_selector_moved() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config(dir.path());
	for step in [
		Step::pending(Kind::DkimKey, "", None),
		Step::pending(Kind::DkimDomainKey, "example.org", None),
	] {
		let Intent::Queued { active } = prepare(&config, &step).expect("prepare") else {
			panic!("a DKIM step records the selector in service");
		};
		assert!(
			!landed(&config, &step, &active).expect("landed"),
			"{:?} counts as done before it was asked for",
			step.kind
		);
		apply(&config, &step, NOW).expect("queue");
		assert!(
			landed(&config, &step, &active).expect("landed"),
			"{:?}: the waiting request does not count",
			step.kind
		);
		// The server served it (or gave up) and removed the request: the
		// step is done only if the selector in service changed.
		let request = match step.kind {
			Kind::DkimKey => config.data_dir.join(crate::dkim::rotate::REQUEST_FILE),
			_ => crate::dkim::domain_rotate::state_dir(&config.data_dir, &step.item)
				.expect("dir")
				.join(crate::dkim::domain_rotate::REQUEST_FILE),
		};
		std::fs::remove_file(&request).expect("the request was written");
		assert!(
			!landed(&config, &step, &active).expect("landed"),
			"{:?}: a request that is gone with the selector unchanged counts as done",
			step.kind
		);
		assert!(
			landed(&config, &step, "a-selector-replaced-since").expect("landed"),
			"{:?}: a selector that moved does not count as done",
			step.kind
		);
	}
}
