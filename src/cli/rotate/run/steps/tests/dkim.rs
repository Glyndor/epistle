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

/// Write a rotation state at `path` whose key in service is `selector`,
/// rotated at `rotated_at`, with the replaced selector published until
/// `retire_at` when given.
fn state(path: &std::path::Path, selector: &str, rotated_at: u64, retire_at: Option<u64>) {
	let dir = path.parent().expect("dir");
	std::fs::create_dir_all(dir).expect("mkdir");
	let (pem, _) = crate::dkim::generate_key().expect("key");
	std::fs::write(dir.join(format!("{selector}.pem")), pem).expect("key");
	let state = crate::dkim::rotate::RotationState {
		selector: selector.into(),
		key_file: dir.join(format!("{selector}.pem")),
		rotated_at,
		previous: retire_at.map(|retire_at| crate::dkim::rotate::Previous {
			selector: "replaced".into(),
			key_file: dir.join("replaced.pem"),
			retire_at,
			rsa: None,
		}),
		pending: None,
		rsa: None,
	};
	std::fs::write(path, serde_json::to_vec(&state).expect("json")).expect("state");
}

#[test]
fn a_key_rotated_today_or_inside_its_overlap_is_a_note_and_not_a_refusal() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config(dir.path());
	let domain_dir =
		crate::dkim::domain_rotate::state_dir(&config.data_dir, "example.org").expect("dir");
	state(
		&domain_dir.join(crate::dkim::domain_rotate::STATE_FILE),
		"own19995",
		NOW - 5 * 86_400,
		Some(NOW + 86_400),
	);
	state(
		&config.data_dir.join(crate::dkim::rotate::STATE_FILE),
		&crate::dkim::rotate::selector_for(NOW),
		NOW - 60,
		None,
	);
	let (steps, notes) =
		plan(&config, NOW).expect("a key that cannot rotate today refuses nothing");
	assert!(steps.is_empty(), "{steps:?}");
	assert!(
		notes
			.iter()
			.any(|note| note.contains("[dkim] key already rotated today")),
		"{notes:?}"
	);
	assert!(
		notes
			.iter()
			.any(|note| note.contains("example.org") && note.contains("stays published until")),
		"{notes:?}"
	);
	// Once the overlap is over the domain's key is queued again.
	let (steps, _) = plan(&config, NOW + 2 * 86_400).expect("plan");
	assert!(
		steps
			.iter()
			.any(|step| step.kind == Kind::DkimDomainKey && step.item == "example.org"),
		"{steps:?}"
	);
}
