//! The watcher hands a new `warmup.json` to the running warm-up and
//! publishes it in the reload status the CLI waits on.

use std::sync::Arc;

use super::{FileWatcher, PollEvent, PollTarget};
use crate::directory_store::AccountStore;
use crate::queue::warmup::settings::{self, Action, Settings};
use crate::queue::warmup::{Group, Warmup};

#[test]
fn a_cli_write_of_warmup_json_reaches_the_running_warm_up() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = Arc::new(
		AccountStore::open(
			dir.path(),
			vec!["example.org".to_string()],
			std::collections::HashMap::new(),
			Vec::new(),
		)
		.expect("open store"),
	);
	let warmup = Arc::new(Warmup::open(dir.path(), None, 1));
	let mut watcher = FileWatcher::new(dir.path().to_path_buf(), store)
		.with_warmup(Arc::clone(&warmup) as Arc<dyn super::WarmupReloader>);
	assert!(!warmup.enabled());

	let mut wanted = Settings {
		enabled: true,
		..Settings::default()
	};
	wanted.order(Group::Gmail, Action::Set { cap: 20 });
	settings::save(dir.path(), &wanted).expect("save");
	let report = watcher.poll();

	assert!(
		report
			.events
			.contains(&PollEvent::Loaded(PollTarget::Warmup)),
		"{:?}",
		report.events
	);
	assert!(warmup.enabled());
	assert_eq!(warmup.snapshot().1.group(Group::Gmail).cap, Some(20));
	let status = crate::directory_store::read_reload_status(dir.path()).expect("status");
	assert!(status.matches(
		"warmup.json",
		crate::directory_store::reload_fingerprint(&settings::path(dir.path()))
	));
}
