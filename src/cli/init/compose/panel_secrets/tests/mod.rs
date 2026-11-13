#[allow(unused_imports)]
pub use super::*;

use std::path::PathBuf;

use crate::api::ApiKey;
use crate::cli::init::apply::ReportStep;

mod admin_id;
mod create;
mod lost;
mod no_print;
mod plan;
mod prepare;
mod refuse;
mod renew;
mod reuse;

/// A fixed "now", so expiry arithmetic does not depend on the clock.
pub(super) const NOW: u64 = 1_800_000_000;
pub(super) const DAY: u64 = 24 * 60 * 60;

/// An install layout: `data_dir` with the secrets directory beside it.
pub(super) struct Layout {
	_root: tempfile::TempDir,
	pub(super) data: PathBuf,
}

pub(super) fn layout() -> Layout {
	let root = tempfile::tempdir().expect("tempdir");
	let data = root.path().join("data");
	std::fs::create_dir_all(&data).expect("data dir");
	Layout { _root: root, data }
}

/// Run [`ensure`] at `now` and return what it reported.
pub(super) fn run(layout: &Layout, now: u64) -> Report {
	let mut report = Report::default();
	ensure(&layout.data, now, &mut report).expect("ensure");
	report
}

/// The stored `panel` row.
pub(super) fn row(layout: &Layout) -> ApiKey {
	let store = ApiKeyStore::open(&layout.data).expect("open");
	let panel: Vec<&ApiKey> = store
		.keys()
		.iter()
		.filter(|key| key.label == LABEL)
		.collect();
	assert_eq!(panel.len(), 1, "exactly one panel key: {:?}", store.keys());
	panel[0].clone()
}

pub(super) fn count_keys(layout: &Layout) -> usize {
	ApiKeyStore::open(&layout.data).expect("open").keys().len()
}

pub(super) fn text(path: &std::path::Path) -> String {
	std::fs::read_to_string(path).expect("read")
}

/// The reported steps as `(kind, path)`.
pub(super) fn kinds(report: &Report) -> Vec<(&'static str, PathBuf)> {
	report
		.steps
		.iter()
		.map(|step| match step {
			ReportStep::Wrote(path) => ("wrote", path.clone()),
			ReportStep::Updated(path) => ("updated", path.clone()),
			ReportStep::Reused(path) => ("reused", path.clone()),
			other => panic!("unexpected step {other:?}"),
		})
		.collect()
}

/// The mode bits of `path`.
pub(super) fn mode(path: &std::path::Path) -> u32 {
	use std::os::unix::fs::PermissionsExt;
	std::fs::metadata(path)
		.expect("metadata")
		.permissions()
		.mode()
		& 0o777
}

/// The refusal [`ensure`] gives, as text.
pub(super) fn refusal(layout: &Layout, now: u64) -> String {
	let mut report = Report::default();
	match ensure(&layout.data, now, &mut report) {
		Ok(()) => panic!("ensure must refuse"),
		Err(error) => error.to_string(),
	}
}
