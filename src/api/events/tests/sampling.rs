//! What the sampler turns a difference into.

use super::base::{ADMIN, QUIET, SOON, TENANT_A, add_account, app, fast, settle, state, stream};
use crate::api::events::sampler::{Sample, changes};
use crate::api::events::topic::{Reach, Topic};

#[test]
fn a_moved_queue_is_one_queue_and_one_status_notification() {
	let before = Sample::for_test(1, &[], &[]);
	let now = Sample::for_test(2, &[], &[]);
	assert_eq!(
		changes(&before, &now),
		[
			(Topic::Queue, Reach::Everyone),
			(Topic::Status, Reach::Everyone)
		]
	);
}

#[test]
fn nothing_moved_means_nothing_is_published() {
	let sample = |q| {
		Sample::for_test(
			q,
			&[("a.example", 1)],
			&[("alice", 1, &["alice@a.example"])],
		)
	};
	assert!(changes(&sample(1), &sample(1)).is_empty());
}

#[tokio::test]
async fn removing_an_account_is_told_to_its_tenant() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state(dir.path(), fast());
	add_account(&state, "carol", "carol@a.example");
	let app = app(&state);
	let mut tenant = stream(&app, TENANT_A, None).await;
	let mut admin = stream(&app, ADMIN, None).await;
	settle().await;
	state.store().remove("carol").expect("remove");
	let mut told = tenant.names(QUIET * 3).await;
	told.sort();
	assert_eq!(told, ["accounts", "status"]);
	assert!(admin.event(SOON).await.is_some());
}
