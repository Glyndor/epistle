//! Retry, hold and release: what each does to the entry, once, and what the
//! audit says.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use tracing::field::{Field, Visit};
use tracing::instrument::WithSubscriber;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::{Layer, Registry};

use super::fixture::*;

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<BTreeMap<String, String>>>>);

#[derive(Default)]
struct Fields(BTreeMap<String, String>);
impl Visit for Fields {
	fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
		self.0.insert(field.name().into(), format!("{value:?}"));
	}
	fn record_str(&mut self, field: &Field, value: &str) {
		self.0.insert(field.name().into(), value.into());
	}
}
impl<S: tracing::Subscriber> Layer<S> for Capture {
	fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
		if event.metadata().target() == "epistle::api::audit" {
			let mut fields = Fields::default();
			event.record(&mut fields);
			self.0.lock().unwrap().push(fields.0);
		}
	}
}

#[tokio::test]
async fn hold_and_release_change_the_entry_once_and_say_so() {
	let world = world();
	let id = world.mine;
	let path = |action: &str| format!("/api/v1/queue/{id}/{action}");
	let (status, body) = call(&world.state, "POST", &path("hold"), WRITER).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(
		(body["changed"].as_bool(), body["held"].as_bool()),
		(Some(true), Some(true))
	);
	assert!(
		world
			.state
			.spool()
			.load_envelope(id)
			.unwrap()
			.held
			.is_some()
	);
	let (_, again) = call(&world.state, "POST", &path("hold"), WRITER).await;
	assert_eq!(again["changed"], false, "a second hold changes nothing");
	let (_, released) = call(&world.state, "POST", &path("release"), WRITER).await;
	assert_eq!(
		(released["changed"].as_bool(), released["held"].as_bool()),
		(Some(true), Some(false))
	);
	let (_, again) = call(&world.state, "POST", &path("release"), WRITER).await;
	assert_eq!(again["changed"], false);
}

#[tokio::test]
async fn retry_makes_the_next_attempt_due_now() {
	let world = world();
	let id = world.mine;
	world
		.state
		.spool()
		.update_envelope(id, |envelope| envelope.next_attempt = 4_000_000_000)
		.expect("defer");
	let (_, body) = call(
		&world.state,
		"POST",
		&format!("/api/v1/queue/{id}/retry"),
		WRITER,
	)
	.await;
	assert_eq!(body["changed"], true, "{body}");
	assert_eq!(
		world.state.spool().load_envelope(id).unwrap().next_attempt,
		0
	);
	let (_, again) = call(
		&world.state,
		"POST",
		&format!("/api/v1/queue/{id}/retry"),
		WRITER,
	)
	.await;
	assert_eq!(again["changed"], false);
}

#[tokio::test]
async fn every_change_is_audited_once_and_the_rest_is_silent() {
	crate::cli::trace::capture::keep_callsites_live();
	let world = world();
	let capture = Capture::default();
	let subscriber = Registry::default().with(capture.clone());
	let (mine, theirs) = (world.mine, world.theirs);
	async {
		for (path, bearer) in [
			(format!("/api/v1/queue/{mine}/hold"), WRITER),
			// Nothing changes: already held.
			(format!("/api/v1/queue/{mine}/hold"), WRITER),
			// Refused: not the key's, no scope, no such entry.
			(format!("/api/v1/queue/{theirs}/hold"), TENANT_A),
			(format!("/api/v1/queue/{mine}/release"), READER),
			(
				format!("/api/v1/queue/{}/release", uuid::Uuid::now_v7()),
				WRITER,
			),
			(format!("/api/v1/queue/{mine}/release"), WRITER),
			(format!("/api/v1/queue/{mine}/retry"), token()),
		] {
			call(&world.state, "POST", &path, bearer).await;
		}
	}
	.with_subscriber(subscriber)
	.await;
	let events = capture.0.lock().unwrap().clone();
	let kinds: Vec<&str> = events.iter().map(|event| event["event"].as_str()).collect();
	assert_eq!(kinds, ["queue.held", "queue.released"], "{events:?}");
	assert_eq!(events[0]["key"], "writer");
	assert_eq!(events[0]["id"], mine.to_string());
	let text = format!("{events:?}");
	for secret in [WRITER, READER, TENANT_A, token()] {
		assert!(!text.contains(secret), "the audit carries a bearer");
	}
}

/// Requests that arrive together hold the entry once and write one line.
#[tokio::test]
async fn concurrent_holds_change_the_entry_once() {
	crate::cli::trace::capture::keep_callsites_live();
	let world = world();
	let capture = Capture::default();
	let dispatch = tracing::Dispatch::new(Registry::default().with(capture.clone()));
	let mut tasks = tokio::task::JoinSet::new();
	for _ in 0..16 {
		let state = world.state.clone();
		let id = world.mine;
		tasks.spawn(
			async move {
				call(&state, "POST", &format!("/api/v1/queue/{id}/hold"), WRITER)
					.await
					.1["changed"]
					.as_bool()
			}
			.with_subscriber(dispatch.clone()),
		);
	}
	let mut changed = 0;
	while let Some(done) = tasks.join_next().await {
		if done.expect("task") == Some(true) {
			changed += 1;
		}
	}
	assert_eq!(changed, 1);
	assert_eq!(capture.0.lock().unwrap().len(), 1);
}

/// An entry whose removal began stays on hold until it is gone: a release is
/// refused and nothing is written.
#[tokio::test]
async fn an_entry_being_removed_cannot_be_released() {
	let world = world();
	let id = world.mine;
	world
		.state
		.spool()
		.update_envelope(id, |envelope| {
			envelope.hold(1);
			envelope.cancelling = Some(1);
		})
		.expect("start a removal");
	for bearer in [WRITER, token(), TENANT_A] {
		let (status, body) = call(
			&world.state,
			"POST",
			&format!("/api/v1/queue/{id}/release"),
			bearer,
		)
		.await;
		assert_eq!(status, StatusCode::CONFLICT, "{body}");
	}
	let kept = world.state.spool().load_envelope(id).unwrap();
	assert!(kept.held.is_some() && kept.cancelling.is_some());
}

/// A key confined to some domains lifts only a hold a key confined inside its
/// domains put; the operator's stays.
#[tokio::test]
async fn a_confined_key_cannot_lift_a_hold_the_operator_put() {
	let world = world();
	let id = world.mine;
	let path = format!("/api/v1/queue/{id}");
	// The operator's hold (the configured token has no confinement).
	let (status, _) = call(&world.state, "POST", &format!("{path}/hold"), token()).await;
	assert_eq!(status, StatusCode::OK);
	let (status, body) = call(&world.state, "POST", &format!("{path}/release"), TENANT_A).await;
	assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
	assert!(
		world
			.state
			.spool()
			.load_envelope(id)
			.unwrap()
			.held
			.is_some(),
		"the hold went"
	);
	// Its own hold, the key lifts.
	let (_, _) = call(&world.state, "POST", &format!("{path}/release"), token()).await;
	let (status, _) = call(&world.state, "POST", &format!("{path}/hold"), TENANT_A).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(
		world.state.spool().load_envelope(id).unwrap().held_by,
		Some(vec!["a.example".to_string()])
	);
	let (status, body) = call(&world.state, "POST", &format!("{path}/release"), TENANT_A).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["held"], false);
	// A key holding a hold does not take over the operator's.
	call(&world.state, "POST", &format!("{path}/hold"), token()).await;
	call(&world.state, "POST", &format!("{path}/hold"), TENANT_A).await;
	assert_eq!(world.state.spool().load_envelope(id).unwrap().held_by, None);
	let (status, _) = call(&world.state, "POST", &format!("{path}/release"), TENANT_A).await;
	assert_eq!(status, StatusCode::FORBIDDEN);
	// An unconfined key lifts any.
	let (status, _) = call(&world.state, "POST", &format!("{path}/release"), WRITER).await;
	assert_eq!(status, StatusCode::OK);
}

/// Removing is held to the rule for a hold as releasing is: a key confined to
/// some domains does not remove mail the operator holds, the mail stays on
/// hold, and a hold of its own does not stand in its way.
#[tokio::test]
async fn a_confined_key_cannot_remove_mail_the_operator_holds() {
	let world = world();
	let id = world.mine;
	let path = format!("/api/v1/queue/{id}");
	call(&world.state, "POST", &format!("{path}/hold"), token()).await;
	let (status, body) = call(&world.state, "DELETE", &path, TENANT_A).await;
	assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
	let kept = world
		.state
		.spool()
		.load_envelope(id)
		.expect("the entry stays");
	assert!(
		kept.held.is_some() && kept.cancelling.is_none(),
		"it stays as it was"
	);
	// Its own hold is its own to remove with.
	call(&world.state, "POST", &format!("{path}/release"), token()).await;
	call(&world.state, "POST", &format!("{path}/hold"), TENANT_A).await;
	let (status, body) = call(&world.state, "DELETE", &path, TENANT_A).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert!(world.state.spool().load_envelope(id).is_err());
	// The operator removes anything.
	let (status, _) = call(
		&world.state,
		"DELETE",
		&format!("/api/v1/queue/{}", world.forward),
		token(),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
}

/// The decision is made on the entry as the removal reads it under the lock,
/// not on the one a caller read earlier.
#[test]
fn the_guard_of_a_removal_sees_a_hold_put_after_the_entry_was_read() {
	let world = world();
	let id = world.mine;
	let stale = world.state.spool().load_envelope(id).expect("read");
	assert!(stale.held.is_none());
	world
		.state
		.spool()
		.update_envelope(id, |envelope| envelope.hold(5))
		.expect("the operator holds it");
	let mut asked = None;
	let refused = crate::evidence::cancel::remove_if(
		world.state.spool(),
		&crate::evidence::service::root_of(world.state.data_dir()),
		id,
		|fresh| {
			asked = Some(fresh.held);
			Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
		},
	)
	.expect_err("refused");
	assert_eq!(refused.kind(), std::io::ErrorKind::PermissionDenied);
	assert_eq!(asked, Some(Some(5)), "the guard saw the hold");
	let kept = world.state.spool().load_envelope(id).expect("kept");
	assert_eq!(
		(kept.held, kept.cancelling),
		(Some(5), None),
		"left as it was"
	);
}

/// Starts a removal that does not finish: the entry keeps the hold and the
/// mark a removal puts on it, and nothing else.
fn interrupted_removal(world: &World, id: uuid::Uuid) {
	let error = world
		.state
		.spool()
		.remove_with(id, |_, wrote| {
			wrote.set(true);
			Err(std::io::Error::other("interrupted"))
		})
		.expect_err("interrupted");
	assert_eq!(error.to_string(), "interrupted");
	let marked = world.state.spool().load_envelope(id).unwrap();
	assert!(marked.held.is_some() && marked.cancelling.is_some() && marked.held_for_removal);
	assert!(!marked.has_real_hold());
}

/// The hold a removal puts on an entry is no one's hold: the key that began the
/// removal finishes it.
#[tokio::test]
async fn the_mark_of_an_unfinished_removal_is_not_a_hold() {
	let world = world();
	let id = world.mine;
	interrupted_removal(&world, id);
	let (status, body) = call(
		&world.state,
		"DELETE",
		&format!("/api/v1/queue/{id}"),
		TENANT_A,
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
}

/// A hold the operator places on an entry a tenant is already removing is a
/// hold, and the tenant's removal does not go through it.
#[tokio::test]
async fn a_hold_placed_on_an_entry_being_removed_is_respected() {
	let world = world();
	let id = world.mine;
	interrupted_removal(&world, id);
	let path = format!("/api/v1/queue/{id}");
	let (status, body) = call(&world.state, "POST", &format!("{path}/hold"), token()).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["changed"], true, "{body}");
	let held = world.state.spool().load_envelope(id).unwrap();
	assert!(held.has_real_hold() && held.cancelling.is_some());
	let (status, body) = call(&world.state, "DELETE", &path, TENANT_A).await;
	assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
	let kept = world.state.spool().load_envelope(id).unwrap();
	assert_eq!(
		(kept.held, kept.held_by.clone()),
		(held.held, None),
		"the entry was written to"
	);
	// The operator, whose hold it is, removes it.
	let (status, _) = call(&world.state, "DELETE", &path, token()).await;
	assert_eq!(status, StatusCode::OK);
}

/// A refused removal writes no mark: the entry is as it was.
#[tokio::test]
async fn a_refused_removal_leaves_no_mark_on_the_entry() {
	let world = world();
	let id = world.mine;
	call(
		&world.state,
		"POST",
		&format!("/api/v1/queue/{id}/hold"),
		token(),
	)
	.await;
	let before = world.state.spool().load_envelope(id).unwrap();
	let (status, _) = call(
		&world.state,
		"DELETE",
		&format!("/api/v1/queue/{id}"),
		TENANT_A,
	)
	.await;
	assert_eq!(status, StatusCode::FORBIDDEN);
	let after = world.state.spool().load_envelope(id).unwrap();
	assert_eq!(after, before);
	assert!(after.cancelling.is_none() && !after.held_for_removal);
}
