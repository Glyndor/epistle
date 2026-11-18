//! No event says more than which topic changed.

use super::base::{
	ADMIN, QUIET, TENANT_A, add_account, app, enqueue, fast, log_delivery, settle, state, stream,
	suppress,
};

/// Strings that must never appear in any frame: addresses, the pieces of a
/// message, the delivery reply, and every credential in the fixture.
const FORBIDDEN: [&str; 14] = [
	"@",
	"alice",
	"carol",
	"elsewhere",
	"private",
	"Subject",
	"secret",
	"argon2",
	"queued as",
	"example",
	"Bearer",
	"password",
	"token",
	"mx.",
];

#[tokio::test]
async fn no_event_carries_an_address_a_credential_or_content() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state(dir.path(), fast());
	let app = app(&state);
	let mut admin = stream(&app, ADMIN, None).await;
	let mut tenant = stream(&app, TENANT_A, None).await;
	settle().await;
	add_account(&state, "carol", "carol@a.example");
	enqueue(&state, "alice@a.example", "someone@elsewhere.example");
	suppress(dir.path(), "x@elsewhere.example");
	log_delivery(dir.path(), "someone@elsewhere.example");
	let mut frames = admin.collect(QUIET * 3).await;
	frames.extend(tenant.collect(QUIET).await);
	assert!(
		frames.len() >= 6,
		"the scenario produced {} events",
		frames.len()
	);
	for frame in frames {
		for word in FORBIDDEN {
			assert!(
				!frame.raw.contains(word),
				"{word:?} appears in an event: {:?}",
				frame.raw
			);
		}
		let name = frame.event.as_deref().expect("event name");
		assert!(
			[
				"queue",
				"deliveries",
				"suppression",
				"status",
				"accounts",
				"domains"
			]
			.contains(&name),
			"{name}"
		);
		assert_eq!(
			frame.data,
			Some(serde_json::json!({ "topic": name })),
			"data is the topic and nothing else"
		);
	}
}
