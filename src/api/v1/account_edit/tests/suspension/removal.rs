//! A suspended account is removed by a key that is not confined, and by no
//! other, so that removing it is no way round the suspension.

use axum::http::StatusCode;
use tracing::instrument::WithSubscriber;

use super::fixture::*;

const NOT_FOR_REMOVING: &str =
	"removing a suspended account is for a key that is not confined to an account or some domains.";
const REMOVE: &str = "/api/v1/accounts/alice?queue=drain";

/// A message in the mailbox of `alice`.
fn mail_of_alice(world: &World) -> std::path::PathBuf {
	let new = world.dir.path().join("accounts/alice/new");
	std::fs::create_dir_all(&new).expect("mailbox");
	let message = new.join("message");
	std::fs::write(&message, "kept").expect("message");
	message
}

#[tokio::test]
async fn a_confined_key_does_not_remove_a_suspended_account() {
	let world = world();
	let message = mail_of_alice(&world);
	post(&world, token(), "alice", "disable").await;
	let capture = Capture::default();
	let (status, body) = call(&world.state, "DELETE", REMOVE, OF_A, None)
		.with_subscriber(capture.dispatch())
		.await;
	assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
	assert_eq!(body["error"]["message"], NOT_FOR_REMOVING);
	assert!(disabled(&world, "alice"));
	assert!(message.exists());
	assert!(capture.events().is_empty(), "{:?}", capture.events());
	// Another tenant's key learns nothing of it.
	let (status, body) = call(&world.state, "DELETE", REMOVE, OF_B, None).await;
	assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
	let (status, body) = call(&world.state, "DELETE", REMOVE, WRITER, None).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert!(world.store.dynamic("alice").is_none());
}

#[tokio::test]
async fn a_confined_key_still_removes_an_active_account_of_its_domains() {
	let world = world();
	let (status, body) = call(&world.state, "DELETE", REMOVE, OF_A, None).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert!(world.store.dynamic("alice").is_none());
}

/// The suspension, or the confinement of the key, arrives after the first look
/// and before the removal reserves the account: nothing is destroyed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removal_asks_again_when_it_reserves_the_account() {
	for case in ["suspended meanwhile", "key confined meanwhile"] {
		let world = world();
		let message = mail_of_alice(&world);
		let by_operator = case == "key confined meanwhile";
		if by_operator {
			world.store.set_disabled("alice", true).expect("prepare");
		}
		let bearer = if by_operator { WRITER } else { OF_A };
		let (status, body, capture) =
			while_the_write_waits(&world, "DELETE", REMOVE, bearer, || {
				if by_operator {
					let confined = key("writer", WRITER, &["manage:write"], &["a.test"]);
					replace_key(&world, "writer", Some(confined));
				} else {
					edit_on_disk(&world, "alice", "disabled", true.into());
				}
			})
			.await;
		assert_eq!(status, StatusCode::NOT_FOUND, "{case}: {body}");
		assert_eq!(body["error"]["message"], "no such dynamic account");
		assert!(message.exists(), "{case}");
		let text = std::fs::read_to_string(world.store.store_path()).expect("file");
		assert!(text.contains("name = \"alice\""), "{case}: {text}");
		assert!(!text.contains("[removals]"), "{case}: {text}");
		assert!(capture.events().is_empty(), "{case}");
	}
}
