//! The bounds on a `sync-collection` reply.

use super::*;
use crate::webdav::report_bounds::MAX_RESOURCE_BYTES;

async fn text(response: Response) -> (StatusCode, String) {
	let status = response.status();
	let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024 * 1024)
		.await
		.expect("body");
	(status, String::from_utf8_lossy(&bytes).into_owned())
}

fn request(prop: &str) -> String {
	format!(
		"<D:sync-collection xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\
		<D:sync-token/><D:sync-level>1</D:sync-level><D:prop>{prop}</D:prop></D:sync-collection>"
	)
}

#[tokio::test]
async fn members_beyond_what_a_first_sync_lists_are_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	for n in 0..4 {
		std::fs::write(dir.path().join(format!("e{n}.ics")), b"x").expect("write");
	}
	assert_eq!(
		members(dir.path(), true, 3).await,
		Err(Refusal::TooManyMembers)
	);
	assert_eq!(members(dir.path(), true, 4).await.map(|m| m.len()), Ok(4));
}

/// Seven resources of the largest stored size do not fit one reply: the
/// ones that fit carry their data, the others are answered `507` by name so
/// the client asks for them on their own, and the token is still returned.
#[tokio::test]
async fn data_that_outgrows_the_reply_is_answered_507_by_name() {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = dir.path().canonicalize().expect("root");
	let calendar = root.join("cal");
	std::fs::create_dir(&calendar).expect("mkdir");
	for n in 0..7 {
		std::fs::write(
			calendar.join(format!("e{n}.ics")),
			vec![b'x'; MAX_RESOURCE_BYTES as usize],
		)
		.expect("write");
	}
	let body = request("<D:getetag/><C:calendar-data/>");
	let (status, out) = text(report(&root, &calendar, true, &body).await).await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	assert_eq!(out.matches("200 OK").count(), 6);
	assert_eq!(out.matches("507 Insufficient Storage").count(), 1);
	assert!(out.contains("<D:sync-token>"));
	let (_, etags) = text(report(&root, &calendar, true, &request("<D:getetag/>")).await).await;
	assert_eq!(etags.matches("200 OK").count(), 7);
}
