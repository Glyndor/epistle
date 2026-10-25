//! The bounds on a `sync-collection` reply.

use super::*;
use crate::webdav::report_bounds::MAX_RESOURCE_BYTES;
use crate::webdav::sync;

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

fn long_name(n: usize) -> String {
	format!("{}{n:04}.ics", "é ".repeat(40))
}

async fn calendar_of(dir: &std::path::Path, count: usize) -> std::path::PathBuf {
	let calendar = dir.join("cal");
	std::fs::create_dir(&calendar).expect("mkdir");
	for n in 0..count {
		std::fs::write(calendar.join(long_name(n)), b"x").expect("write");
	}
	calendar
}

fn token_of(body: &str) -> String {
	let start = body.rfind("<D:sync-token>").expect("token") + "<D:sync-token>".len();
	let end = body.rfind("</D:sync-token>").expect("token end");
	body[start..end].to_string()
}

fn request_from(token: &str) -> String {
	format!(
		"<D:sync-collection xmlns:D=\"DAV:\"><D:sync-token>{token}</D:sync-token>\
		<D:sync-level>1</D:sync-level><D:prop><D:getetag/></D:prop></D:sync-collection>"
	)
}

/// With long names a first sync outgrows the reply long before the member
/// cap: it is refused as a whole, never answered with some members missing
/// and a token that says it is complete.
#[tokio::test]
async fn a_first_sync_that_outgrows_the_reply_is_refused_not_cut() {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = dir.path().canonicalize().expect("root");
	let calendar = calendar_of(&root, 100).await;
	let out = report_within(&root, &calendar, true, &request(""), (20_000, 1000)).await;
	let (status, body) = text(out).await;
	assert_eq!(status, StatusCode::INSUFFICIENT_STORAGE);
	assert!(body.contains("number-of-matches-within-limits"));
	assert!(!body.contains("sync-token>urn"));
	let out = report_within(&root, &calendar, true, &request(""), (200_000, 1000)).await;
	let (status, body) = text(out).await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	assert_eq!(body.matches("200 OK").count(), 100);
}

/// An incremental sync that outgrows the reply stops with the token of the
/// last change it delivered; resuming from it brings the rest, and every
/// member arrives exactly once.
#[tokio::test]
async fn an_incremental_sync_that_outgrows_the_reply_resumes_from_its_token() {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = dir.path().canonicalize().expect("root");
	let calendar = calendar_of(&root, 100).await;
	let start = sync::load(&calendar).await.expect("log").token();
	let changes: Vec<(String, bool)> = (0..100)
		.map(|n| (href::segment(&long_name(n)), false))
		.collect();
	sync::record(&calendar, &changes).await;
	let mut token = start;
	let mut seen = std::collections::BTreeSet::new();
	let mut rounds = 0;
	loop {
		rounds += 1;
		assert!(rounds < 50, "no progress");
		let out = report_within(
			&root,
			&calendar,
			true,
			&request_from(&token),
			(20_000, 1000),
		)
		.await;
		let (status, body) = text(out).await;
		assert_eq!(status, StatusCode::MULTI_STATUS);
		let before = seen.len();
		for line in body.lines().filter(|l| l.contains("<D:href>")) {
			if !line.contains("<D:href>/cal/") {
				continue;
			}
			seen.insert(line.trim().to_string());
		}
		assert!(seen.len() > before, "round {rounds} delivered nothing");
		let cut = body.contains("number-of-matches-within-limits");
		token = token_of(&body);
		if !cut {
			break;
		}
	}
	assert!(rounds > 1, "the reply was never cut");
	assert_eq!(seen.len(), 100);
}
