use super::*;

async fn text(response: Response) -> (StatusCode, String) {
	let status = response.status();
	let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024 * 1024)
		.await
		.expect("body");
	(status, String::from_utf8_lossy(&bytes).into_owned())
}

const HEAD: &str = "<D:multistatus xmlns:D=\"DAV:\">\n";

#[tokio::test]
async fn a_member_is_escaped_into_the_body_and_counted() {
	let mut reply = Reply::new(HEAD, 10_000);
	let before = reply.remaining();
	let added = reply.member("/a&b.ics", "\"e\"", Some(("C:calendar-data", b"x<y>&\"'")));
	assert_eq!(added, Added::Yes);
	assert_eq!(reply.members(), 1);
	assert!(reply.remaining() < before);
	let (status, body) = text(reply.finish("")).await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
	assert!(body.contains("<D:href>/a&amp;b.ics</D:href>"));
	assert!(body.contains("<C:calendar-data>x&lt;y&gt;&amp;&quot;&apos;</C:calendar-data>"));
	assert!(body.ends_with("</D:multistatus>\n"));
}

/// What the client receives never passes the limit, however the data
/// escapes: every byte of `"` becomes six.
#[tokio::test]
async fn the_body_never_passes_the_limit() {
	let data = vec![b'"'; 1000];
	let mut reply = Reply::new(HEAD, 6_000);
	let mut added = 0;
	for n in 0..10 {
		if reply.member(&format!("/{n}"), "e", Some(("C:d", &data))) == Added::Yes {
			added += 1;
		}
	}
	assert!(added < 10, "added {added}");
	let (_, body) = text(reply.finish("")).await;
	assert!(
		body.len() <= 6_000 + "</D:multistatus>\n".len(),
		"{}",
		body.len()
	);
}

#[tokio::test]
async fn a_member_that_does_not_fit_adds_nothing() {
	let mut reply = Reply::new(HEAD, 600);
	assert_eq!(
		reply.member("/a", "e", Some(("C:d", &[b'x'; 500]))),
		Added::NoRoom
	);
	assert_eq!(reply.members(), 0);
	reply.too_large("/a");
	let (_, body) = text(reply.finish("")).await;
	assert!(body.contains("HTTP/1.1 507 Insufficient Storage"));
	assert!(!body.contains("200 OK"));
}

#[tokio::test]
async fn a_truncated_reply_names_the_condition() {
	let mut reply = Reply::new(HEAD, 600);
	reply.truncated("/cal/");
	let (_, body) = text(reply.finish("")).await;
	assert!(body.contains("<D:href>/cal/</D:href>"));
	assert!(body.contains("507 Insufficient Storage"));
	assert!(body.contains("<D:number-of-matches-within-limits/>"));
}

/// The reply limit leaves room for one resource of the largest stored size
/// at its worst escaped size, so a stored resource is never unreadable.
#[tokio::test]
async fn the_largest_stored_resource_always_fits_alone() {
	use crate::webdav::report_bounds::{MAX_REPORT_BYTES, MAX_RESOURCE_BYTES};
	let data = vec![b'"'; MAX_RESOURCE_BYTES as usize];
	let mut reply = Reply::new(HEAD, MAX_REPORT_BYTES);
	assert_eq!(
		reply.member("/big.ics", "\"e\"", Some(("C:calendar-data", &data))),
		Added::Yes
	);
}
