use super::*;

fn names(list: &[&str]) -> Vec<String> {
	list.iter().map(|s| (*s).to_string()).collect()
}

#[test]
fn a_repeated_href_counts_once_and_keeps_its_place() {
	let root = Path::new("/r");
	let got = distinct_hrefs(root, names(&["/a", "/b", "/a", "/b", "/c"]), 3).expect("fits");
	assert_eq!(got, names(&["/a", "/b", "/c"]));
}

#[test]
fn two_spellings_of_one_resource_count_once() {
	let root = Path::new("/r");
	let spellings = names(&["/a.ics", "/./a.ics", "//a.ics", "/%61.ics", "/x/../a.ics"]);
	let got = distinct_hrefs(root, spellings, 2);
	// `/x/../a.ics` is refused by `resolve` and stays a distinct key.
	assert_eq!(got.map(|v| v.len()), Ok(2));
	let got = distinct_hrefs(root, names(&["/a.ics", "/./a.ics", "/%61.ics"]), 1);
	assert_eq!(got, Ok(names(&["/a.ics"])));
}

#[test]
fn more_distinct_hrefs_than_the_cap_are_refused() {
	let root = Path::new("/r");
	assert_eq!(
		distinct_hrefs(root, names(&["/a", "/b", "/c"]), 2),
		Err(Refusal::TooManyHrefs)
	);
	assert!(distinct_hrefs(root, names(&["/a", "/b", "/a"]), 2).is_ok());
}

#[tokio::test]
async fn the_refusals_answer_with_standard_codes_and_the_condition() {
	for (refusal, status) in [
		(Refusal::TooManyHrefs, StatusCode::PAYLOAD_TOO_LARGE),
		(Refusal::BodyTooLarge, StatusCode::PAYLOAD_TOO_LARGE),
		(Refusal::TooManyMembers, StatusCode::INSUFFICIENT_STORAGE),
	] {
		let response = refusal.response();
		assert_eq!(response.status(), status);
		let body = axum::body::to_bytes(response.into_body(), 4096)
			.await
			.expect("body");
		assert!(
			String::from_utf8_lossy(&body).contains("<D:number-of-matches-within-limits/>"),
			"{refusal:?}"
		);
	}
}

#[tokio::test]
async fn a_capped_read_stops_at_the_limit() {
	let dir = tempfile::tempdir().expect("tempdir");
	let file = dir.path().join("f");
	std::fs::write(&file, vec![b'x'; 100]).expect("write");
	assert_eq!(read_capped(&file, 100).await.map(|d| d.len()), Some(100));
	assert!(read_capped(&file, 99).await.is_none());
}

#[test]
fn the_reply_limit_holds_the_worst_escaped_resource() {
	const { assert!(MAX_REPORT_BYTES > MAX_RESOURCE_BYTES * ESCAPE_EXPANSION) };
}
