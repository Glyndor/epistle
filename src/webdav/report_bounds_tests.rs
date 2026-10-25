use super::*;

fn names(list: &[&str]) -> Vec<String> {
	list.iter().map(|s| (*s).to_string()).collect()
}

#[test]
fn a_repeated_href_counts_once_and_keeps_its_place() {
	let got = distinct_hrefs(names(&["/a", "/b", "/a", "/b", "/c"]), 3).expect("fits");
	assert_eq!(got, names(&["/a", "/b", "/c"]));
}

#[test]
fn more_distinct_hrefs_than_the_cap_are_refused() {
	assert_eq!(
		distinct_hrefs(names(&["/a", "/b", "/c"]), 2),
		Err(Refusal::TooManyHrefs)
	);
	assert!(distinct_hrefs(names(&["/a", "/b", "/a"]), 2).is_ok());
}

#[test]
fn the_budget_refuses_what_does_not_fit() {
	let mut budget = Budget::new(10);
	assert!(budget.charge(4).is_ok());
	assert!(budget.charge(6).is_ok());
	assert_eq!(budget.charge(1), Err(Refusal::TooLarge));
}

#[test]
fn the_refusals_answer_with_standard_codes() {
	assert_eq!(
		Refusal::TooManyHrefs.response().status(),
		StatusCode::PAYLOAD_TOO_LARGE
	);
	assert_eq!(
		Refusal::BodyTooLarge.response().status(),
		StatusCode::PAYLOAD_TOO_LARGE
	);
	assert_eq!(
		Refusal::TooLarge.response().status(),
		StatusCode::INSUFFICIENT_STORAGE
	);
}

#[tokio::test]
async fn a_capped_read_stops_at_the_limit() {
	let dir = tempfile::tempdir().expect("tempdir");
	let file = dir.path().join("f");
	std::fs::write(&file, vec![b'x'; 100]).expect("write");
	assert_eq!(read_capped(&file, 100).await.map(|d| d.len()), Some(100));
	assert!(read_capped(&file, 99).await.is_none());
}

#[tokio::test]
async fn a_member_larger_than_what_is_left_is_refused_unread() {
	let dir = tempfile::tempdir().expect("tempdir");
	let file = dir.path().join("f");
	std::fs::write(&file, vec![b'x'; 100]).expect("write");
	let mut budget = Budget::new(150);
	assert!(
		read_member(&file, &mut budget)
			.await
			.expect("fits")
			.is_some()
	);
	assert!(matches!(
		read_member(&file, &mut budget).await,
		Err(Refusal::TooLarge)
	));
	assert!(
		read_member(&dir.path().join("missing"), &mut budget)
			.await
			.expect("skipped")
			.is_none()
	);
}
