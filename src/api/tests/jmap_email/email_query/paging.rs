use super::*;

#[tokio::test]
async fn q27_received_at_ascending_uses_internal_date() {
	let f = Fixture::new();
	for sort in [
		json!([{"property": "receivedAt", "isAscending": true}]),
		json!([{"property": "receivedAt"}]),
	] {
		f.page(json!({"sort": sort}), &[&f.old, &f.middle, &f.new], 0)
			.await;
	}
}

#[tokio::test]
async fn q28_received_at_descending_uses_internal_date() {
	let f = Fixture::new();
	f.page(
		json!({"sort": [{"property": "receivedAt", "isAscending": false}]}),
		&[&f.new, &f.middle, &f.old],
		0,
	)
	.await;
}

#[tokio::test]
async fn q29_default_order_is_stable_newest_first_including_ties() {
	let f = Fixture::new();
	// Equal dates in one mailbox are ordered by persistent UID, newest UID first.
	let tied = append(
		f.dir.path(),
		"INBOX",
		EPOCH + 10,
		&[],
		b"Subject: tied\r\n\r\nbody",
	);
	// Freeze UID assignment before querying so snapshot reopen exercises persistence.
	let snapshot =
		mailbox::Snapshot::open(f.dir.path(), "alice", "INBOX", &MessageCrypto::disabled())
			.expect("snapshot");
	let uid = |id: &str| {
		snapshot
			.messages()
			.find(|m| m.id().to_string() == id)
			.expect("message")
			.uid
	};
	let (first, second) = if uid(&tied) > uid(&f.middle) {
		(&tied, &f.middle)
	} else {
		(&f.middle, &tied)
	};
	for args in [
		json!({}),
		json!({}),
		json!({"sort": null}),
		json!({"sort": []}),
	] {
		f.page(args, &[&f.new, first, second, &f.old], 0).await;
	}
}

#[tokio::test]
async fn q33_positive_position_starts_at_the_filtered_sorted_index() {
	let f = Fixture::new();
	f.page(json!({"position": 1}), &[&f.middle, &f.old], 1)
		.await;
	f.page(
		json!({"filter": {"inMailbox": "INBOX"}, "position": 1}),
		&[&f.old],
		1,
	)
	.await;
}

#[tokio::test]
async fn q34_negative_position_counts_from_the_end_and_clamps_at_zero() {
	let f = Fixture::new();
	f.page(json!({"position": -1}), &[&f.old], 2).await;
	f.page(json!({"position": -2}), &[&f.middle, &f.old], 1)
		.await;
	f.page(json!({"position": -100}), &[&f.new, &f.middle, &f.old], 0)
		.await;
}

#[tokio::test]
async fn q35_position_at_or_past_total_returns_an_empty_page() {
	let f = Fixture::new();
	for position in [3, 4, 9_007_199_254_740_991i64] {
		let response = f.page(json!({"position": position}), &[], 3).await;
		assert_eq!(response["total"], 3);
	}
}

#[tokio::test]
async fn q36_anchor_starts_at_its_sorted_id() {
	let f = Fixture::new();
	f.page(json!({"anchor": f.middle}), &[&f.middle, &f.old], 1)
		.await;
}

#[tokio::test]
async fn q37_anchor_offsets_move_both_ways_and_clamp() {
	let f = Fixture::new();
	f.page(json!({"anchor": f.middle, "anchorOffset": 1}), &[&f.old], 2)
		.await;
	f.page(
		json!({"anchor": f.middle, "anchorOffset": -1}),
		&[&f.new, &f.middle, &f.old],
		0,
	)
	.await;
	f.page(
		json!({"anchor": f.middle, "anchorOffset": -100}),
		&[&f.new, &f.middle, &f.old],
		0,
	)
	.await;
	f.page(json!({"anchor": f.middle, "anchorOffset": 100}), &[], 3)
		.await;
}

#[tokio::test]
async fn q38_anchor_overrides_position_and_unanchored_offset_is_ignored() {
	let f = Fixture::new();
	f.page(
		json!({"anchor": f.middle, "position": 999}),
		&[&f.middle, &f.old],
		1,
	)
	.await;
	f.page(
		json!({"position": 1, "anchorOffset": 999}),
		&[&f.middle, &f.old],
		1,
	)
	.await;
	f.page(
		json!({"anchor": null, "anchorOffset": -999}),
		&[&f.new, &f.middle, &f.old],
		0,
	)
	.await;
}

#[tokio::test]
async fn q39_anchor_must_exist_in_the_filtered_result() {
	let f = Fixture::new();
	for args in [
		json!({"anchor": "missing"}),
		json!({"anchor": f.new, "filter": {"inMailbox": "INBOX"}}),
	] {
		error(&call(&f.app, "Email/query", args).await, "anchorNotFound");
	}
}

#[tokio::test]
async fn q40_limit_truncates_after_position_without_changing_total() {
	let f = Fixture::new();
	let response = f
		.page(json!({"position": 1, "limit": 1}), &[&f.middle], 1)
		.await;
	assert_eq!(response["total"], 3);
	assert!(
		response.get("limit").is_none(),
		"explicit limit was not adjusted: {response}"
	);
}

#[tokio::test]
async fn q41_null_missing_and_excess_limits_are_capped_and_announced() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let max = crate::api::jmap::MAX_OBJECTS_IN_GET;
	let mut expected = Vec::new();
	// Real messages prove take(max) is enforced, not just the advertised number.
	for index in 0..=max {
		expected.push(append(
			dir.path(),
			"INBOX",
			EPOCH + index as u64,
			&[],
			b"Subject: page\r\n\r\nx",
		));
	}
	expected.reverse();
	expected.truncate(max);
	for args in [
		json!({}),
		json!({"limit": null}),
		json!({"limit": max + 1}),
		json!({"limit": 9_007_199_254_740_991u64}),
	] {
		let response = query(&app, args).await;
		assert_eq!(response["ids"], json!(expected));
		assert_eq!(response["limit"], max);
		assert_eq!(response["total"], max + 1);
	}
	let response = query(&app, json!({"limit": max})).await;
	assert_eq!(response["ids"], json!(expected));
	assert!(response.get("limit").is_none(), "{response}");
}

#[tokio::test]
async fn q43_calculate_total_true_includes_and_false_omits_total() {
	let f = Fixture::new();
	let args = json!({"calculateTotal": true, "position": 1, "limit": 1, "filter": {"inMailbox": "INBOX"}});
	let response = f.page(args.clone(), &[&f.old], 1).await;
	assert_eq!(response["total"], 2);
	let mut args = args;
	args["calculateTotal"] = json!(false);
	let response = f.page(args, &[&f.old], 1).await;
	assert!(
		response.get("total").is_none(),
		"must omit, not return null: {response}"
	);
}
