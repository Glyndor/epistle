use super::*;

async fn invalid_filter(app: &Router, filter: Value, kind: &str) {
	let response = call(app, "Email/query", json!({"filter": filter})).await;
	error(&response, kind);
	assert!(response[1]["description"].is_string(), "{response}");
}

fn nested(depth: usize) -> Value {
	let mut filter = json!({});
	for _ in 0..depth {
		filter = json!({"operator": "AND", "conditions": [filter]});
	}
	filter
}

#[tokio::test]
async fn q16_filter_depth_boundary() {
	let f = Fixture::new();
	f.filtered(nested(8), &[&f.new, &f.middle, &f.old]).await;
	invalid_filter(&f.app, nested(9), "invalidArguments").await;
}

#[tokio::test]
async fn q17_filter_condition_and_text_term_budgets() {
	let f = Fixture::new();
	// Root plus 63 empty children is exactly 64 nodes.
	f.filtered(
		json!({"operator": "AND", "conditions": vec![json!({}); 63]}),
		&[&f.new, &f.middle, &f.old],
	)
	.await;
	for count in [64, 65] {
		invalid_filter(
			&f.app,
			json!({"operator": "AND", "conditions": vec![json!({}); count]}),
			"invalidArguments",
		)
		.await;
	}
	// Each text expression allows 16 terms; the entire tree allows 32.
	let terms = std::iter::repeat_n("alpha", 16)
		.collect::<Vec<_>>()
		.join(" ");
	f.filtered(
		json!({"operator": "AND", "conditions": [{"subject": terms}, {"text": terms}]}),
		&[&f.old],
	)
	.await;
	invalid_filter(
		&f.app,
		json!({"operator": "AND", "conditions": [
			{"subject": terms}, {"text": terms}, {"from": "SenderNeedle"}
		]}),
		"invalidArguments",
	)
	.await;
	invalid_filter(
		&f.app,
		json!({"text": format!("{terms} alpha")}),
		"invalidArguments",
	)
	.await;
}

#[tokio::test]
async fn q18_unknown_filter_property_is_unsupported_filter() {
	let f = Fixture::new();
	invalid_filter(&f.app, json!({"hasAttachment": true}), "unsupportedFilter").await;
	invalid_filter(
		&f.app,
		json!({"operator": "OR", "conditions": [{"unknown": "x"}]}),
		"unsupportedFilter",
	)
	.await;
}

#[tokio::test]
async fn q19_known_filter_properties_require_the_correct_type() {
	let f = Fixture::new();
	for property in [
		"inMailbox",
		"text",
		"from",
		"to",
		"subject",
		"before",
		"after",
		"hasKeyword",
		"notKeyword",
	] {
		for value in [Value::Null, json!(true), json!(1), json!([]), json!({})] {
			let mut filter = json!({});
			filter[property] = value;
			invalid_filter(&f.app, filter, "invalidArguments").await;
		}
	}
	for filter in [
		json!(false),
		json!([]),
		json!({"operator": "X", "conditions": []}),
		json!({"operator": "AND", "conditions": [1]}),
		json!({"operator": "AND"}),
		json!({"operator": "AND", "conditions": [], "text": "x"}),
	] {
		invalid_filter(&f.app, filter, "invalidArguments").await;
	}
}

#[tokio::test]
async fn q20_mailbox_names_must_be_safe_and_nonempty() {
	let f = Fixture::new();
	for name in [
		"",
		"bad\nname",
		"bad\0name",
		"../escape",
		"/absolute",
		"a/../b",
	] {
		invalid_filter(&f.app, json!({"inMailbox": name}), "invalidArguments").await;
	}
	invalid_filter(
		&f.app,
		json!({"inMailbox": "x".repeat(256)}),
		"invalidArguments",
	)
	.await;
}

#[tokio::test]
async fn q21_dates_must_be_valid_utc_dates() {
	let f = Fixture::new();
	for property in ["before", "after"] {
		for date in [
			"",
			"yesterday",
			"2020-01-01",
			"2020-13-01T00:00:00Z",
			"2020-02-30T00:00:00Z",
			"2020-01-01T00:00:00+01:00",
		] {
			let mut filter = json!({});
			filter[property] = json!(date);
			invalid_filter(&f.app, filter, "invalidArguments").await;
		}
	}
}

#[tokio::test]
async fn q22_text_rejects_unclosed_quotes_trailing_escape_and_excess_bytes() {
	let f = Fixture::new();
	for text in [
		"\"unclosed".to_string(),
		"'unclosed".to_string(),
		"alpha\\".to_string(),
		"x".repeat(1025),
	] {
		for property in ["text", "from", "to", "subject"] {
			let mut filter = json!({});
			filter[property] = json!(text);
			invalid_filter(&f.app, filter, "invalidArguments").await;
		}
	}
	// Byte boundary is accepted, even when there is no matching message.
	f.filtered(json!({"text": "x".repeat(1024)}), &[]).await;
}

#[tokio::test]
async fn q30_unknown_sort_property_is_unsupported_sort() {
	let f = Fixture::new();
	for property in ["subject", "sentAt", "id", "unknown"] {
		let response = call(
			&f.app,
			"Email/query",
			json!({"sort": [{"property": property}]}),
		)
		.await;
		error(&response, "unsupportedSort");
	}
}

#[tokio::test]
async fn q31_malformed_sort_comparators_are_invalid_arguments() {
	let f = Fixture::new();
	for sort in [
		json!({}),
		json!(true),
		json!([null]),
		json!([{}]),
		json!([{"property": 1}]),
		json!([{"property": "receivedAt", "isAscending": "false"}]),
		json!([{"property": "receivedAt", "collation": false}]),
		json!([{"property": "receivedAt", "unknown": true}]),
		json!(vec![json!({"property": "receivedAt"}); 5]),
	] {
		let response = call(&f.app, "Email/query", json!({"sort": sort})).await;
		error(&response, "invalidArguments");
	}
}

#[tokio::test]
async fn q42_limit_must_be_a_nonnegative_jmap_integer() {
	let f = Fixture::new();
	for limit in [
		json!(-1),
		json!(1.5),
		json!("1"),
		json!(true),
		json!(9_007_199_254_740_992u64),
	] {
		let response = call(&f.app, "Email/query", json!({"limit": limit})).await;
		error(&response, "invalidArguments");
	}
	f.page(json!({"limit": 0}), &[], 0).await;
}

#[tokio::test]
async fn q44_paging_arguments_require_the_correct_type_and_integer_range() {
	let f = Fixture::new();
	for property in ["calculateTotal", "collapseThreads"] {
		for value in [Value::Null, json!(0), json!("false"), json!({})] {
			let mut args = json!({});
			args[property] = value;
			error(&call(&f.app, "Email/query", args).await, "invalidArguments");
		}
	}
	for property in ["position", "anchorOffset"] {
		for value in [
			Value::Null,
			json!(true),
			json!("0"),
			json!(1.5),
			json!(9_007_199_254_740_992i64),
			json!(-9_007_199_254_740_992i64),
		] {
			let mut args = json!({});
			args[property] = value;
			error(&call(&f.app, "Email/query", args).await, "invalidArguments");
		}
	}
}
