use super::*;
use crate::api::tests::base::request;

#[tokio::test]
async fn q51_query_changes_keeps_mailbox_scope_and_descending_received_at() {
	let f = Fixture::new();
	let filter = json!({"inMailbox": "Archive"});
	let sort = json!([{"property": "receivedAt", "isAscending": false}]);
	let initial = query(&f.app, json!({"filter": filter, "sort": sort})).await;
	assert_eq!(initial["ids"], json!([f.new]));
	assert_eq!(initial["canCalculateChanges"], true);
	let early = append(
		f.dir.path(),
		"Archive",
		EPOCH - 10,
		&[],
		b"Subject: early\r\n\r\nx",
	);
	let late = append(
		f.dir.path(),
		"Archive",
		EPOCH + 40,
		&[],
		b"Subject: late\r\n\r\nx",
	);
	append(
		f.dir.path(),
		"INBOX",
		EPOCH + 50,
		&[],
		b"Subject: outside\r\n\r\nx",
	);
	let response = call(
		&f.app,
		"Email/queryChanges",
		json!({
			"filter": filter, "sort": sort, "sinceQueryState": initial["queryState"], "calculateTotal": true
		}),
	)
	.await;
	assert_eq!(response[0], "Email/queryChanges", "{response}");
	assert_eq!(response[1]["oldQueryState"], initial["queryState"]);
	assert_eq!(response[1]["removed"], json!([]));
	assert_eq!(
		response[1]["added"],
		json!([{"id": late, "index": 0}, {"id": early, "index": 2}])
	);
	assert_eq!(response[1]["total"], 3);
	let current = query(&f.app, json!({"filter": filter, "sort": sort})).await;
	assert_eq!(current["ids"], json!([late, f.new, early]));
	assert_eq!(response[1]["newQueryState"], current["queryState"]);
}

#[tokio::test]
async fn q52_nonreplayable_filters_and_sort_refuse_query_changes() {
	let f = Fixture::new();
	let since = query(&f.app, json!({})).await["queryState"].clone();
	for mut args in [
		json!({"filter": {"text": "needle"}}),
		json!({"filter": {"hasKeyword": "$seen"}}),
		json!({"filter": {"before": "2020-01-01T00:00:10Z"}}),
		json!({"filter": {"operator": "OR", "conditions": [{"inMailbox": "INBOX"}]}}),
		json!({"filter": {"inMailbox": "INBOX", "subject": "alpha"}}),
		json!({"sort": [{"property": "receivedAt", "isAscending": true}]}),
	] {
		let initial = query(&f.app, args.clone()).await;
		assert_eq!(initial["canCalculateChanges"], false, "{args}");
		args["sinceQueryState"] = since.clone();
		error(
			&call(&f.app, "Email/queryChanges", args).await,
			"cannotCalculateChanges",
		);
	}
}

#[tokio::test]
async fn q54_query_and_query_changes_share_order_and_indices_including_ties() {
	let f = Fixture::new();
	let initial = query(&f.app, json!({})).await;
	// Ties across and within mailboxes exercise both UID and final UUID tie breakers.
	let a = append(
		f.dir.path(),
		"INBOX",
		EPOCH + 30,
		&[],
		b"Subject: a\r\n\r\nx",
	);
	let b = append(
		f.dir.path(),
		"Archive",
		EPOCH + 30,
		&[],
		b"Subject: b\r\n\r\nx",
	);
	let c = append(
		f.dir.path(),
		"Archive",
		EPOCH + 30,
		&[],
		b"Subject: c\r\n\r\nx",
	);
	for args in [
		json!({}),
		json!({"filter": {"inMailbox": "Archive"}, "sort": [{"property": "receivedAt", "isAscending": false}]}),
	] {
		let current = query(&f.app, args.clone()).await;
		let mut changes_args = args;
		changes_args["sinceQueryState"] = initial["queryState"].clone();
		let changes = call(&f.app, "Email/queryChanges", changes_args).await;
		assert_eq!(changes[0], "Email/queryChanges", "{changes}");
		let expected: Vec<Value> = current["ids"]
			.as_array()
			.expect("ids")
			.iter()
			.enumerate()
			.filter(|(_, id)| {
				[a.as_str(), b.as_str(), c.as_str()].contains(&id.as_str().expect("id"))
			})
			.map(|(index, id)| json!({"id": id, "index": index}))
			.collect();
		assert!(!expected.is_empty());
		assert_eq!(changes[1]["added"], json!(expected));
		assert_eq!(changes[1]["removed"], json!([]));
		assert_eq!(changes[1]["newQueryState"], current["queryState"]);
	}
}

#[tokio::test]
async fn q56_foreign_existing_account_returns_account_not_found() {
	let dir = tempfile::tempdir().expect("tempdir");
	let secret = "query-alice-only";
	let mut keys = crate::api::ApiKeyStore::open(dir.path()).expect("key store");
	keys.add(crate::api::api_keys::ApiKey {
		label: "query-alice".into(),
		hash: crate::api::api_keys::sha256_hash(secret),
		expires_at: None,
		ip_cidr: None,
		scopes: vec!["read".into()],
		domains: Vec::new(),
		account: Some("alice".into()),
	})
	.expect("account-bound key");
	drop(keys);
	let app = router(test_state(dir.path(), 0));
	let (status, created) = request_with_body(&app, "POST", "/api/v1/accounts", Some(TOKEN.as_str()),
		Some(json!({"name": "bob", "addresses": ["bob@example.org"], "password": crate::test_support::fixtures::password()}))).await;
	assert_eq!(status, StatusCode::OK, "{created}");
	assert_eq!(created["created"], "bob");
	let bob = mailbox::append(
		dir.path(),
		"bob",
		"INBOX",
		&[],
		b"Subject: private\r\n\r\nx",
		&MessageCrypto::disabled(),
	)
	.expect("bob mail");
	assert_eq!(
		query(&app, json!({"accountId": "bob"})).await["ids"],
		json!([bob.to_string()])
	);
	for account in ["alice", "bob", "missing"] {
		let req = json!({"using": [MAIL], "methodCalls": [["Email/query", {"accountId": account}, "c1"]]});
		let (status, body) =
			request_with_body(&app, "POST", "/jmap/api", Some(secret), Some(req)).await;
		assert_eq!(status, StatusCode::OK, "{body}");
		let response = &body["methodResponses"][0];
		assert_eq!(response[2], "c1");
		if account == "alice" {
			assert_eq!(response[0], "Email/query", "{response}");
		} else {
			error(response, "accountNotFound");
		}
	}
}

#[tokio::test]
async fn q32_and_q57_session_announces_sort_and_every_query_limit_at_both_levels() {
	let f = Fixture::new();
	let (status, session) = request(&f.app, "GET", "/jmap/session", Some(TOKEN.as_str())).await;
	assert_eq!(status, StatusCode::OK, "{session}");
	for capabilities in [
		&session["capabilities"][MAIL],
		&session["accounts"]["alice"]["accountCapabilities"][MAIL],
	] {
		assert_eq!(capabilities["emailQuerySortOptions"], json!(["receivedAt"]));
		for (name, expected) in [
			(
				"maxEmailQueryLimit",
				crate::api::jmap::MAX_OBJECTS_IN_GET as u64,
			),
			("maxEmailQueryResults", 100_000),
			("maxEmailQueryMailboxes", 1_000),
			("maxEmailQuerySearchMessages", 10_000),
			("maxEmailQuerySearchBytes", 16 * 1024 * 1024),
			("maxEmailQuerySearchHeaderBytes", 256 * 1024),
		] {
			assert_eq!(capabilities[name], expected, "{name}: {capabilities}");
		}
	}
}
