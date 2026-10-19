//! Who may change whose scripts: an account sets only its own, whatever ids,
//! blobs and names a request carries.

use serde_json::{Value, json};

use super::jmap_tests_sieve_support::{ann_only, call, store, upload};
use super::tests::TOKEN;

const KEEP: &[u8] = b"keep;\r\n";

/// Everything under `root`, as relative paths, sorted.
fn tree(root: &std::path::Path) -> Vec<String> {
	fn walk(dir: &std::path::Path, root: &std::path::Path, out: &mut Vec<String>) {
		for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
			let path = entry.path();
			out.push(
				path.strip_prefix(root)
					.expect("under root")
					.display()
					.to_string(),
			);
			if path.is_dir() {
				walk(&path, root, out);
			}
		}
	}
	let mut out = Vec::new();
	walk(root, root, &mut out);
	out.sort();
	out
}

#[tokio::test]
async fn an_account_cannot_set_on_another_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, secret) = ann_only(dir.path(), &["read", "write"]);
	let bobs_blob = upload(&app, TOKEN.as_str(), "bob", KEEP).await;
	let response = call(
		&app,
		&secret,
		"SieveScript/set",
		json!({"accountId": "bob", "create": {"a": {"name": "planted", "blobId": bobs_blob}}}),
	)
	.await;
	assert_eq!(response[0], "error");
	assert_eq!(response[1]["type"], "accountNotFound");
	assert!(store(dir.path(), "bob").list().expect("list").is_empty());
	for method in ["SieveScript/get", "SieveScript/query"] {
		let read = call(&app, &secret, method, json!({"accountId": "bob"})).await;
		assert_eq!(read[1]["type"], "accountNotFound", "{method}");
	}
}

#[tokio::test]
async fn another_accounts_blob_cannot_become_my_script() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, secret) = ann_only(dir.path(), &["read", "write"]);
	let bobs_blob = upload(&app, TOKEN.as_str(), "bob", b"discard;\r\n").await;
	let response = call(
		&app,
		&secret,
		"SieveScript/set",
		json!({"accountId": "ann", "create": {"a": {"name": "stolen", "blobId": bobs_blob}}}),
	)
	.await;
	assert_eq!(
		response[1]["notCreated"]["a"],
		json!({"type": "blobNotFound", "notFound": [bobs_blob]})
	);
	assert!(store(dir.path(), "ann").list().expect("list").is_empty());
}

#[tokio::test]
async fn another_accounts_script_ids_find_nothing_here() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, secret) = ann_only(dir.path(), &["read", "write"]);
	let bobs = store(dir.path(), "bob");
	let work = bobs.create("work", "keep;\r\n").expect("work");
	let other = bobs.create("other", "keep;\r\n").expect("other");
	bobs.set_active(Some("work")).expect("activate");
	let blob = upload(&app, TOKEN.as_str(), "ann", b"discard;\r\n").await;
	let anns = store(dir.path(), "ann")
		.create("mine", "keep;\r\n")
		.expect("mine");
	let response = call(
		&app,
		&secret,
		"SieveScript/set",
		json!({
			"accountId": "ann",
			"update": {work.id.clone(): {"name": "hijacked", "blobId": blob}},
			"destroy": [other.id.clone()],
			"onSuccessActivateScript": other.id,
		}),
	)
	.await;
	assert_eq!(
		response[1]["notUpdated"][&work.id],
		json!({"type": "notFound"})
	);
	assert_eq!(
		response[1]["notDestroyed"][&other.id],
		json!({"type": "notFound"})
	);
	// Both refusals mean the activation is not attempted; asked alone it is ignored too.
	let alone = call(
		&app,
		&secret,
		"SieveScript/set",
		json!({"accountId": "ann", "onSuccessActivateScript": other.id}),
	)
	.await;
	assert_eq!(alone[1]["updated"], json!({}));
	assert_eq!(store(dir.path(), "ann").active_name(), None);
	// Bob's side is exactly as it was.
	assert_eq!(bobs.get("work").expect("work"), "keep;\r\n");
	assert_eq!(bobs.get("other").expect("other"), "keep;\r\n");
	assert_eq!(bobs.active_name().as_deref(), Some("work"));
	assert_eq!(bobs.list().expect("list").len(), 2);
	assert_eq!(
		store(dir.path(), "ann").get("mine").expect("mine"),
		"keep;\r\n"
	);
	let _ = anns;
}

#[tokio::test]
async fn an_id_is_scoped_to_the_account_even_for_a_principal_that_sees_both() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, _) = ann_only(dir.path(), &["read", "write"]);
	let anns = store(dir.path(), "ann")
		.create("mine", "keep;\r\n")
		.expect("ann");
	// The configured token reaches every account; an id still names a script of one.
	let response = call(
		&app,
		TOKEN.as_str(),
		"SieveScript/set",
		json!({"accountId": "bob", "destroy": [anns.id.clone()]}),
	)
	.await;
	assert_eq!(
		response[1]["notDestroyed"][&anns.id],
		json!({"type": "notFound"})
	);
	assert_eq!(
		store(dir.path(), "ann").get("mine").expect("untouched"),
		"keep;\r\n"
	);
}

#[tokio::test]
async fn the_same_name_in_two_accounts_is_two_scripts() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, _) = ann_only(dir.path(), &["read", "write"]);
	for (account, script) in [("ann", &b"keep;\r\n"[..]), ("bob", &b"discard;\r\n"[..])] {
		let blob = upload(&app, TOKEN.as_str(), account, script).await;
		let response = call(&app, TOKEN.as_str(), "SieveScript/set", json!({"accountId": account, "create": {"a": {"name": "work", "blobId": blob}}, "onSuccessActivateScript": "#a"})).await;
		assert!(
			response[1]["created"]["a"]["id"].is_string(),
			"the script was not created: {response}"
		);
	}
	assert_eq!(
		store(dir.path(), "ann").get("work").expect("ann"),
		"keep;\r\n"
	);
	assert_eq!(
		store(dir.path(), "bob").get("work").expect("bob"),
		"discard;\r\n"
	);
	let live = |account: &str| {
		std::fs::read_to_string(
			dir.path()
				.join("accounts")
				.join(account)
				.join("filter.sieve"),
		)
		.expect("filter")
	};
	assert_eq!(live("ann"), "keep;\r\n");
	assert_eq!(live("bob"), "discard;\r\n");
}

#[tokio::test]
async fn a_name_cannot_leave_the_script_directory() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, _) = ann_only(dir.path(), &["read", "write"]);
	let blob = upload(&app, TOKEN.as_str(), "ann", KEEP).await;
	let before = tree(dir.path());
	for name in [
		"../escape",
		"..",
		".",
		"a/../../escape",
		"/etc/escape",
		"..\\escape",
		"x\0y",
		"x\ny",
		"x\u{1b}[2Jy",
	] {
		let response = call(
			&app,
			TOKEN.as_str(),
			"SieveScript/set",
			json!({"accountId": "ann", "create": {"a": {"name": name, "blobId": blob}}}),
		)
		.await;
		assert_eq!(
			response[1]["notCreated"]["a"],
			json!({"type": "invalidProperties", "properties": ["name"]}),
			"{name:?}"
		);
	}
	let after = tree(dir.path());
	// Only the account's own script directory and its lock appeared.
	let new: Vec<&String> = after.iter().filter(|path| !before.contains(path)).collect();
	let allowed = [
		"accounts",
		"accounts/ann",
		"accounts/ann/sieve",
		"accounts/ann/sieve/.lock",
	];
	assert!(
		new.iter().all(|path| allowed.contains(&path.as_str())),
		"something was written outside the script directory: {new:?}"
	);
	assert!(
		before.iter().all(|path| after.contains(path)),
		"nothing was removed"
	);
}

#[tokio::test]
async fn the_write_scope_stores_and_the_read_scope_only_reads() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, secret) = ann_only(dir.path(), &["read"]);
	let blob = upload(&app, TOKEN.as_str(), "ann", KEEP).await;
	let denied = call(
		&app,
		&secret,
		"SieveScript/set",
		json!({"accountId": "ann", "create": {"a": {"name": "x", "blobId": blob}}}),
	)
	.await;
	assert_eq!(denied[0], "error");
	assert_eq!(denied[1]["type"], "forbidden");
	assert!(store(dir.path(), "ann").list().expect("list").is_empty());

	let other = tempfile::tempdir().expect("tempdir");
	let (app, secret) = ann_only(other.path(), &["write"]);
	let blob = upload(&app, TOKEN.as_str(), "ann", KEEP).await;
	let stored = call(
		&app,
		&secret,
		"SieveScript/set",
		json!({"accountId": "ann", "create": {"a": {"name": "x", "blobId": blob}}}),
	)
	.await;
	assert_eq!(stored[0], "SieveScript/set");
	assert!(stored[1]["created"]["a"]["id"].is_string(), "{stored}");
	let read: Value = call(
		&app,
		&secret,
		"SieveScript/get",
		json!({"accountId": "ann"}),
	)
	.await;
	assert_eq!(
		read[1]["type"], "forbidden",
		"a write-only key does not list scripts"
	);
}
