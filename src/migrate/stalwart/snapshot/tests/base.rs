use serde_json::json;

use super::*;
use crate::migrate::import::Algorithm;
use crate::migrate::import::tests::test_keys;

/// A snapshot of two domains, a group, two users, a list and three keys,
/// in the shape `stalwart-cli snapshot --include-secrets` prints.
fn plan_text(ed: &str, rsa: &str) -> String {
	let lines = [
		json!({"@type":"upsert","object":"Domain","matchOn":["name"],"value":{
			"domain-a":{"name":"example.org","catchAllAddress":"jane@example.org",
				"aliases":{"example.net":true}},
			"domain-b":{"name":"Example.COM","enable":false}}}),
		json!({"@type":"upsert","object":"Account","matchOn":["name"],"value":{
			"account-a":{"@type":"Group","name":"support","domainId":"#domain-a"}}}),
		json!({"@type":"upsert","object":"Account","matchOn":["name"],"value":{
			"account-b":{"@type":"User","name":"john","domainId":"#domain-a",
				"description":"John Doe",
				"credentials":{"0":{"@type":"Password","secret":"$argon2id$v=19$not-a-real-hash"}},
				"aliases":{"0":{"name":"j.doe","domainId":"#domain-a"},
					"1":{"name":"off","domainId":"#domain-a","enable":false}},
				"memberGroupIds":{"#account-a":true}},
			"account-c":{"@type":"User","name":"jane","domainId":"#domain-a",
				"roles":{"@type":"Admin"}},
			"account-d":{"@type":"User","name":"lost","domainId":"#domain-zz"}}}),
		json!({"@type":"upsert","object":"MailingList","matchOn":["name"],"value":{
			"list-a":{"name":"sales","domainId":"#domain-a",
				"recipients":{"john@example.org":true,"jane@example.org":true,"bad":true}}}}),
		json!({"@type":"upsert","object":"DkimSignature","matchOn":["selector"],"value":{
			"dkimsignature-a":{"@type":"Dkim1Ed25519Sha256","domainId":"#domain-a",
				"selector":"edsel","privateKey":{"@type":"Text","secret":ed}},
			"dkimsignature-b":{"@type":"Dkim1RsaSha256","domainId":"#domain-a",
				"selector":"rsasel","privateKey":{"@type":"Text","secret":rsa}},
			"dkimsignature-c":{"@type":"Dkim1RsaSha256","domainId":"#domain-a",
				"selector":"masked","privateKey":{"@type":"Text","secret":"****"}},
			"dkimsignature-d":{"@type":"Dkim1RsaSha256","domainId":"#domain-a",
				"selector":"gone","stage":"retired","privateKey":{"@type":"Text","secret":rsa}},
			"dkimsignature-e":{"@type":"Dkim2MlDsa44","domainId":"#domain-a",
				"selector":"pq"}}}),
		json!({"@type":"update","object":"SystemSettings","value":{"defaultHostname":"mx.example.org"}}),
	];
	let mut text = String::new();
	for line in lines {
		text.push_str(&line.to_string());
		text.push('\n');
	}
	text
}

fn write(dir: &std::path::Path) -> (std::path::PathBuf, String, String) {
	let ed = test_keys::ed25519_v2_pem();
	let rsa = test_keys::rsa_pkcs8_pem().to_string();
	let file = dir.join("plan.ndjson");
	std::fs::write(&file, plan_text(&ed, &rsa)).expect("write");
	(file, ed, rsa)
}

#[test]
fn reads_domains_accounts_lists_and_keys() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (file, ..) = write(dir.path());
	let plan = crate::migrate::stalwart::read(&file).expect("plan");
	assert_eq!(plan.domains, ["example.org", "example.com"]);
	let john = plan
		.accounts
		.iter()
		.find(|a| a.name == "john")
		.expect("john");
	assert_eq!(john.addresses, ["john@example.org", "j.doe@example.org"]);
	assert_eq!(john.display_name.as_deref(), Some("John Doe"));
	let jane = plan
		.accounts
		.iter()
		.find(|a| a.name == "jane")
		.expect("jane");
	assert_eq!(jane.catch_all, ["example.org"]);
	assert!(
		plan.manual
			.iter()
			.any(|m| m.contains("jane") && m.contains("administrator"))
	);
	assert!(
		plan.manual
			.iter()
			.any(|m| m.contains("example.com") && m.contains("disabled"))
	);
	assert!(plan.manual.iter().any(|m| m.contains("alias domains")));
	assert!(plan.skipped.iter().any(|n| n.item == "account lost"));
	let alias = |address: &str| {
		plan.aliases
			.iter()
			.find(|a| a.address == address)
			.expect(address)
	};
	assert_eq!(alias("support@example.org").members, ["john@example.org"]);
	assert_eq!(
		alias("sales@example.org").members,
		["jane@example.org", "john@example.org"]
	);
	assert!(plan.skipped.iter().any(|n| n.item.contains("bad")));
	let mut keys: Vec<(&str, Algorithm)> = plan
		.keys
		.iter()
		.map(|k| (k.selector.as_str(), k.algorithm))
		.collect();
	keys.sort_by_key(|k| k.0);
	assert_eq!(
		keys,
		[("edsel", Algorithm::Ed25519), ("rsasel", Algorithm::Rsa)]
	);
	let skipped = |item: &str, reason: &str| {
		plan.skipped
			.iter()
			.any(|n| n.item.contains(item) && n.reason.contains(reason))
	};
	assert!(skipped("masked", "--include-secrets"));
	assert!(skipped("gone", "active"));
	assert!(skipped("pq", "DKIM1"));
	assert!(plan.manual.iter().any(|m| m.contains("systemsettings")));
}

#[test]
fn passwords_and_keys_never_appear_in_the_plan_output() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (file, ed, rsa) = write(dir.path());
	let plan = crate::migrate::stalwart::read(&file).expect("plan");
	let shown = format!("{plan:?}\n{}", serde_json::to_string(&plan).expect("json"));
	for pem in [&ed, &rsa] {
		let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
		assert!(!shown.contains(&body[..40]));
	}
	assert!(!shown.contains("PRIVATE KEY"));
	assert!(!shown.contains("not-a-real-hash"));
}

#[test]
fn a_snapshot_without_secrets_skips_every_key_and_still_imports_the_rest() {
	let dir = tempfile::tempdir().expect("tempdir");
	let file = dir.path().join("plan.ndjson");
	let text = r##"{"@type":"upsert","object":"Domain","matchOn":["name"],"value":{"d":{"name":"example.org"}}}
{"@type":"upsert","object":"DkimSignature","matchOn":["selector"],"value":{"k":{"@type":"Dkim1Ed25519Sha256","domainId":"#d","selector":"s1"}}}
"##;
	std::fs::write(&file, text).expect("write");
	let plan = crate::migrate::stalwart::read(&file).expect("plan");
	assert_eq!(plan.domains, ["example.org"]);
	assert!(plan.keys.is_empty());
	assert!(
		plan.skipped
			.iter()
			.any(|n| n.reason.contains("--include-secrets"))
	);
}

#[test]
fn a_broken_line_names_its_number() {
	let dir = tempfile::tempdir().expect("tempdir");
	let file = dir.path().join("plan.ndjson");
	std::fs::write(
		&file,
		"{\"@type\":\"update\",\"object\":\"SystemSettings\",\"value\":{}}\n{oops\n",
	)
	.expect("write");
	let error = crate::migrate::stalwart::read(&file).expect_err("refused");
	assert!(error.to_string().contains("line 2"), "{error}");
}

#[test]
fn the_bootstrap_file_is_still_told_apart_from_a_plan() {
	assert!(!is_plan(
		r#"{"@type":"RocksDb","path":"/var/lib/stalwart/"}"#
	));
	assert!(is_plan(
		"\n{\"@type\":\"upsert\",\"object\":\"Domain\",\"value\":{}}\n"
	));
}
