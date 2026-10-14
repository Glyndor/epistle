use super::*;
use crate::migrate::import::{Account, Algorithm};

fn names(plan: &Plan) -> Vec<&str> {
	let mut names: Vec<&str> = plan.accounts.iter().map(|a| a.name.as_str()).collect();
	names.sort_unstable();
	names
}

fn account<'a>(plan: &'a Plan, name: &str) -> &'a Account {
	plan.accounts.iter().find(|a| a.name == name).expect(name)
}

#[test]
fn reads_domains_accounts_aliases_and_signing_keys() {
	let dir = tempfile::tempdir().expect("tempdir");
	fixture::write(dir.path());
	let plan = read(dir.path()).expect("plan");
	let mut domains = plan.domains.clone();
	domains.sort();
	assert_eq!(domains, ["example.com", "xn--bcher-kva.example"]);
	assert_eq!(names(&plan), ["alice", "bob"]);
	assert!(
		plan.skipped
			.iter()
			.any(|n| n.item == "account Mail Admin" && n.reason.contains("lowercase")),
		"a name the store cannot hold is reported, not renamed: {:?}",
		plan.skipped
	);
	let alice = account(&plan, "alice");
	assert_eq!(
		alice.addresses,
		["alice@example.com", "postmaster@example.com"]
	);
	assert_eq!(alice.display_name.as_deref(), Some("Alice Liddell"));
	let bob = account(&plan, "bob");
	assert_eq!(
		bob.addresses,
		["bob@example.com", "info@xn--bcher-kva.example"]
	);
	assert_eq!(bob.catch_all, ["example.com"]);
	assert_eq!(plan.aliases.len(), 1);
	assert_eq!(plan.aliases[0].address, "team@example.com");
	assert_eq!(
		plan.aliases[0].members,
		["alice@example.com", "bob@example.com"]
	);
	assert!(
		!plan.aliases[0].hidden,
		"ListMembers: true makes the list visible"
	);
	let mut keys: Vec<(&str, &str, Algorithm)> = plan
		.keys
		.iter()
		.map(|k| (k.domain.as_str(), k.selector.as_str(), k.algorithm))
		.collect();
	keys.sort_by_key(|k| (k.0, k.1));
	assert_eq!(
		keys,
		[
			("example.com", "2024a", Algorithm::Ed25519),
			("example.com", "2024b", Algorithm::Rsa),
			("xn--bcher-kva.example", "2024a", Algorithm::Ed25519),
		]
	);
	assert!(
		plan.skipped
			.iter()
			.any(|n| n.item.contains("2023old") && n.reason.contains("Sign")),
		"{:?}",
		plan.skipped
	);
	assert!(plan.manual.iter().any(|step| step.contains("DMARC")));
	assert!(
		plan.manual
			.iter()
			.any(|step| step.contains("bob") && step.contains("disabled"))
	);
	assert!(plan.manual.iter().any(|step| step.contains("passwords")));
}

#[test]
fn mox_conf_alone_is_enough_to_find_the_directory() {
	let dir = tempfile::tempdir().expect("tempdir");
	fixture::write(dir.path());
	let plan = read(&dir.path().join("mox.conf")).expect("plan");
	assert_eq!(plan.accounts.len(), 2);
}

#[test]
fn keys_never_appear_in_the_plan_output() {
	let dir = tempfile::tempdir().expect("tempdir");
	let written = fixture::write(dir.path());
	let plan = read(dir.path()).expect("plan");
	let shown = format!("{plan:?}\n{}", serde_json::to_string(&plan).expect("json"));
	for pem in [&written.ed25519, &written.rsa, &written.other] {
		let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
		assert!(
			!shown.contains(&body[..40]),
			"key material in the plan output"
		);
	}
	assert!(!shown.contains("PRIVATE KEY"));
	assert!(
		plan.manual
			.iter()
			.chain(plan.skipped.iter().map(|n| &n.reason))
			.all(|line| !line.chars().any(char::is_control)),
		"output lines carry no tabs or control characters"
	);
}

#[test]
fn a_missing_or_broken_file_is_an_error() {
	let dir = tempfile::tempdir().expect("tempdir");
	assert!(matches!(read(dir.path()), Err(ReadError::Io(..))));
	fixture::write(dir.path());
	std::fs::write(dir.path().join("domains.conf"), "Domains:\n  bad: indent\n").expect("write");
	assert!(matches!(read(dir.path()), Err(ReadError::Parse(..))));
}

#[test]
fn a_broken_key_is_skipped_with_its_reason() {
	let dir = tempfile::tempdir().expect("tempdir");
	fixture::write(dir.path());
	std::fs::write(
		dir.path()
			.join("dkim/2024b._domainkey.example.com.rsa2048.privatekey.pkcs8.pem"),
		"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
	)
	.expect("write");
	let plan = read(dir.path()).expect("plan");
	assert_eq!(plan.keys.len(), 2);
	assert!(plan.skipped.iter().any(|n| n.item.contains("2024b")));
}
