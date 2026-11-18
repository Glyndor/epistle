//! Keep the two cargo-deny advisory ignore lists and their documentation in sync.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

fn read(root: &Path, path: &str) -> String {
	fs::read_to_string(root.join(path)).unwrap_or_else(|error| panic!("read {path}: {error}"))
}

#[test]
fn advisory_ignores_agree_and_are_documented() {
	let root = Path::new(env!("CARGO_MANIFEST_DIR"));
	let deny: toml::Table = toml::from_str(&read(root, "deny.toml")).expect("parse deny.toml");
	let audit: toml::Table =
		toml::from_str(&read(root, ".cargo/audit.toml")).expect("parse .cargo/audit.toml");
	let deny_ignores = deny
		.get("advisories")
		.and_then(|table| table.get("ignore"))
		.and_then(toml::Value::as_array)
		.expect("deny.toml [advisories].ignore must be an array");
	let audit_ignores = audit
		.get("advisories")
		.and_then(|table| table.get("ignore"))
		.and_then(toml::Value::as_array)
		.expect(".cargo/audit.toml [advisories].ignore must be an array");

	let mut deny_ids = BTreeSet::new();
	for ignore in deny_ignores {
		let id = ignore
			.get("id")
			.and_then(toml::Value::as_str)
			.expect("each deny.toml ignore must have a string id");
		let reason = ignore
			.get("reason")
			.and_then(toml::Value::as_str)
			.expect("each deny.toml ignore must have a string reason");
		assert!(!reason.trim().is_empty(), "{id} has an empty ignore reason");
		assert!(
			deny_ids.insert(id),
			"duplicate advisory ignore {id} in deny.toml"
		);
	}

	let audit_ids: BTreeSet<_> = audit_ignores
		.iter()
		.map(|ignore| ignore.as_str().expect("each audit ignore must be a string"))
		.collect();
	assert_eq!(
		deny_ids, audit_ids,
		"deny.toml and .cargo/audit.toml ignore different advisories"
	);

	let threat_model = read(root, "docs/threat-model.md");
	for id in &deny_ids {
		assert!(
			threat_model.contains(id),
			"docs/threat-model.md does not mention ignored advisory {id}"
		);
	}
}
