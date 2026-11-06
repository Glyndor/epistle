//! What each service of a split stack mounts, and in which order.
//!
//! The split promises that `mail`, the process that takes SMTP from the
//! internet, cannot write what `certs` owns: the certificate pair, the TLSA
//! retry state and the file that says which container holds the credential.
//! That promise is implemented as nested bind mounts — a read-only mount of a
//! subdirectory over a read-write mount of its parent — and it only holds
//! while the nested mount is applied after the parent. Nothing in the
//! repository checked that order, so the whole mount table of the split
//! layout is pinned here, and so is the rule that decides which mount wins.

use super::certs::split_answers;
use super::*;
use serde_json::Value;

/// The directories the split shares between the two services, and who owns
/// what inside them: `certs` writes the pair and the TLSA state, and the
/// compose file says which container holds the DNS credential.
const PAIR_DIR: &str = "/var/lib/epistle/acme";
const TLSA_DIR: &str = "/var/lib/epistle/dns-tlsa";
const COMPOSE_DIR: &str = "/var/lib/epistle/compose";

/// A bind mount at its own path: (source, target, read-only).
fn mount(source: &str, read_only: bool) -> (String, String, bool) {
	(source.to_string(), source.to_string(), read_only)
}

/// The bind mounts of `service`, in the order the rendered file carries
/// them. The named volumes are not paths on the host and are not part of
/// the table.
fn binds(service: &Value) -> Vec<(String, String, bool)> {
	service["volumes"]
		.as_array()
		.expect("volumes")
		.iter()
		.filter(|volume| volume["type"] == "bind")
		.map(|volume| {
			(
				volume["source"].as_str().expect("source").to_string(),
				volume["target"].as_str().expect("target").to_string(),
				volume["read_only"].as_bool().expect("read_only"),
			)
		})
		.collect()
}

/// The mounts of `service` that reach `path`: the ones whose target is the
/// path itself or a directory above it. The last of them is the one that
/// counts, because a mount applied later sits on top of an earlier one.
fn reaching(mounts: &[(String, String, bool)], path: &str) -> Vec<(String, bool)> {
	mounts
		.iter()
		.filter(|(_, target, _)| target == path || path.starts_with(&format!("{target}/")))
		.map(|(_, target, read_only)| (target.clone(), *read_only))
		.collect()
}

/// The mount of `service` that reaches `path` last, and whether it is
/// read-only.
fn last_reaching(mounts: &[(String, String, bool)], path: &str) -> (String, bool) {
	let reaching = reaching(mounts, path);
	let (target, read_only) = reaching.last().expect("a mount reaches the path").clone();
	(target, read_only)
}

/// The table of the split layout: every path each service mounts and the
/// mode it mounts it with. A path that appears here and nowhere else is a
/// path one of the two containers holds and the other does not.
#[test]
fn the_split_layout_mounts_exactly_what_each_service_needs() {
	let value = render(&split_answers("/secure/dns/token"), true);
	assert_eq!(
		binds(&value["services"]["mail"]),
		[
			mount("/etc/epistle", true),
			mount("/var/lib/epistle", false),
			mount(PAIR_DIR, true),
			mount(TLSA_DIR, true),
			mount(COMPOSE_DIR, true),
			mount("/usr/bin/epistle", true),
		]
	);
	assert_eq!(
		binds(&value["services"]["certs"]),
		[
			mount("/etc/epistle", true),
			mount(PAIR_DIR, false),
			mount(TLSA_DIR, false),
			mount("/secure/dns/token", true),
			mount("/usr/bin/epistle", true),
		]
	);
}

/// `certs` holds the DNS credential and the ACME account key, and writes
/// the pair and the TLSA state. `mail` holds neither credential and writes
/// neither state: the pair and the TLSA state are read-only there, and the
/// account key is not mounted at all.
#[test]
fn the_paths_certs_owns_are_writable_only_in_certs() {
	let value = render(&split_answers("/secure/dns/token"), true);
	let mail = binds(&value["services"]["mail"]);
	let certs = binds(&value["services"]["certs"]);
	for path in [PAIR_DIR, TLSA_DIR] {
		let in_mail = mail
			.iter()
			.filter(|(source, ..)| source == path)
			.collect::<Vec<_>>();
		assert_eq!(in_mail.len(), 1, "mail mounts {path} once");
		assert!(in_mail[0].2, "mail must not be able to write {path}");
		let in_certs = certs
			.iter()
			.filter(|(source, ..)| source == path)
			.collect::<Vec<_>>();
		assert_eq!(in_certs.len(), 1, "certs mounts {path} once");
		assert!(!in_certs[0].2, "certs must be able to write {path}");
	}
	// The compose file names the container that holds the credential:
	// `mail` reads it and cannot write it, `certs` never mounts it.
	assert!(
		mail.iter()
			.any(|(source, _, read_only)| source == COMPOSE_DIR && *read_only),
		"mail must read the compose directory and not write it"
	);
	assert!(
		!certs.iter().any(|(source, ..)| source == COMPOSE_DIR),
		"certs does not need the compose directory"
	);
	// The account key: a secret in `certs`, nothing in `mail`.
	let account_key = |service: &Value| {
		service["secrets"]
			.as_array()
			.expect("secrets")
			.iter()
			.any(|secret| secret["source"] == "epistle_acme_account_key")
	};
	assert!(
		account_key(&value["services"]["certs"]),
		"certs holds the key"
	);
	assert!(
		!account_key(&value["services"]["mail"]),
		"mail holds the key"
	);
}

/// The read-only mount of a directory `certs` owns is applied after the
/// read-write mount of data_dir, and nothing after it covers the directory
/// again: the last mount that reaches a path is the one that counts, and a
/// read-write mount applied last would hand `mail` back what `certs` owns.
#[test]
fn no_later_mount_shadows_the_paths_certs_owns() {
	let value = render(&split_answers("/secure/dns/token"), true);
	let mail = binds(&value["services"]["mail"]);
	let certs = binds(&value["services"]["certs"]);
	for (path, read_only) in [(PAIR_DIR, true), (TLSA_DIR, true), (COMPOSE_DIR, true)] {
		let (target, last_is_read_only) = last_reaching(&mail, path);
		assert_eq!(
			target, path,
			"mail mounts {path} read-only, and the mount that reaches it last is the one at {path}"
		);
		assert_eq!(last_is_read_only, read_only, "mail and {path}");
	}
	for path in [PAIR_DIR, TLSA_DIR] {
		let (target, last_is_read_only) = last_reaching(&certs, path);
		assert_eq!(
			target, path,
			"certs mounts {path} read-write, and the mount that reaches it last is the one at {path}"
		);
		assert!(!last_is_read_only, "certs cannot write {path}");
	}
}
