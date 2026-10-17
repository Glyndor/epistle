//! Leftovers no rotation names are found, logged and removed only when the
//! operator asks; anything the state names, or the configuration, stays.

use super::orphans::{orphan_key_files, orphan_records};
use super::tests_crash::{DOMAINS, Lab, NOW, Start, Visibility};
use super::*;
use crate::dns::provider::RecordKind;

fn txt(name: &str) -> DnsRecord {
	DnsRecord {
		name: name.into(),
		kind: RecordKind::Txt,
		value: "v=DKIM1; k=ed25519; p=AAAA".into(),
		ttl: 300,
		proxied: None,
	}
}

fn state_with_all_three() -> RotationState {
	RotationState {
		selector: "ed100".into(),
		key_file: "dkim-ed100.key".into(),
		rotated_at: NOW,
		previous: Some(Previous {
			selector: "ed10".into(),
			key_file: "dkim-ed10.key".into(),
			retire_at: NOW,
			rsa: None,
		}),
		pending: Some(Pending {
			selector: "ed190".into(),
			key_file: "dkim-ed190.key".into(),
			domains: vec!["example.org".into()],
			started_at: NOW,
			withdrawing: None,
			rsa: None,
		}),
		rsa: None,
	}
}

#[test]
fn only_unnamed_rotated_key_files_are_orphans() {
	let dir = tempfile::tempdir().expect("dir");
	for name in [
		"dkim-ed100.key",
		"dkim-ed10.key",
		"dkim-ed190.key",
		"dkim-ed5.key",
		"dkim-ed77.key",
		"dkim-s1.key",
		"dkim-ed.key",
		"dkim-ed5.key.bak",
		"ed6.key",
	] {
		std::fs::write(dir.path().join(name), "x").expect("file");
	}
	let state = state_with_all_three();
	let found = orphan_key_files(dir.path(), Some(&state), &["ed77".into()]);
	assert_eq!(found, vec![dir.path().join("dkim-ed5.key")]);
}

#[test]
fn only_unnamed_rotated_records_of_signing_domains_are_orphans() {
	let records = [
		txt("ed100._domainkey.example.org."),
		txt("ed10._domainkey.example.org"),
		txt("ed190._domainkey.example.org"),
		txt("ED5._domainkey.Example.org."),
		txt("ed6._domainkey.other.example"),
		txt("s1._domainkey.example.org"),
		txt("ed77._domainkey.example.org"),
		DnsRecord {
			kind: RecordKind::Cname,
			proxied: None,
			..txt("ed8._domainkey.example.org")
		},
	];
	let state = state_with_all_three();
	let domains = vec!["example.org".to_string()];
	assert_eq!(
		orphan_records(&records, &domains, Some(&state), &["ed77".into()]),
		vec!["ed5._domainkey.example.org".to_string()]
	);
}

#[tokio::test]
async fn orphans_are_removed_only_on_request_and_named_ones_stay() {
	let lab = Lab::new(Start::RetireDue);
	lab.install_key("ed5", "dkim-ed5.key");
	let (signer, rotator) = lab.start(Visibility::AfterOneWait);
	let rotator = rotator.keeping(vec!["configured".into()]);

	let found = find_orphans(
		&lab.root,
		Some(lab.zone.as_ref()),
		"example.org",
		&DOMAINS.map(String::from),
		&[],
	)
	.await
	.expect("orphans");
	assert_eq!(found.key_files, vec![lab.root.join("dkim-ed5.key")]);
	assert_eq!(
		found.records,
		DOMAINS
			.iter()
			.map(|d| format!("ed5._domainkey.{d}"))
			.collect::<Vec<_>>()
	);

	rotator.report_orphans().await;
	assert!(!rotator.serve_cleanup().await.expect("no request"));
	assert!(
		lab.root.join("dkim-ed5.key").exists(),
		"never removed unasked"
	);

	request_cleanup(&lab.root).expect("request");
	assert!(rotator.serve_cleanup().await.expect("cleanup"));
	assert!(
		!lab.root.join(CLEANUP_FILE).exists(),
		"the request is consumed"
	);
	assert!(!lab.root.join("dkim-ed5.key").exists());
	let names: Vec<String> = lab.zone.records.lock().unwrap().keys().cloned().collect();
	assert!(!names.iter().any(|n| n.starts_with("ed5.")), "{names:?}");
	// The active and the previous selector keep their keys and records.
	lab.assert_settled(&signer, "ed100", Some("ed0")).await;
}

#[tokio::test]
async fn an_unreadable_state_finds_nothing_to_remove() {
	let lab = Lab::new(Start::RotationDue);
	lab.install_key("ed5", "dkim-ed5.key");
	std::fs::write(lab.root.join(STATE_FILE), "{").expect("tear");
	let rotator = Rotator::new(
		lab.root.clone(),
		ReloadableSigner::new(Arc::new(
			Signer::load("ed0", &lab.root.join("ed0.key")).expect("key"),
		)),
		lab.zone.clone(),
		"example.org".into(),
		DOMAINS.map(String::from).to_vec(),
		30 * 86_400,
		86_400,
	);
	request_cleanup(&lab.root).expect("request");
	let error = rotator.serve_cleanup().await.expect_err("refused");
	assert!(error.to_string().contains(STATE_FILE), "{error}");
	assert!(lab.root.join("dkim-ed5.key").exists());
	assert!(
		!lab.root.join(CLEANUP_FILE).exists(),
		"a refused request does not come back every minute"
	);
}

/// A state naming an RSA key in each of its three places.
fn dual_state() -> RotationState {
	let mut state = state_with_all_three();
	state.rsa = Some(RsaKey {
		selector: "rsa100".into(),
		key_file: "dkim-rsa100.key".into(),
	});
	state.previous.as_mut().expect("previous").rsa = Some(RsaKey {
		selector: "rsa10".into(),
		key_file: "dkim-rsa10.key".into(),
	});
	state.pending.as_mut().expect("pending").rsa = Some(RsaKey {
		selector: "rsa190".into(),
		key_file: "dkim-rsa190.key".into(),
	});
	state
}

#[test]
fn unnamed_rotated_rsa_keys_and_records_are_orphans_too() {
	let dir = tempfile::tempdir().expect("dir");
	for name in [
		"dkim-rsa100.key",
		"dkim-rsa10.key",
		"dkim-rsa190.key",
		"dkim-rsa5.key",
		"dkim-rsa77.key",
		"dkim-rsa.key",
		"dkim-rsaX1.key",
	] {
		std::fs::write(dir.path().join(name), "key").expect("write");
	}
	let state = dual_state();
	assert_eq!(
		orphan_key_files(dir.path(), Some(&state), &["rsa77".into()]),
		vec![dir.path().join("dkim-rsa5.key")]
	);
	let records = [
		txt("rsa100._domainkey.example.org"),
		txt("rsa10._domainkey.example.org"),
		txt("rsa190._domainkey.example.org"),
		txt("rsa5._domainkey.example.org."),
		txt("rsa77._domainkey.example.org"),
		txt("rsa-configured._domainkey.example.org"),
	];
	assert_eq!(
		orphan_records(
			&records,
			&["example.org".to_string()],
			Some(&state),
			&["rsa77".into()]
		),
		vec!["rsa5._domainkey.example.org".to_string()]
	);
}
