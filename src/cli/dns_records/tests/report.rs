//! The report `dns-records` prints: one zone file line per record, with the
//! TXT values split into the quoted strings a zone file accepts, and the
//! selector of the DKIM key the rotation state names.

use super::*;
use crate::dns::provider::{DnsRecord, RecordKind};

#[test]
fn report_prints_zone_file_lines() {
	let records = vec![PublishRecord {
		zone: "example.org".to_string(),
		record: DnsRecord {
			name: "_dmarc.example.org".to_string(),
			kind: RecordKind::Txt,
			value: "v=DMARC1; p=none".to_string(),
			ttl: 3600,
			proxied: None,
		},
	}];
	let mut out = Vec::new();
	assert_eq!(report(&records, &mut out), ExitCode::SUCCESS);
	let text = String::from_utf8(out).expect("utf8");
	assert_eq!(
		text,
		"_dmarc.example.org 3600 IN TXT \"v=DMARC1; p=none\"\n"
	);
}

#[test]
fn report_splits_a_long_txt_into_quoted_strings() {
	let records = vec![PublishRecord {
		zone: "example.org".to_string(),
		record: DnsRecord {
			name: "rsasel._domainkey.example.org".to_string(),
			kind: RecordKind::Txt,
			value: "v=DKIM1; k=rsa; p=".to_string() + &"A".repeat(600),
			ttl: 3600,
			proxied: None,
		},
	}];
	let mut out = Vec::new();
	assert_eq!(report(&records, &mut out), ExitCode::SUCCESS);
	let text = String::from_utf8(out).expect("utf8");
	// A 614-byte value splits into 3 strings of ≤255 bytes → 6 quotes.
	let quote_count = text.chars().filter(|c| *c == '"').count();
	assert!(quote_count >= 6, "got {quote_count} quotes in {text}");
}

#[test]
fn dkim_uses_rotation_state_selector_when_present() {
	// After the rotator has run, the operator's printed DKIM records must
	// name the rotated key so the published TXT matches what the receiver
	// looks up. We generate a fresh ed25519 key under the rotated name and
	// write a rotation state pointing at it, then assert the printed record
	// uses the rotated selector and not the configured one.
	let dir = tempfile::tempdir().expect("tempdir");
	let (pem, _record) = crate::dkim::generate_key().expect("ed25519 key");
	let rotated_key = dir.path().join("rotated.key");
	std::fs::write(&rotated_key, &pem).expect("write rotated key");
	let state = crate::dkim::rotate::RotationState {
		selector: "ed-rotated".into(),
		key_file: rotated_key.clone(),
		rotated_at: 31 * 86_400,
		previous: None,
		pending: None,
		rsa: None,
	};
	std::fs::write(
		dir.path().join("dkim-rotation.json"),
		serde_json::to_vec(&state).expect("state JSON"),
	)
	.expect("write state");
	let (orig_pem, _record) = crate::dkim::generate_key().expect("original ed25519 key");
	let orig_key = dir.path().join("original.key");
	std::fs::write(&orig_key, &orig_pem).expect("write original key");
	let toml = format!(
		r#"
hostname = "mail.example.org"
data_dir = "{}"
domains = ["example.org"]

[dkim]
selector = "ed-original"
key_file = "{}"
"#,
		dir.path().display(),
		orig_key.display(),
	);
	let config: Config = toml::from_str(&toml).expect("config");
	let mut out = Vec::new();
	assert_eq!(run(&config, false, &mut out), ExitCode::SUCCESS);
	let text = String::from_utf8_lossy(&out);
	assert!(
		text.contains("ed-rotated._domainkey.example.org"),
		"dns-records must print the rotated selector, not the configured one: {text}"
	);
	assert!(
		!text.contains("ed-original._domainkey.example.org"),
		"dns-records must NOT print the pre-rotation selector once a state file exists: {text}"
	);
}
