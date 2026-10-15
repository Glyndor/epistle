//! The warning header goes on top of the message, so a DKIM signature the
//! sender made still verifies after the server flags it: a header that is
//! added is not covered unless a signer listed its name in `h=`, and the
//! signer the server itself uses lists only From, To, Cc, Subject, Date
//! and Message-ID.

use super::*;
use crate::antispam::attachments::corpus;
use crate::config::{AttachmentMode, Attachments};
use crate::dkim::{DkimOutcome, Signer, generate_key, verify_message};
use std::future::Future;
use std::pin::Pin;

use crate::spf::{DnsFailure, DnsLookup};

type Lookup<'a, T> = Pin<Box<dyn Future<Output = Result<T, DnsFailure>> + Send + 'a>>;

struct KeyDns(String);

impl DnsLookup for KeyDns {
	fn txt(&self, name: &str) -> Lookup<'_, Vec<String>> {
		let found = (name == "s1._domainkey.example.net").then(|| self.0.clone());
		Box::pin(async move { Ok(found.into_iter().collect()) })
	}

	fn addresses(&self, _name: &str) -> Lookup<'_, Vec<std::net::IpAddr>> {
		Box::pin(async { Ok(Vec::new()) })
	}

	fn mx(&self, _name: &str) -> Lookup<'_, Vec<String>> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

#[tokio::test]
async fn a_flagged_message_keeps_its_dkim_signature() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (pem, record) = generate_key().expect("key");
	let key = dir.path().join("key.pem");
	std::fs::write(&key, pem).expect("write key");
	let signer = Signer::load("s1", &key).expect("signer");
	let message = corpus::message(&[corpus::attachment(
		"Content-Type: image/jpeg; name=holiday.jpg",
		&corpus::pe(),
	)]);
	let message = String::from_utf8(message)
		.expect("ascii")
		.replacen("From: a@example.org", "From: a@example.net", 1)
		.into_bytes();
	let mut signed = signer
		.sign("example.net", &message)
		.expect("signature")
		.into_bytes();
	signed.extend_from_slice(&message);
	let dns = KeyDns(record);
	assert_eq!(
		verify_message(&dns, &signed).await[0].outcome,
		DkimOutcome::Pass,
		"the fixture verifies"
	);
	let section = Attachments {
		mode: AttachmentMode::Flag,
		..Attachments::default()
	};
	let policy = Policy::from_config(&section, 1 << 20).expect("on");
	let (_, decision) = policy.check(&signed);
	assert_eq!(decision.action, Action::Flag);
	let mut flagged = signed.clone();
	decision.stamp(&mut flagged);
	assert!(flagged.starts_with(WARNING_HEADER.as_bytes()));
	assert_eq!(
		verify_message(&dns, &flagged).await[0].outcome,
		DkimOutcome::Pass,
		"the header on top does not break the signature"
	);
}
