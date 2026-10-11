//! Envelope-domain signing through the outbound spool before and after rotation.

use super::*;
use std::pin::Pin;

use crate::dkim::rotate::Decision;
use crate::dkim::test_support::{KeyDns, signature_fields};
use crate::dkim::{ReloadableSigner, Rotator, Signer};
use crate::dns::provider::{DnsProvider, DnsRecord, ProviderError};

struct NoNetworkDns;
type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

impl DnsProvider for NoNetworkDns {
	fn upsert(&self, _zone: &str, _record: DnsRecord) -> Op<'_> {
		Box::pin(async { Ok(()) })
	}

	fn delete(&self, _zone: &str, _record: DnsRecord) -> Op<'_> {
		Box::pin(async { Ok(()) })
	}

	fn list(&self, _zone: &str) -> ListOp<'_> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

async fn check_delivery(rotate: bool) {
	let dir = tempfile::tempdir_in(".").expect("tempdir");
	let root = dir.path().canonicalize().expect("absolute data dir");
	let (pem, _) = crate::dkim::generate_key().expect("key");
	let key_file = root.join("original.key");
	std::fs::write(&key_file, pem).expect("write key");
	let signer =
		ReloadableSigner::new(Arc::new(Signer::load("original", &key_file).expect("load")));
	let domains = ["example.org", "other.example.net"];
	let directory = DirectoryHandle::new(crate::smtp::directory::Directory::new(
		domains.map(str::to_string),
		std::iter::empty::<(String, String)>(),
	));
	let split = SplitDelivery::new(&root, directory)
		.expect("sink")
		.with_signer(signer.clone());
	let expected_selector = if rotate {
		let rotator = Rotator::new(
			root.clone(),
			signer.clone(),
			Arc::new(NoNetworkDns),
			"example.org".into(),
			"example.org".into(),
			90 * 86_400,
			14 * 86_400,
		);
		assert_eq!(
			rotator.tick(100 * 86_400).await.expect("rotate"),
			Decision::Rotate
		);
		"ed100"
	} else {
		"original"
	};
	let spool = FsSpool::open(&root).expect("spool");
	for domain in domains {
		split
			.deliver(AcceptedMessage {
				reverse_path: format!("alice@{domain}"),
				recipients: vec!["bob@elsewhere.net".into()],
				data: format!("From: alice@{domain}\r\nSubject: domain\r\n\r\nHello\r\n")
					.into_bytes(),
				require_tls: false,
				mailbox: None,
				tlsrpt_verified: false,
				no_dsn: Vec::new(),
			})
			.expect("deliver");
		let ids = spool.list().expect("spool ids");
		let entry = spool
			.load(*ids.last().expect("queued message"))
			.expect("queued bytes");
		assert_eq!(
			signature_fields(&entry.data),
			vec![(
				expected_selector.into(),
				domain.into(),
				"ed25519-sha256".into()
			)],
			"delivery must use the envelope sender domain even outside the DNS zone"
		);
		// Supply the key under this message's domain to isolate signature behavior
		// from the rotator's separate DNS publication policy.
		let dns = KeyDns(std::collections::HashMap::from([(
			format!("{expected_selector}._domainkey.{domain}"),
			vec![signer.current().dns_record_value()],
		)]));
		let results = crate::dkim::verify_message(&dns, &entry.data).await;
		assert_eq!(results.len(), 1, "queued mail carries one signature");
		assert_eq!(
			results[0].outcome,
			crate::dkim::DkimOutcome::Pass,
			"queued signature must verify with the active public key"
		);
	}
}

#[tokio::test]
async fn relayed_mail_uses_sender_domain_without_rotation() {
	check_delivery(false).await;
}

#[tokio::test]
async fn rotated_mail_uses_sender_domain_outside_dns_zone() {
	check_delivery(true).await;
}
