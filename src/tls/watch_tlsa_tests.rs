//! The TLSA record follows a certificate the operator replaced: published
//! through the `[dns]` provider when there is one, otherwise reported with
//! the value to publish by hand.

use super::*;
use crate::dns::provider::{DnsRecord, ProviderError, RecordKind};
use std::pin::Pin;
use std::sync::Mutex;

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

#[derive(Default)]
struct Recording {
	upserts: Mutex<Vec<DnsRecord>>,
	refuse: bool,
}

impl DnsProvider for Recording {
	fn upsert(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		if self.refuse {
			return Box::pin(async { Err(ProviderError::Remote("refused".into())) });
		}
		self.upserts.lock().unwrap().push(record);
		Box::pin(async { Ok(()) })
	}

	fn delete(&self, _zone: &str, _record: DnsRecord) -> Op<'_> {
		Box::pin(async { Ok(()) })
	}

	fn list(&self, _zone: &str) -> ListOp<'_> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

fn chain() -> (String, String) {
	let certified =
		rcgen::generate_simple_self_signed(vec!["mail.example.org".into()]).expect("certificate");
	let pem = certified.cert.pem();
	let value = crate::dns::records::tlsa_full_cert(&pem).expect("association");
	(pem, value)
}

#[tokio::test]
async fn a_provider_publishes_the_new_association() {
	let (pem, value) = chain();
	let provider = Recording::default();
	let update = republish_tlsa(Some(&provider), "mail.example.org", &pem).await;
	assert!(
		update
			== TlsaUpdate::Published {
				value: value.clone()
			},
		"the record is published"
	);
	let upserts = provider.upserts.lock().unwrap();
	assert_eq!(upserts.len(), 1, "one record");
	assert_eq!(upserts[0].name, "_25._tcp.mail.example.org");
	assert_eq!(upserts[0].kind, RecordKind::Tlsa);
	assert!(
		upserts[0].value == value,
		"the association of the new certificate"
	);
}

#[tokio::test]
async fn a_refused_publication_says_what_to_publish() {
	let (pem, value) = chain();
	let provider = Recording {
		refuse: true,
		..Recording::default()
	};
	match republish_tlsa(Some(&provider), "mail.example.org", &pem).await {
		TlsaUpdate::Failed { value: wanted, .. } => {
			assert!(wanted == value, "the value to publish by hand")
		}
		_ => panic!("a refused upsert is reported as failed"),
	}
}

#[tokio::test]
async fn without_a_provider_the_record_is_left_to_the_operator() {
	let (pem, value) = chain();
	let update = republish_tlsa(None, "mail.example.org", &pem).await;
	assert!(
		update == TlsaUpdate::ByHand { value },
		"the value to publish by hand"
	);
}

#[tokio::test(start_paused = true)]
async fn the_watch_loop_republishes_the_tlsa_of_a_replaced_certificate() {
	let dir = tempfile::tempdir().expect("tempdir");
	let tls = crate::config::Tls {
		cert_file: dir.path().join("cert.pem"),
		key_file: dir.path().join("key.pem"),
		client_ca: None,
	};
	let first =
		rcgen::generate_simple_self_signed(vec!["mail.example.org".into()]).expect("certificate");
	std::fs::write(&tls.cert_file, first.cert.pem()).expect("certificate");
	std::fs::write(&tls.key_file, first.signing_key.serialize_pem()).expect("key");
	let reloadable =
		crate::tls::ReloadableAcceptor::new(crate::tls::acceptor(&tls).expect("acceptor"));
	let watcher = crate::tls::watch::CertWatcher::new(tls.clone(), reloadable);
	let provider = std::sync::Arc::new(Recording::default());
	tokio::spawn(crate::tls::watch::run(
		watcher,
		Some(provider.clone()),
		"mail.example.org".into(),
	));
	tokio::time::sleep(std::time::Duration::from_secs(90)).await;
	assert!(
		provider.upserts.lock().unwrap().is_empty(),
		"an unchanged pair publishes nothing"
	);

	let second =
		rcgen::generate_simple_self_signed(vec!["mail.example.org".into()]).expect("certificate");
	std::fs::write(&tls.cert_file, second.cert.pem()).expect("certificate");
	std::fs::write(&tls.key_file, second.signing_key.serialize_pem()).expect("key");
	let second_value =
		crate::dns::records::tlsa_full_cert(&second.cert.pem()).expect("association");
	tokio::time::sleep(std::time::Duration::from_secs(61)).await;
	let upserts = provider.upserts.lock().unwrap();
	assert_eq!(
		upserts.len(),
		1,
		"the new certificate's record is published once"
	);
	assert!(
		upserts[0].value == second_value,
		"the association of the new certificate"
	);
}
