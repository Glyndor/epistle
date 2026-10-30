//! What a delivery session reports for the evidence of a delivered
//! recipient: the accepting reply, the TLS version and cipher, and DANE.

use super::tls::{acceptor_and_leaf, mock_mta};
use super::{Trace, deliver_each};
use crate::config::OutboundTls;
use crate::dane::tlsa::TlsaRecord;

async fn deliver_with(tlsa: Vec<TlsaRecord>) -> Trace {
	let (acceptor, _) = acceptor_and_leaf();
	deliver_using(acceptor, tlsa).await
}

async fn deliver_using(acceptor: tokio_rustls::TlsAcceptor, tlsa: Vec<TlsaRecord>) -> Trace {
	let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(mock_mta(acceptor, server_stream));
	let mut trace = Trace::default();
	let results = deliver_each(
		client_stream,
		"mail.example.org",
		"mail.sender.example",
		"alice@sender.example",
		&["bob@example.org".to_string()],
		b"Subject: hi\r\n\r\nbody\r\n",
		false,
		None,
		&if tlsa.is_empty() {
			crate::dane::rrset::TlsaRrset::Absent
		} else {
			crate::dane::rrset::TlsaRrset::Usable(tlsa)
		},
		OutboundTls::Opportunistic,
		&mut trace,
	)
	.await
	.expect("conversation");
	assert!(results.iter().all(|(_, result)| result.is_ok()));
	let _ = task.await;
	trace
}

#[tokio::test]
async fn a_delivery_reports_the_accepting_reply_and_the_tls_session() {
	let trace = deliver_with(Vec::new()).await;
	assert_eq!(trace.facts.reply.as_deref(), Some("250 queued"));
	let (version, cipher) = trace.facts.tls.expect("an encrypted session");
	assert_eq!(version, "TLSv1_3");
	assert!(cipher.starts_with("TLS13_"), "{cipher}");
	assert!(!trace.facts.dane, "no TLSA record, no DANE");
}

#[tokio::test]
async fn a_dane_authenticated_session_says_so() {
	let (acceptor, leaf) = acceptor_and_leaf();
	let digest = ring::digest::digest(&ring::digest::SHA256, &leaf)
		.as_ref()
		.to_vec();
	let record = TlsaRecord::from_parts(3, 0, 1, digest).expect("tlsa");
	let trace = deliver_using(acceptor, vec![record]).await;
	assert!(trace.facts.dane, "DANE authenticated the server");
}
