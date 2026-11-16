//! What the spool keeps as the reason of a delivery that failed on this
//! side of the conversation, with a real SMTP server and real TLS on the
//! other: an enhanced status and one fixed sentence, retried.

use super::policy_matrix::{Mx, Sts, Tlsa, attempt_reason};
use crate::config::OutboundTls;

async fn reason(sts: Sts, tlsa: Tlsa, mx: Mx, mode: OutboundTls) -> String {
	attempt_reason((sts, tlsa, mx, mode))
		.await
		.expect("a deferred message keeps its reason")
}

#[tokio::test]
async fn a_certificate_nothing_vouches_for_is_a_failed_handshake() {
	assert_eq!(
		reason(Sts::None, Tlsa::Absent, Mx::Bad, OutboundTls::Strict).await,
		"4.7.5 the TLS handshake with mx.remote.example failed"
	);
}

#[tokio::test]
async fn a_certificate_that_matches_no_tlsa_record_is_x_7_5() {
	assert_eq!(
		reason(Sts::None, Tlsa::Usable, Mx::Bad, OutboundTls::Opportunistic).await,
		"4.7.5 the certificate of mx.remote.example matches none of its DANE TLSA records"
	);
}

#[tokio::test]
async fn an_enforce_policy_with_a_server_that_offers_no_tls_is_x_7_10() {
	assert_eq!(
		reason(Sts::Enforce, Tlsa::Absent, Mx::Plain, OutboundTls::Strict).await,
		"4.7.10 TLS is required but mx.remote.example does not offer STARTTLS"
	);
}

#[tokio::test]
async fn a_tlsa_lookup_that_fails_is_x_7_5() {
	assert_eq!(
		reason(Sts::None, Tlsa::TempFail, Mx::Good, OutboundTls::Strict).await,
		"4.7.5 the DANE TLSA records of mx.remote.example could not be looked up, so its TLS cannot be verified"
	);
}
