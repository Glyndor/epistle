//! `TLS-Required: No` (RFC 8689 section 3): a message that carries it is
//! delivered even where MTA-STS or DANE would refuse an unverified
//! connection, still over STARTTLS when the MX offers it. REQUIRETLS on
//! the same message wins (section 4.1: the header is then ignored), and a
//! message with the field twice is not honoured (section 3 allows one).

use super::tests_policy_matrix::{Mx, MxDns, Seen, Sts, Tlsa, attempt_cell};
use crate::config::OutboundTls;
use crate::smtp::session::AcceptedMessage;

fn message(headers: &str, require_tls: bool) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "alice@sender.example".into(),
		recipients: vec!["bob@remote.example".to_string()],
		data: format!("{headers}From: alice@sender.example\r\nSubject: hi\r\n\r\nbody\r\n")
			.into_bytes(),
		require_tls,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: false,
		no_dsn: Vec::new(),
	}
}

const OPTIONAL: &str = "TLS-Required: No\r\n";

#[tokio::test]
async fn an_enforced_mta_sts_policy_gives_way_to_tls_required_no() {
	let bad_cert = (
		Sts::Enforce,
		Tlsa::Absent,
		Mx::Bad,
		OutboundTls::Strict,
		MxDns::Secure,
	);
	assert_eq!(
		attempt_cell(bad_cert, &message("", false)).await,
		Seen::Deferred
	);
	assert_eq!(
		attempt_cell(bad_cert, &message(OPTIONAL, false)).await,
		Seen::DeliveredTls,
		"STARTTLS is still used, with any certificate"
	);
	let plain = (
		Sts::Enforce,
		Tlsa::Absent,
		Mx::Plain,
		OutboundTls::Strict,
		MxDns::Secure,
	);
	assert_eq!(
		attempt_cell(plain, &message("", false)).await,
		Seen::Deferred
	);
	assert_eq!(
		attempt_cell(plain, &message("tls-required:  no \r\n", false)).await,
		Seen::DeliveredPlain
	);
}

#[tokio::test]
async fn dane_gives_way_to_tls_required_no() {
	for tlsa in [Tlsa::Usable, Tlsa::TempFail] {
		let cell = (Sts::None, tlsa, Mx::Bad, OutboundTls::Strict, MxDns::Secure);
		assert_eq!(
			attempt_cell(cell, &message("", false)).await,
			Seen::Deferred,
			"{tlsa:?}"
		);
		assert_eq!(
			attempt_cell(cell, &message(OPTIONAL, false)).await,
			Seen::DeliveredTls,
			"{tlsa:?}"
		);
	}
}

#[tokio::test]
async fn requiretls_on_the_same_message_wins() {
	let plain = (
		Sts::None,
		Tlsa::Absent,
		Mx::Plain,
		OutboundTls::Strict,
		MxDns::Secure,
	);
	assert_eq!(
		attempt_cell(plain, &message("", false)).await,
		Seen::DeliveredPlain
	);
	assert_eq!(
		attempt_cell(plain, &message(OPTIONAL, true)).await,
		Seen::Deferred,
		"REQUIRETLS still needs verified TLS"
	);
	// DANE is how this MX is verified: setting it aside would leave PKIX,
	// which its self-signed certificate fails.
	let dane_only = (
		Sts::None,
		Tlsa::Usable,
		Mx::DaneOnly,
		OutboundTls::Strict,
		MxDns::Secure,
	);
	assert_eq!(
		attempt_cell(dane_only, &message(OPTIONAL, true)).await,
		Seen::DeliveredTls,
		"the header is ignored, DANE still applies"
	);
}

#[tokio::test]
async fn the_field_twice_or_another_value_is_not_honoured() {
	let plain = (
		Sts::Enforce,
		Tlsa::Absent,
		Mx::Plain,
		OutboundTls::Strict,
		MxDns::Secure,
	);
	for headers in [
		"TLS-Required: No\r\nTLS-Required: No\r\n",
		"TLS-Required: Yes\r\n",
	] {
		assert_eq!(
			attempt_cell(plain, &message(headers, false)).await,
			Seen::Deferred,
			"{headers}"
		);
	}
}

#[derive(Clone, Default)]
struct Messages(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Messages {
	fn on_event(
		&self,
		event: &tracing::Event<'_>,
		_ctx: tracing_subscriber::layer::Context<'_, S>,
	) {
		let mut line = String::new();
		event.record(
			&mut |field: &tracing::field::Field, value: &dyn std::fmt::Debug| {
				use std::fmt::Write;
				let _ = write!(&mut line, "{field}={value:?};");
			},
		);
		self.0.lock().expect("messages").push(line);
	}
}

#[tokio::test]
async fn setting_a_policy_aside_is_logged() {
	use tracing_subscriber::layer::SubscriberExt;
	crate::cli::tracing_capture::keep_callsites_live();
	let messages = Messages::default();
	let _guard =
		tracing::subscriber::set_default(tracing_subscriber::registry().with(messages.clone()));
	tracing::callsite::rebuild_interest_cache();
	let cell = (
		Sts::Enforce,
		Tlsa::Usable,
		Mx::Bad,
		OutboundTls::Strict,
		MxDns::Secure,
	);
	assert_eq!(
		attempt_cell(cell, &message(OPTIONAL, false)).await,
		Seen::DeliveredTls
	);
	let lines = messages.0.lock().expect("messages").join("\n");
	assert!(
		lines.contains("not enforcing the MTA-STS policy"),
		"{lines}"
	);
	assert!(lines.contains("not applying DANE"), "{lines}");
}
