//! Minimal SMTP client for outbound delivery.
//!
//! Speaks just enough ESMTP to hand a message to a remote server: EHLO,
//! opportunistic STARTTLS, MAIL, RCPT, DATA. Strict about replies; any
//! unexpected code aborts the attempt.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::client::danger::{
	HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

use crate::config::OutboundTls;
use crate::dane::policy::DaneOutcome;
use crate::dane::rrset::TlsaRrset;
use crate::dane::verify::verify_chain;

use super::timeouts::Phase;
use super::tls_outcome::{
	STARTTLS_NOT_SUPPORTED, TLSA_INVALID, TlsOutcome, VALIDATION_FAILURE, classify_handshake,
};

#[path = "client_conn.rs"]
mod conn;
#[cfg(test)]
use conn::complete_reply;
use conn::{Conn, Stream};

/// Whether the attempt may be retried later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryError {
	/// 4xx or connection trouble: retry later.
	Transient(String),
	/// 5xx: the remote refused permanently.
	Permanent(String),
}

impl DeliveryError {
	/// The error for a reply that was not the one expected. `raw` is the
	/// whole reply as received; the reason keeps it as one line. Whether it
	/// is worth retrying follows the reply's enhanced status when it has one
	/// (a 552 5.2.2 full mailbox is retried), else its basic code.
	fn from_reply(code: u16, raw: &str) -> Self {
		let reason = super::reply::normalize(code, raw);
		let text = reason.get(4..).unwrap_or_default();
		if code >= 500 && super::reply::classify(code, text).permanent {
			DeliveryError::Permanent(reason)
		} else {
			DeliveryError::Transient(reason)
		}
	}
}

/// One outbound delivery attempt over an established stream.
///
/// `server_name` is the MX hostname used for TLS verification when the remote
/// offers STARTTLS. `tlsa` is the classified TLSA RRset of this MX: any secure
/// RRset, usable or not, makes STARTTLS mandatory (RFC 7672 section 2.2), and
/// usable records authenticate the presented certificate. Without TLSA and
/// without a mandate, TLS is opportunistic: a remote without STARTTLS still
/// gets the mail. Fail closed: a TLSA mismatch, or mandatory STARTTLS the
/// remote does not offer, returns a transient error so the message is
/// retried, never sent in the clear.
///
/// How the STARTTLS certificate is authenticated:
/// * usable TLSA records: accept-any handshake, then `verify_chain`
///   authenticates the chain against them (DANE-EE certificates are commonly
///   self-signed, so PKIX must not run first). This holds under MTA-STS
///   enforce and REQUIRETLS too.
/// * otherwise `require_tls` (MTA-STS enforce / REQUIRETLS): strict PKIX
///   (webpki + hostname).
/// * otherwise `mode` decides: [`OutboundTls::Strict`] (the default) uses
///   strict PKIX, [`OutboundTls::Opportunistic`] completes the handshake with
///   any certificate (encryption without authentication, the SMTP norm).
///
/// `tls` receives how the TLS part ended (for TLS-RPT), once the attempt gets
/// as far as the STARTTLS decision; it stays `None` before that.
///
/// This is the all-or-nothing form: any recipient the remote refuses fails
/// the call. The queue uses [`deliver_each`], which keeps one answer per
/// recipient.
#[allow(clippy::too_many_arguments)]
pub async fn deliver<S>(
	stream: S,
	server_name: &str,
	ehlo_hostname: &str,
	reverse_path: &str,
	recipients: &[String],
	data: &[u8],
	require_tls: bool,
	auth: Option<(&str, &str)>,
	tlsa: &TlsaRrset,
	mode: OutboundTls,
	tls: &mut Option<TlsOutcome>,
) -> Result<(), DeliveryError>
where
	S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
	let mut trace = Trace::default();
	let results = deliver_each(
		stream,
		server_name,
		ehlo_hostname,
		reverse_path,
		recipients,
		data,
		require_tls,
		auth,
		tlsa,
		mode,
		&mut trace,
	)
	.await;
	*tls = trace.tls;
	let results = results?;
	match results.into_iter().find_map(|(_, result)| result.err()) {
		Some(error) => Err(error),
		None => Ok(()),
	}
}

/// What a conversation showed besides the answer for each recipient.
#[derive(Debug, Default)]
pub struct Trace {
	/// How the TLS part ended (for TLS-RPT), once the conversation got as
	/// far as the STARTTLS decision.
	pub tls: Option<TlsOutcome>,
	/// Whether the session was set up and the mail transaction begun (MAIL
	/// was sent). A failure before that is about this exchanger, not the
	/// message, and the next exchanger may do better (RFC 5321 section 5.1).
	pub transaction: bool,
	/// Set as soon as the whole message, final dot included, is written:
	/// from then on the remote may have accepted it, and giving up on its
	/// reply would send it again on the next attempt (RFC 5321 section
	/// 4.5.3.2.6). Shared so the caller can see it while the reply is
	/// awaited.
	pub sent: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// The remote's answer for one recipient of a conversation.
pub type RecipientResult = (String, Result<(), DeliveryError>);

/// One outbound conversation with an answer per recipient (RFC 5321 §3.3).
///
/// Every recipient gets its own `RCPT TO`, and a refusal applies to that
/// recipient alone. DATA is sent when at least one recipient was accepted,
/// and its outcome applies to the accepted ones. `Err` means the
/// conversation broke before any recipient had an answer of its own (the
/// connection, the greeting, EHLO, STARTTLS, AUTH, `MAIL FROM`, or the
/// connection dropping mid-`RCPT`); it applies to every recipient. `trace`
/// receives the TLS outcome and how far the session got; the other
/// arguments are those of [`deliver`].
#[allow(clippy::too_many_arguments)]
pub async fn deliver_each<S>(
	stream: S,
	server_name: &str,
	ehlo_hostname: &str,
	reverse_path: &str,
	recipients: &[String],
	data: &[u8],
	require_tls: bool,
	auth: Option<(&str, &str)>,
	tlsa: &TlsaRrset,
	mode: OutboundTls,
	trace: &mut Trace,
) -> Result<Vec<RecipientResult>, DeliveryError>
where
	S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
	// Any secure TLSA RRset makes TLS mandatory, even when none of its
	// records can authenticate the server (RFC 7672 section 2.2).
	let tls_mandatory = require_tls || *tlsa != TlsaRrset::Absent;
	let tlsa = tlsa.records();
	let mut conn = Conn::new(Box::new(stream));
	conn.expect(220, Phase::Greeting).await?;

	conn.command(&format!("EHLO {ehlo_hostname}"), 250, Phase::Command)
		.await?;
	let offers_starttls = conn.last_reply_contains("STARTTLS");
	if !offers_starttls {
		trace.tls = Some(TlsOutcome::Failure(STARTTLS_NOT_SUPPORTED));
	}
	// DANE presence makes STARTTLS mandatory (RFC 7672 §2.2): never downgrade.
	if tls_mandatory && !offers_starttls {
		return Err(DeliveryError::Transient(
			"TLS required (MTA-STS/DANE) but remote offers no STARTTLS".into(),
		));
	}

	let mut tls_active = false;
	if offers_starttls {
		if let Err(error) = conn.command("STARTTLS", 220, Phase::Command).await {
			trace.tls = Some(TlsOutcome::Failure(STARTTLS_NOT_SUPPORTED));
			return Err(error);
		}
		let inner = conn.into_inner();
		// Authenticate the certificate via PKIX (webpki + hostname) unless usable
		// TLSA records do it (DANE, below), when TLS is mandated or strict mode
		// is set; a DANE-EE leaf is normally self-signed.
		let authenticate_pkix = pkix_required(require_tls, !tlsa.is_empty(), mode);
		let (stream, peer_chain) = tls_connect(inner, server_name, authenticate_pkix)
			.await
			.map_err(|(error, result_type)| {
				trace.tls = Some(TlsOutcome::Failure(result_type));
				error
			})?;
		// DANE: authenticate the presented chain against validated TLSA records.
		// With none, this is a no-op (opportunistic); a mismatch fails closed.
		match verify_chain(tlsa, &peer_chain) {
			DaneOutcome::Authenticated | DaneOutcome::NoRecords => {}
			DaneOutcome::Mismatch => {
				trace.tls = Some(TlsOutcome::Failure(TLSA_INVALID));
				return Err(DeliveryError::Transient(format!(
					"DANE: no TLSA record matches the certificate of {server_name}"
				)));
			}
		}
		trace.tls = Some(TlsOutcome::Success);
		conn = Conn::new(Box::new(stream));
		conn.command(&format!("EHLO {ehlo_hostname}"), 250, Phase::Command)
			.await?;
		tls_active = true;
	}

	// Relay (submission) AUTH: only over TLS, never in plaintext (fail closed).
	if let Some((username, password)) = auth {
		if !tls_active {
			return Err(DeliveryError::Permanent(
				"relay AUTH requested but smarthost offered no STARTTLS".into(),
			));
		}
		use base64::Engine;
		let token =
			base64::engine::general_purpose::STANDARD.encode(format!("\0{username}\0{password}"));
		conn.command(&format!("AUTH PLAIN {token}"), 235, Phase::Command)
			.await?;
	}

	trace.transaction = true;
	conn.command(&format!("MAIL FROM:<{reverse_path}>"), 250, Phase::Command)
		.await?;
	let mut results = Vec::with_capacity(recipients.len());
	// Once the remote says the transaction has too many recipients, the
	// rest are not offered: they wait for a transaction of their own.
	let mut full: Option<DeliveryError> = None;
	for recipient in recipients {
		if let Some(error) = &full {
			results.push((recipient.clone(), Err(error.clone())));
			continue;
		}
		conn.send(&format!("RCPT TO:<{recipient}>"), Phase::Rcpt)
			.await?;
		// A reply refuses this recipient only; a broken connection (no
		// reply at all) is the `?` and leaves every recipient unanswered.
		let (code, text) = conn.reply(Phase::Rcpt).await?;
		let outcome = match code / 100 {
			2 => Ok(()),
			_ => Err(DeliveryError::from_reply(code, &text)),
		};
		if let Err(DeliveryError::Transient(reason)) = &outcome
			&& super::backoff::too_many_recipients(reason)
		{
			full = outcome.clone().err();
		}
		results.push((recipient.clone(), outcome));
	}
	if results.iter().any(|(_, outcome)| outcome.is_ok()) {
		let message_sent = std::sync::Arc::clone(&trace.sent);
		let sent = async {
			conn.command("DATA", 354, Phase::DataInit).await?;
			conn.send_data(data).await?;
			message_sent.store(true, std::sync::atomic::Ordering::SeqCst);
			conn.expect(250, Phase::DataEnd).await
		}
		.await;
		if let Err(error) = sent {
			for (_, outcome) in results.iter_mut().filter(|(_, outcome)| outcome.is_ok()) {
				*outcome = Err(error.clone());
			}
		}
	}
	// After a timeout or a failed read or write, the session is in no state
	// for QUIT: just close it.
	if !conn.is_broken() {
		let _ = conn.command("QUIT", 221, Phase::Quit).await;
	}
	Ok(results)
}

/// Whether the STARTTLS certificate must pass PKIX (webpki roots and the
/// MX name). Usable TLSA records authenticate the server instead: DANE
/// takes precedence over MTA-STS (RFC 8461 section 2) and satisfies
/// REQUIRETLS (RFC 8689 section 4.2.1), and a DANE-EE certificate is
/// usually self-signed, so PKIX must not run in front of it. Without
/// them, a mandate (MTA-STS enforce, REQUIRETLS) or strict mode requires
/// PKIX.
fn pkix_required(require_tls: bool, dane_records: bool, mode: OutboundTls) -> bool {
	!dane_records && (require_tls || mode == OutboundTls::Strict)
}

/// Complete a STARTTLS handshake, returning the encrypted stream and the DER
/// certificate chain the peer presented (leaf first), for DANE authentication.
///
/// With `authenticate` set, the certificate is strictly verified against the
/// webpki roots and must match `server_name` (PKIX). Otherwise the handshake
/// accepts any certificate (encryption only): the caller authenticates the
/// returned chain by another means (DANE via `verify_chain`) or accepts
/// unauthenticated TLS (opportunistic mode). The peer chain is captured in both
/// cases so DANE can run on it. A failure carries its RFC 8460 result type.
async fn tls_connect(
	stream: Box<dyn Stream>,
	server_name: &str,
	authenticate: bool,
) -> Result<
	(
		tokio_rustls::client::TlsStream<Box<dyn Stream>>,
		Vec<Vec<u8>>,
	),
	(DeliveryError, &'static str),
> {
	crate::tls::ensure_crypto_provider();
	let config = if authenticate {
		let mut roots = RootCertStore::empty();
		roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
		#[cfg(test)]
		TEST_ROOTS.with(|extra| {
			for root in extra.borrow().iter() {
				let _ = roots.add(root.clone());
			}
		});
		ClientConfig::builder()
			.with_root_certificates(roots)
			.with_no_client_auth()
	} else {
		ClientConfig::builder()
			.dangerous()
			.with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert::new()))
			.with_no_client_auth()
	};
	let name = ServerName::try_from(server_name.to_string()).map_err(|_| {
		(
			DeliveryError::Transient(format!("invalid TLS name {server_name}")),
			"validation-failure",
		)
	})?;
	let handshake = TlsConnector::from(Arc::new(config)).connect(name, stream);
	let tls = match tokio::time::timeout(Phase::TlsHandshake.limit(), handshake).await {
		Ok(Ok(tls)) => tls,
		Ok(Err(error)) => {
			return Err((
				DeliveryError::Transient(format!("TLS handshake failed: {error}")),
				classify_handshake(&error),
			));
		}
		Err(_) => return Err((Phase::TlsHandshake.timed_out(), VALIDATION_FAILURE)),
	};
	let peer_chain = tls
		.get_ref()
		.1
		.peer_certificates()
		.map(|certs| certs.iter().map(|cert| cert.as_ref().to_vec()).collect())
		.unwrap_or_default();
	Ok((tls, peer_chain))
}

#[cfg(test)]
thread_local! {
	/// Trust anchors added to the webpki roots for PKIX in tests on this
	/// thread: no test certificate chains to a public root.
	pub(crate) static TEST_ROOTS: std::cell::RefCell<Vec<CertificateDer<'static>>> =
		const { std::cell::RefCell::new(Vec::new()) };
}

/// A `rustls` certificate verifier that accepts ANY server certificate without
/// PKIX validation, used only when authentication is intentionally not done via
/// PKIX: opportunistic mode (encryption without authentication) or DANE (the
/// chain is authenticated afterwards against TLSA records). It is NEVER used when
/// TLS is mandated (`require_tls`).
///
/// The handshake signatures are still verified — against the presented
/// certificate's own key, using the process crypto provider's algorithms — so
/// the peer must hold the private key for the certificate it offers; only the
/// trust-anchor/hostname checks are skipped. `supported_verify_schemes` is taken
/// verbatim from the provider so the offered schemes match what we can verify.
#[derive(Debug)]
struct AcceptAnyServerCert {
	provider: Arc<tokio_rustls::rustls::crypto::CryptoProvider>,
}

impl AcceptAnyServerCert {
	fn new() -> Self {
		let provider = tokio_rustls::rustls::crypto::CryptoProvider::get_default()
			.cloned()
			.unwrap_or_else(|| Arc::new(tokio_rustls::rustls::crypto::ring::default_provider()));
		AcceptAnyServerCert { provider }
	}
}

impl ServerCertVerifier for AcceptAnyServerCert {
	fn verify_server_cert(
		&self,
		_end_entity: &CertificateDer<'_>,
		_intermediates: &[CertificateDer<'_>],
		_server_name: &ServerName<'_>,
		_ocsp_response: &[u8],
		_now: UnixTime,
	) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
		Ok(ServerCertVerified::assertion())
	}

	fn verify_tls12_signature(
		&self,
		message: &[u8],
		cert: &CertificateDer<'_>,
		dss: &DigitallySignedStruct,
	) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
		tokio_rustls::rustls::crypto::verify_tls12_signature(
			message,
			cert,
			dss,
			&self.provider.signature_verification_algorithms,
		)
	}

	fn verify_tls13_signature(
		&self,
		message: &[u8],
		cert: &CertificateDer<'_>,
		dss: &DigitallySignedStruct,
	) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
		tokio_rustls::rustls::crypto::verify_tls13_signature(
			message,
			cert,
			dss,
			&self.provider.signature_verification_algorithms,
		)
	}

	fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
		self.provider
			.signature_verification_algorithms
			.supported_schemes()
	}
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "client_tls_tests.rs"]
mod tls_tests;

#[cfg(test)]
#[path = "client_timeout_tests.rs"]
mod timeout_tests;

#[path = "client_probe.rs"]
mod probe;
pub use probe::probe;
