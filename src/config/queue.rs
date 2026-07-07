//! Outbound queue configuration: the `[queue]` section.
//!
//! Currently a single knob, `outbound_tls`, selecting how the STARTTLS
//! certificate of a recipient MX is authenticated. The default is the most
//! restrictive option (strict PKIX verification), so an absent `[queue]`
//! section leaves existing deployments unchanged (fail closed).

use serde::Deserialize;

/// How outbound STARTTLS authenticates the recipient MX certificate when TLS is
/// neither mandated (MTA-STS enforce / REQUIRETLS) nor authenticated by DANE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutboundTls {
	/// Strict PKIX: the certificate must chain to a webpki trust anchor and
	/// match the MX hostname, exactly like a browser (the default). A remote
	/// with a self-signed or expired certificate and no DANE/MTA-STS is
	/// deferred rather than sent in the clear.
	#[default]
	Strict,
	/// Opportunistic: complete the handshake with any certificate (encryption
	/// without authentication). This is the historical SMTP norm — it stops
	/// passive eavesdropping but not an active man-in-the-middle — and is opt
	/// in. MTA-STS enforce, REQUIRETLS and DANE still authenticate regardless.
	Opportunistic,
}

/// The `[queue]` configuration section.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Queue {
	/// Outbound STARTTLS authentication mode for unmandated, non-DANE delivery.
	/// Defaults to [`OutboundTls::Strict`].
	#[serde(default)]
	pub outbound_tls: OutboundTls,
}
