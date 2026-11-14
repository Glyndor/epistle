/// The longest type token [`RecordKind::from_token`] keeps.
pub const MAX_OTHER_KIND_LEN: usize = 32;

/// The token of an [`RecordKind::Other`] whose type a provider returned in
/// a shape no record type has (empty, too long, or with other characters
/// than letters, digits and hyphens).
pub const UNKNOWN_KIND: &str = "UNKNOWN";

/// A DNS record kind. The first eight are what epistle publishes. `Ns`,
/// `Https` and `Svcb` are read back from a zone so a listing keeps them as
/// what they are: an `NS` rrset at a name below the apex is a delegation,
/// and the lockdown must not write anything under it. Every other type a
/// provider returns is kept as [`RecordKind::Other`] with its type token,
/// so a listing never turns a record it does not know into a TXT.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RecordKind {
	/// IPv4 address record.
	#[serde(rename = "A")]
	A,
	/// IPv6 address record.
	#[serde(rename = "AAAA")]
	Aaaa,
	/// Text record. Used for SPF, DMARC, DKIM keys, MTA-STS, TLSRPT, and
	/// ACME DNS-01 challenges.
	#[serde(rename = "TXT")]
	Txt,
	/// Mail exchange record.
	#[serde(rename = "MX")]
	Mx,
	/// Canonical name (alias) record.
	#[serde(rename = "CNAME")]
	Cname,
	/// TLSA association record (RFC 6698) for DANE.
	#[serde(rename = "TLSA")]
	Tlsa,
	/// Service locator record (RFC 2782).
	#[serde(rename = "SRV")]
	Srv,
	/// Certification Authority Authorization (RFC 8659).
	#[serde(rename = "CAA")]
	Caa,
	/// Name server record. Marks a delegation: any name (other than the
	/// zone apex) that carries NS records is delegated to other
	/// nameservers, and `epistle dns lockdown` must not try to publish
	/// anything under it.
	#[serde(rename = "NS")]
	Ns,
	/// HTTPS RR (RFC 9460): alias for `SVCB` plus a `svcparams` hint,
	/// used at the apex or a service name.
	#[serde(rename = "HTTPS")]
	Https,
	/// Service binding record (RFC 9460).
	#[serde(rename = "SVCB")]
	Svcb,
	/// Any other record type a provider listed (`NAPTR`, `SSHFP`, `LOC`,
	/// ...), with its type token. Build it with [`RecordKind::from_token`], which
	/// bounds the token. Providers refuse to publish or delete it.
	#[serde(rename = "OTHER")]
	Other(String),
}

impl RecordKind {
	/// The kind for a record type token a provider API returned, in any
	/// letter case. Every provider reads its listing through this, so a
	/// type epistle does not publish keeps what it is instead of turning
	/// into a TXT: `NS` is [`RecordKind::Ns`] (a delegation), and a type
	/// with no variant is [`RecordKind::Other`].
	///
	/// The token comes from a remote API, so an `Other` keeps it only when
	/// it can be a record type (ASCII letters, digits and hyphens, at most
	/// [`MAX_OTHER_KIND_LEN`] characters, upper-cased). Anything else
	/// becomes [`UNKNOWN_KIND`], so a hostile token never reaches a
	/// terminal, a log line or a JSON document.
	pub fn from_token(token: &str) -> RecordKind {
		let shaped = !token.is_empty()
			&& token.len() <= MAX_OTHER_KIND_LEN
			&& token
				.bytes()
				.all(|b| b.is_ascii_alphanumeric() || b == b'-');
		if !shaped {
			return RecordKind::Other(UNKNOWN_KIND.to_string());
		}
		let upper = token.to_ascii_uppercase();
		match upper.as_str() {
			"A" => RecordKind::A,
			"AAAA" => RecordKind::Aaaa,
			"TXT" => RecordKind::Txt,
			"MX" => RecordKind::Mx,
			"CNAME" => RecordKind::Cname,
			"TLSA" => RecordKind::Tlsa,
			"SRV" => RecordKind::Srv,
			"CAA" => RecordKind::Caa,
			"NS" => RecordKind::Ns,
			"HTTPS" => RecordKind::Https,
			"SVCB" => RecordKind::Svcb,
			_ => RecordKind::Other(upper),
		}
	}

	/// The record type token used in zone files and provider APIs.
	pub fn as_str(&self) -> &str {
		match self {
			RecordKind::A => "A",
			RecordKind::Aaaa => "AAAA",
			RecordKind::Txt => "TXT",
			RecordKind::Mx => "MX",
			RecordKind::Cname => "CNAME",
			RecordKind::Tlsa => "TLSA",
			RecordKind::Srv => "SRV",
			RecordKind::Caa => "CAA",
			RecordKind::Ns => "NS",
			RecordKind::Https => "HTTPS",
			RecordKind::Svcb => "SVCB",
			RecordKind::Other(name) => name.as_str(),
		}
	}
}
