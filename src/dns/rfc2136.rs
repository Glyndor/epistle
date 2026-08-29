//! An RFC 2136 DNS provider (dynamic update, TSIG-authenticated). epistle sends
//! DNS UPDATE messages (opcode 5) over TCP to the nameserver `host:port`
//! configured in `[dns].endpoint`, authenticated with TSIG (RFC 8945). This is
//! the wire format the protocol prescribes; there is no HTTP API to wrap.
//!
//! Records epistle publishes — A, AAAA, TXT, CNAME, TLSA, MX, SRV and CAA —
//! are each encoded into their own RDATA type. MX and SRV carry the extra
//! fields the wire format demands (preference; priority, weight and port),
//! parsed out of the record value. TXT values are emitted as a single
//! character-string without the surrounding quotes a zone file would use.
//!
//! The UPDATE semantics follow RFC 2136 §2.5: an **upsert** is the pair
//! `delete RRset (name,type)` + `add record` in the update section of one
//! message; that guarantees we never end up with two TXT records at the
//! same name (the classic "two SPF records" foot-gun). A **delete** is a
//! single `delete RRset` (class NONE, TTL 0, empty RDATA), which is
//! idempotent by definition — the server answers NOERROR whether or not
//! the RRset existed.
//!
//! **List is not implemented.** RFC 2136 defines UPDATE, not query;
//! enumerating a zone needs a separate connection and a query per name
//! the provider has no way to know about. The trait's `list` is
//! documented as "lo que epistle gestiona" and the closest API is
//! per-name normal queries, which this provider cannot perform (it only
//! has an UPDATE client, not a full resolver). `list` therefore returns
//! [`ProviderError::Unsupported`].
//!
//! Authentication uses the `token` field as the base64 TSIG key (the
//! secret bytes the server stores); `key_name` is the TSIG key name, and
//! `algorithm` selects the HMAC. We support `hmac-sha256` (default),
//! `hmac-sha384` and `hmac-sha512` — the algorithms for which hickory
//! has working crypto. `hmac-sha1` / `hmac-sha224` / `hmac-md5` are
//! not supported by hickory's TSIG implementation and would fail at
//! sign time.

use std::pin::Pin;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use hickory_resolver::proto::op::{
	Message, MessageType, OpCode, Query, ResponseCode, UpdateMessage,
};
use hickory_resolver::proto::rr::{
	DNSClass, Name, RData, Record, RecordType, TSigner,
	rdata::tlsa::{CertUsage, Matching, Selector},
	rdata::tsig::TsigAlgorithm,
	rdata::{CAA, CNAME, MX, SRV, TLSA, TXT},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::provider::{DnsProvider, DnsRecord, ProviderError, RecordKind, ScopedSecret, parse_srv};

/// Default TSIG fudge (RFC 8945 §5.2 — maximum tolerance between client
/// and server clocks). Five minutes mirrors what most resolvers accept.
const TSIG_FUDGE_SECONDS: u16 = 300;

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

/// An RFC 2136-backed DNS provider. Holds the TSIG credentials and the
/// nameserver `host:port` (set by `with_endpoint` in tests).
pub struct Rfc2136Provider {
	secret: ScopedSecret,
	signer: TSigner,
	endpoint: String,
}

impl Rfc2136Provider {
	/// Build a provider with explicit TSIG parts. The key bytes are
	/// base64-decoded from the secret's token (RFC 8945 §4.1 — keys are
	/// shared as base64 in zone configuration files like BIND).
	///
	/// `algorithm` is one of `hmac-sha256` (default when `None`),
	/// `hmac-sha384`, `hmac-sha512`. Other names fail at build time,
	/// before any network call.
	pub fn new(
		secret: ScopedSecret,
		key_name: &str,
		algorithm: Option<&str>,
		endpoint: &str,
	) -> Result<Self, ProviderError> {
		let key = decode_key(secret.token())?;
		let algorithm = match algorithm.unwrap_or("hmac-sha256") {
			"hmac-sha256" => TsigAlgorithm::HmacSha256,
			"hmac-sha384" => TsigAlgorithm::HmacSha384,
			"hmac-sha512" => TsigAlgorithm::HmacSha512,
			other => {
				return Err(ProviderError::Remote(format!(
					"unsupported TSIG algorithm: {other}"
				)));
			}
		};
		let signer_name = Name::from_ascii(key_name)
			.map_err(|e| ProviderError::Remote(format!("invalid TSIG key name: {e}")))?;
		let signer = TSigner::new(key, algorithm, signer_name, TSIG_FUDGE_SECONDS)
			.map_err(|e| ProviderError::Remote(format!("TSIG init failed: {e}")))?;
		Ok(Rfc2136Provider {
			secret,
			signer,
			endpoint: endpoint.to_string(),
		})
	}

	/// Point the provider at an alternate endpoint (tests). `host:port`.
	pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
		self.endpoint = endpoint.into();
		self
	}

	/// Reject a record whose owner name is outside the secret's zone,
	/// before any network call. Mirrors the check the HTTP providers
	/// perform.
	fn authorize(&self, record: &DnsRecord) -> Result<(), ProviderError> {
		if self.secret.authorizes(&record.name) {
			Ok(())
		} else {
			Err(ProviderError::Auth)
		}
	}

	/// The record kinds this provider can publish. SRV maps directly from the
	/// presentation form to the wire format; MX needs the priority split out
	/// (epistle still packs it into the value).
	fn supported_kind(kind: RecordKind) -> Result<&'static str, ProviderError> {
		match kind {
			RecordKind::A
			| RecordKind::Aaaa
			| RecordKind::Txt
			| RecordKind::Cname
			| RecordKind::Tlsa
			| RecordKind::Srv
			| RecordKind::Mx
			| RecordKind::Caa => Ok(kind.as_str()),
		}
	}

	/// Build a single UPDATE message with one `delete RRset` and one
	/// `add RR` in the update section. The combination replaces the
	/// `(name,type)` set — no risk of duplicate TXT records — and is the
	/// canonical RFC 2136 upsert.
	fn build_update_message(
		zone: &Name,
		name: &Name,
		kind: RecordKind,
		value: &str,
		ttl: u32,
	) -> Result<Message, ProviderError> {
		let rr_type = RecordType::from_str(Self::supported_kind(kind)?)
			.map_err(|e| ProviderError::Remote(format!("unknown record type: {e}")))?;
		let mut message = Message::new(rand_id(), MessageType::Query, OpCode::Update);

		let mut zone_query = Query::query(zone.clone(), RecordType::SOA);
		zone_query.set_query_class(DNSClass::IN);
		message.add_zone(zone_query);

		let mut delete = Record::from_rdata(name.clone(), 0, RData::Update0(rr_type));
		delete.dns_class = DNSClass::NONE;
		message.add_update(delete);

		let rdata = record_rdata(kind, value)?;
		let add = Record::from_rdata(name.clone(), ttl, rdata);
		message.add_update(add);

		Ok(message)
	}

	/// Build a single UPDATE message with one `delete RRset` — the RFC
	/// 2136 idempotent delete: class NONE, TTL 0, empty RDATA. The
	/// server answers NOERROR whether the RRset existed or not.
	fn build_delete_message(
		zone: &Name,
		name: &Name,
		kind: RecordKind,
	) -> Result<Message, ProviderError> {
		let rr_type = RecordType::from_str(Self::supported_kind(kind)?)
			.map_err(|e| ProviderError::Remote(format!("unknown record type: {e}")))?;
		let mut message = Message::new(rand_id(), MessageType::Query, OpCode::Update);

		let mut zone_query = Query::query(zone.clone(), RecordType::SOA);
		zone_query.set_query_class(DNSClass::IN);
		message.add_zone(zone_query);

		let mut delete = Record::from_rdata(name.clone(), 0, RData::Update0(rr_type));
		delete.dns_class = DNSClass::NONE;
		message.add_update(delete);

		Ok(message)
	}

	/// Sign the message with TSIG and send it over TCP, framed with the
	/// 2-byte big-endian length prefix RFC 1035 §4.2.4 specifies for
	/// DNS-over-TCP. Read one response frame, verify the TSIG on it,
	/// and translate the response code.
	async fn send_update(&self, mut message: Message) -> Result<(), ProviderError> {
		let now = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap_or_default()
			.as_secs();
		message
			.finalize(&self.signer, now)
			.map_err(|e| ProviderError::Remote(format!("TSIG sign: {e}")))?;

		let bytes = message
			.to_vec()
			.map_err(|e| ProviderError::Remote(format!("encode UPDATE: {e}")))?;
		let len = u16::try_from(bytes.len()).map_err(|_| {
			ProviderError::Remote("UPDATE message too large for DNS/TCP".to_string())
		})?;

		let mut stream = TcpStream::connect(&self.endpoint)
			.await
			.map_err(|e| ProviderError::Remote(format!("connect {}: {e}", self.endpoint)))?;
		stream
			.write_all(&len.to_be_bytes())
			.await
			.map_err(|e| ProviderError::Remote(format!("send length: {e}")))?;
		stream
			.write_all(&bytes)
			.await
			.map_err(|e| ProviderError::Remote(format!("send UPDATE: {e}")))?;
		stream
			.flush()
			.await
			.map_err(|e| ProviderError::Remote(format!("flush UPDATE: {e}")))?;

		let mut len_buf = [0u8; 2];
		stream
			.read_exact(&mut len_buf)
			.await
			.map_err(|e| ProviderError::Remote(format!("read response length: {e}")))?;
		let resp_len = u16::from_be_bytes(len_buf) as usize;
		let mut resp_buf = vec![0u8; resp_len];
		stream
			.read_exact(&mut resp_buf)
			.await
			.map_err(|e| ProviderError::Remote(format!("read response: {e}")))?;

		// Verify TSIG on the response — both authenticates the server and
		// confirms the response is for our message. A bad MAC is
		// BADSIG, mapped to ProviderError::Auth.
		self.signer
			.verify_message_byte(&resp_buf, None, true)
			.map_err(|_| ProviderError::Auth)?;

		let response = Message::from_vec(&resp_buf)
			.map_err(|e| ProviderError::Remote(format!("decode response: {e}")))?;

		match response.response_code {
			ResponseCode::NoError => Ok(()),
			ResponseCode::NotAuth | ResponseCode::Refused => Err(ProviderError::Auth),
			other => Err(ProviderError::Remote(format!("server returned {other}"))),
		}
	}
}

impl DnsProvider for Rfc2136Provider {
	fn upsert(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		Box::pin(async move {
			self.authorize(&record)?;
			let zone = Name::from_ascii(self.secret.zone())
				.map_err(|e| ProviderError::Remote(format!("invalid zone: {e}")))?;
			let name = Name::from_ascii(record.name.trim_end_matches('.'))
				.map_err(|e| ProviderError::Remote(format!("invalid name: {e}")))?;
			let message =
				Self::build_update_message(&zone, &name, record.kind, &record.value, record.ttl)?;
			self.send_update(message).await
		})
	}
	fn delete(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		Box::pin(async move {
			self.authorize(&record)?;
			let zone = Name::from_ascii(self.secret.zone())
				.map_err(|e| ProviderError::Remote(format!("invalid zone: {e}")))?;
			let name = Name::from_ascii(record.name.trim_end_matches('.'))
				.map_err(|e| ProviderError::Remote(format!("invalid name: {e}")))?;
			let message = Self::build_delete_message(&zone, &name, record.kind)?;
			self.send_update(message).await
		})
	}
	fn list(&self, _zone: &str) -> ListOp<'_> {
		// RFC 2136 only defines UPDATE; the nameserver's record set is
		// not enumerable through UPDATE. Returning Unsupported signals
		// callers that drift detection against this provider is
		// impossible.
		Box::pin(async move { Err(ProviderError::Unsupported) })
	}
}

/// Decode the TSIG key from base64. RFC 8945 §4.1 keys are shared out of
/// band; in BIND-style configs they appear base64-encoded. An invalid
/// value here is a config error, not a network one.
fn decode_key(encoded: &str) -> Result<Vec<u8>, ProviderError> {
	base64::engine::general_purpose::STANDARD
		.decode(encoded.trim())
		.map_err(|e| ProviderError::Remote(format!("TSIG key is not valid base64: {e}")))
}

/// Build an [`RData`] for one of the supported kinds.
fn record_rdata(kind: RecordKind, value: &str) -> Result<RData, ProviderError> {
	match kind {
		RecordKind::A => {
			let addr: std::net::Ipv4Addr = value
				.parse()
				.map_err(|e| ProviderError::Remote(format!("bad IPv4: {e}")))?;
			Ok(RData::A(addr.into()))
		}
		RecordKind::Aaaa => {
			let addr: std::net::Ipv6Addr = value
				.parse()
				.map_err(|e| ProviderError::Remote(format!("bad IPv6: {e}")))?;
			Ok(RData::AAAA(addr.into()))
		}
		RecordKind::Cname => {
			let target = Name::from_ascii(value.trim_end_matches('.'))
				.map_err(|e| ProviderError::Remote(format!("bad CNAME target: {e}")))?;
			Ok(RData::CNAME(CNAME(target)))
		}
		RecordKind::Txt => Ok(RData::TXT(TXT::new(vec![value.to_string()]))),
		RecordKind::Tlsa => {
			// TLSA in presentation form: "usage selector matching cert-hex".
			let mut parts = value.split_whitespace();
			let usage = parts
				.next()
				.and_then(|p| p.parse::<u8>().ok())
				.ok_or_else(|| {
					ProviderError::Remote("TLSA needs usage selector matching cert".into())
				})?;
			let selector = parts
				.next()
				.and_then(|p| p.parse::<u8>().ok())
				.ok_or_else(|| {
					ProviderError::Remote("TLSA needs usage selector matching cert".into())
				})?;
			let matching = parts
				.next()
				.and_then(|p| p.parse::<u8>().ok())
				.ok_or_else(|| {
					ProviderError::Remote("TLSA needs usage selector matching cert".into())
				})?;
			let cert_hex = parts.next().ok_or_else(|| {
				ProviderError::Remote("TLSA needs usage selector matching cert".into())
			})?;
			let cert = hex_decode(cert_hex)
				.map_err(|e| ProviderError::Remote(format!("TLSA cert is not hex: {e}")))?;
			Ok(RData::TLSA(TLSA::new(
				CertUsage::from(usage),
				Selector::from(selector),
				Matching::from(matching),
				cert,
			)))
		}
		RecordKind::Srv => {
			let (priority, weight, port, target) = parse_srv(value)
				.ok_or_else(|| ProviderError::Remote(format!("bad SRV value: {value}")))?;
			let target_name = Name::from_ascii(&target)
				.map_err(|e| ProviderError::Remote(format!("bad SRV target: {e}")))?;
			Ok(RData::SRV(SRV::new(priority, weight, port, target_name)))
		}
		RecordKind::Caa => {
			// CAA in presentation form: `<flags> <tag> <value>`. hickory's
			// CAA struct is `#[non_exhaustive]` and only constructs for
			// `issue` / `issuewild` / `iodef` tags, so for an `issue` record
			// we pass the CA name through `new_issue`. The wire bytes match
			// RFC 8659 because hickory emits `<flags> <taglen> <tag> <value>`
			// on its own. We do not support `issuewild` / `iodef` here
			// because the build_records path only emits `issue`.
			let mut parts = value.splitn(3, ' ');
			let flags: u8 = parts
				.next()
				.and_then(|p| p.parse().ok())
				.ok_or_else(|| ProviderError::Remote("CAA needs flags tag value".into()))?;
			let tag = parts
				.next()
				.ok_or_else(|| ProviderError::Remote("CAA needs flags tag value".into()))?
				.to_string();
			let ca_value = parts
				.next()
				.ok_or_else(|| ProviderError::Remote("CAA needs flags tag value".into()))?
				.trim_matches('"');
			let issuer_critical = flags & 0x80 != 0;
			if tag != "issue" {
				return Err(ProviderError::Remote(format!(
					"rfc2136 only emits CAA issue tags, got {tag}"
				)));
			}
			let name = Name::from_ascii(ca_value)
				.map_err(|e| ProviderError::Remote(format!("bad CAA issuer: {e}")))?;
			// `CAA::new_issue` encodes the value bytes itself; we have to
			// zero out the issuer-critical bit from `reserved_flags` because
			// hickory derives it from the dedicated `issuer_critical` field.
			Ok(RData::CAA(CAA::new_issue(
				issuer_critical,
				Some(name),
				Vec::new(),
			)))
		}
		RecordKind::Mx => {
			// MX in presentation form: `<priority> <target>`. RFC 1035 wire
			// form: `<preference:16> <exchange:Name>`.
			let mut parts = value.split_whitespace();
			let preference: u16 = parts
				.next()
				.and_then(|p| p.parse().ok())
				.ok_or_else(|| ProviderError::Remote("MX needs priority target".into()))?;
			let exchange = Name::from_ascii(
				parts
					.next()
					.ok_or_else(|| ProviderError::Remote("MX needs priority target".into()))?
					.trim_end_matches('.'),
			)
			.map_err(|e| ProviderError::Remote(format!("bad MX exchange: {e}")))?;
			Ok(RData::MX(MX::new(preference, exchange)))
		}
	}
}

/// Hex string → bytes, both upper- and lower-case.
fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
	if !s.len().is_multiple_of(2) {
		return Err("odd length".into());
	}
	(0..s.len())
		.step_by(2)
		.map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
		.collect()
}

/// Random 16-bit message id. The TSIG signature covers the bytes that
/// include the id, so picking it non-deterministically keeps replays
/// non-viable on top of the MAC.
fn rand_id() -> u16 {
	rand::random()
}

#[cfg(test)]
#[path = "rfc2136_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "rfc2136_tests_b.rs"]
mod tests_b;
