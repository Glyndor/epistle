//! The RFC 2136 update messages and how they are sent.

use super::*;

impl Rfc2136Provider {
	/// Build the update section for a TXT upsert. The section
	/// contains a `class NONE` delete for every cached value with the
	/// same purpose as `value` (or, for untagged values, the same
	/// data), followed by the `add` of the new value. When the cache
	/// has no match (a fresh zone, or a different purpose) the
	/// message carries just the `add`; a stale cache would leave
	/// the previous TXT alongside the new one, the known limitation
	/// the module doc names.
	pub(super) fn build_txt_update_message(
		zone: &Name,
		name: &Name,
		ttl: u32,
		value: &str,
		cached: &[String],
	) -> Result<Message, ProviderError> {
		let mut message = Message::new(rand_id(), MessageType::Query, OpCode::Update);
		let mut zone_query = Query::query(zone.clone(), RecordType::SOA);
		zone_query.set_query_class(DNSClass::IN);
		message.add_zone(zone_query);
		for stale in cached.iter().filter(|c| same_txt_purpose(c, value)) {
			let rdata = record_rdata(&RecordKind::Txt, stale)?;
			let mut delete = Record::from_rdata(name.clone(), 0, rdata);
			delete.dns_class = DNSClass::NONE;
			message.add_update(delete);
		}
		let rdata = record_rdata(&RecordKind::Txt, value)?;
		let add = Record::from_rdata(name.clone(), ttl, rdata);
		message.add_update(add);
		Ok(message)
	}

	/// Build a single UPDATE message with one `delete RRset` and one
	/// `add RR` in the update section. The combination replaces the
	/// `(name,type)` set, no risk of duplicate records, and is the
	/// canonical RFC 2136 upsert for kinds epistle owns. The
	/// delete-rrset is class ANY (RFC 2136 §2.5.2) so the server
	/// removes every record of the type at the owner before the add
	/// runs.
	pub(super) fn build_update_message(
		zone: &Name,
		name: &Name,
		kind: &RecordKind,
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
		delete.dns_class = DNSClass::ANY;
		message.add_update(delete);

		let rdata = record_rdata(kind, value)?;
		let add = Record::from_rdata(name.clone(), ttl, rdata);
		message.add_update(add);

		Ok(message)
	}

	/// Build a single UPDATE message with one `delete RRset` — the RFC
	/// 2136 idempotent delete: class ANY, TTL 0, empty RDATA. The
	/// server answers NOERROR whether the RRset existed or not. RFC 2136
	/// §2.5.2 prescribes class ANY for RRset deletion (every record of
	/// `type` at `name`); class NONE would only remove the records
	/// whose RDATA matches the placeholder.
	pub(super) fn build_delete_message(
		zone: &Name,
		name: &Name,
		kind: &RecordKind,
	) -> Result<Message, ProviderError> {
		let rr_type = RecordType::from_str(Self::supported_kind(kind)?)
			.map_err(|e| ProviderError::Remote(format!("unknown record type: {e}")))?;
		let mut message = Message::new(rand_id(), MessageType::Query, OpCode::Update);

		let mut zone_query = Query::query(zone.clone(), RecordType::SOA);
		zone_query.set_query_class(DNSClass::IN);
		message.add_zone(zone_query);

		let mut delete = Record::from_rdata(name.clone(), 0, RData::Update0(rr_type));
		delete.dns_class = DNSClass::ANY;
		message.add_update(delete);

		Ok(message)
	}

	/// Build a TXT delete update section. With a value, the message
	/// is a single `class NONE` delete carrying the RDATA the caller
	/// passed; the server only removes records whose RDATA matches
	/// the placeholder, so a sibling ACME challenge at the same
	/// owner is not touched. With an empty value, the message falls
	/// back to `class ANY` (the RRset delete), which the DKIM
	/// rotator uses to retire an entire selector.
	pub(super) fn build_txt_delete_message(
		zone: &Name,
		name: &Name,
		value: &str,
	) -> Result<Message, ProviderError> {
		let mut message = Message::new(rand_id(), MessageType::Query, OpCode::Update);
		let mut zone_query = Query::query(zone.clone(), RecordType::SOA);
		zone_query.set_query_class(DNSClass::IN);
		message.add_zone(zone_query);
		if value.is_empty() {
			let mut delete = Record::from_rdata(name.clone(), 0, RData::Update0(RecordType::TXT));
			delete.dns_class = DNSClass::ANY;
			message.add_update(delete);
		} else {
			let rdata = record_rdata(&RecordKind::Txt, value)?;
			let mut delete = Record::from_rdata(name.clone(), 0, rdata);
			delete.dns_class = DNSClass::NONE;
			message.add_update(delete);
		}
		Ok(message)
	}

	/// Sign the message with TSIG and send it over TCP, framed with the
	/// 2-byte big-endian length prefix RFC 1035 §4.2.4 specifies for
	/// DNS-over-TCP. Read one response frame, verify the TSIG on it,
	/// and translate the response code.
	pub(super) async fn send_update(&self, mut message: Message) -> Result<(), ProviderError> {
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

		// The exchange has a bound at each wait: a server that accepts and
		// never answers cannot hold the call, as it cannot hold an HTTP one.
		let timed_out =
			|| ProviderError::Remote(format!("{} did not answer in time", self.endpoint));
		let mut stream = tokio::time::timeout(
			crate::dns::providers::connect_timeout(),
			TcpStream::connect(&self.endpoint),
		)
		.await
		.map_err(|_| timed_out())?
		.map_err(|e| ProviderError::Remote(format!("connect {}: {e}", self.endpoint)))?;
		let resp_buf = tokio::time::timeout(crate::dns::providers::request_timeout(), async {
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
			Ok::<_, ProviderError>(resp_buf)
		})
		.await
		.map_err(|_| timed_out())??;

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
