//! Storing and DKIM-signing the outbound copy.

use super::*;

impl SplitDelivery {
	/// Store `message` in the outbound spool.
	pub(super) fn store_outbound(
		&self,
		message: &AcceptedMessage,
		owner: Option<&str>,
	) -> Result<(), SinkError> {
		self.outbound
			.store_owned(message, owner, &BTreeMap::new())
			.map(|_| ())
			.map_err(|error| SinkError::Unavailable(error.to_string()))
	}

	/// DKIM-sign relayed mail so receivers can verify our domain. The signer
	/// returns the DKIM-Signature header line; it is prepended to the body
	/// in a single allocation, so the body is moved, not copied.
	pub(super) fn sign_outbound(&self, message: &mut AcceptedMessage) {
		if let std::borrow::Cow::Owned(data) =
			crate::util::header_block::outbound_crlf(&message.data)
		{
			message.data = data;
		}
		if let Some(signer) = &self.signer
			&& let Some(domain) = self.signing_domain(message)
			&& let Some(header) = signer.sign(&domain, &message.data)
		{
			let header_bytes = header.as_bytes();
			let mut signed = Vec::with_capacity(header_bytes.len() + message.data.len());
			signed.extend_from_slice(header_bytes);
			signed.append(&mut message.data);
			message.data = signed;
		}
	}

	/// DKIM-sign an auto-reply the server writes itself: it has a null
	/// reverse-path, so `d=` is the domain of its From, the account's own.
	/// The signer returns only the DKIM-Signature header line; we prepend
	/// it to the body in a single allocation sized to the combined length
	/// so the body is moved, not copied.
	pub(super) fn sign_reply(&self, reply: &mut AcceptedMessage) {
		reply.data = crate::util::header_block::frame_generated(std::mem::take(&mut reply.data));
		if let Some(signer) = &self.signer
			&& let Some(domain) = self.signing_domain(reply)
			&& let Some(header) = signer.sign(&domain, &reply.data)
		{
			let header_bytes = header.as_bytes();
			let mut signed = Vec::with_capacity(header_bytes.len() + reply.data.len());
			signed.extend_from_slice(header_bytes);
			signed.append(&mut reply.data);
			reply.data = signed;
		}
	}

	/// The `d=` for an outbound message: the domain of its single From
	/// header when the key is published for it, so DMARC aligns with the
	/// domain the reader sees; otherwise the envelope domain.
	pub(super) fn signing_domain(&self, message: &AcceptedMessage) -> Option<String> {
		let envelope = message
			.reverse_path
			.rsplit_once('@')
			.map(|(_, domain)| domain.to_ascii_lowercase());
		match crate::dmarc::author::author_domain(&message.data) {
			crate::dmarc::author::AuthorDomain::One(from)
				if self.directory.current().hosts_domain(&from) =>
			{
				Some(from)
			}
			crate::dmarc::author::AuthorDomain::One(from) => {
				if let Some(envelope) = &envelope {
					tracing::info!(
						%from,
						%envelope,
						"no DKIM key for the From domain; signing for the envelope domain, so DMARC will not align"
					);
				}
				envelope
			}
			_ => envelope,
		}
	}
}
