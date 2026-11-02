//! The mailbox-level commands of the client: LIST, NAMESPACE, EXAMINE and the
//! UID listing and fetch of one batch. Split from `mod.rs`; the session,
//! login and wire plumbing stay there and in `io.rs`.

use super::*;

impl Client {
	/// Every mailbox with its special-use attributes: asked for with
	/// `RETURN (SPECIAL-USE)` when the server has LIST-EXTENDED (RFC 6154
	/// only promises them then), through XLIST on servers that predate
	/// SPECIAL-USE, plain LIST otherwise.
	pub(crate) async fn list(&mut self) -> Result<Vec<ListEntry>, ClientError> {
		let line: &[u8] = if self.has("SPECIAL-USE") && self.has("LIST-EXTENDED") {
			b"LIST \"\" \"*\" RETURN (SPECIAL-USE)"
		} else if self.has("XLIST") && !self.has("SPECIAL-USE") {
			b"XLIST \"\" \"*\""
		} else {
			b"LIST \"\" \"*\""
		};
		let mut entries = Vec::new();
		let mut metadata = std::mem::take(&mut self.metadata);
		let result = self
			.command("LIST", line, |response| {
				if let Some(entry) = parse::list_entry(&response)
					.map_err(|error| ClientError::Protocol(error.to_string()))?
				{
					if entries.len() >= MAX_MAILBOXES {
						return Err(ClientError::Protocol("too many mailboxes".into()));
					}
					if entry.name.len() > MAX_NAME_BYTES {
						return Err(ClientError::Metadata {
							scope: "mailbox name",
							limit: MAX_NAME_BYTES,
						});
					}
					// Include vector growth and the names copied into folder plans and reports.
					metadata.charge(
						4 * (std::mem::size_of::<ListEntry>()
							+ entry.name.capacity()
							+ entry.attributes.capacity() * std::mem::size_of::<String>()
							+ entry.attributes.iter().map(String::capacity).sum::<usize>()),
					)?;
					entries.push(entry);
				}
				Ok(())
			})
			.await;
		self.metadata = metadata;
		result?;
		Ok(entries)
	}

	/// The personal namespace prefix, when the server has NAMESPACE.
	pub(crate) async fn namespace(&mut self) -> Result<Option<Vec<u8>>, ClientError> {
		if !self.has("NAMESPACE") {
			return Ok(None);
		}
		let mut prefix = None;
		self.command("NAMESPACE", b"NAMESPACE", |response| {
			if prefix.is_none() {
				prefix = parse::personal_namespace(&response);
			}
			Ok(())
		})
		.await?;
		Ok(prefix)
	}

	/// Open `name` read-only.
	pub(crate) async fn examine(&mut self, name: &[u8]) -> Result<Examined, ClientError> {
		self.metadata.next_mailbox();
		let mut line = b"EXAMINE ".to_vec();
		line.extend_from_slice(&quote_mailbox(name)?);
		let mut examined = Examined {
			exists: 0,
			uid_validity: 0,
			uid_next: 0,
		};
		self.command("EXAMINE", &line, |response| {
			let words = parse::data_words(&response);
			match words.as_slice() {
				[count, word, ..] if word.eq_ignore_ascii_case("EXISTS") => {
					examined.exists = count.parse().unwrap_or(0);
				}
				_ => {}
			}
			if let Kind::UntaggedStatus { text, .. } = parse::kind(&response)
				&& let [code, value, ..] = parse::response_code(&text).as_slice()
			{
				if code.eq_ignore_ascii_case("UIDVALIDITY") {
					examined.uid_validity = value.parse().unwrap_or(0);
				}
				if code.eq_ignore_ascii_case("UIDNEXT") {
					examined.uid_next = value.parse().unwrap_or(0);
				}
			}
			Ok(())
		})
		.await?;
		Ok(examined)
	}

	/// The UID and size of every message with a UID of `from` or more, at
	/// most `cap` of them. `to` bounds a UID window when UIDNEXT is known.
	pub(crate) async fn list_uids(
		&mut self,
		from: u32,
		to: Option<u32>,
		cap: usize,
	) -> Result<Vec<Listed>, ClientError> {
		let end = to.map_or_else(|| "*".into(), |to| to.to_string());
		let line = format!("UID FETCH {from}:{end} (UID RFC822.SIZE)");
		let mut listed = Vec::new();
		let mut metadata = std::mem::take(&mut self.metadata);
		let result = self
			.command("FETCH", line.as_bytes(), |response| {
				if let Some(item) = parse::listed(response)
					.map_err(|error| ClientError::Protocol(error.to_string()))?
				{
					if listed.len() >= cap {
						return Err(ClientError::Protocol(
							"the server listed more messages than the mailbox holds".into(),
						));
					}
					if item.uid >= from {
						if to.is_some_and(|end| item.uid > end) {
							return Err(ClientError::Protocol(
								"the server listed a UID outside the requested window".into(),
							));
						}
						metadata.charge(2 * std::mem::size_of::<Listed>())?;
						listed.push(item);
					}
				}
				Ok(())
			})
			.await;
		self.metadata = metadata;
		result?;
		listed.sort_by_key(|item| item.uid);
		listed.dedup_by_key(|item| item.uid);
		Ok(listed)
	}

	/// Fetch flags, INTERNALDATE, size and body of every message in `batch`
	/// without setting `\Seen`.
	///
	/// The sizes in `batch` are what the server declared when listing, and
	/// nothing the server declares is trusted for memory: every body that
	/// arrives is checked against its declared size ([`size_fits`]), and the
	/// bodies held for the batch may total at most `budget` octets. Either
	/// failure ends the fetch before more is buffered.
	pub(crate) async fn fetch(
		&mut self,
		batch: &[Listed],
		budget: u64,
	) -> Result<Vec<Fetched>, ClientError> {
		let uids: Vec<u32> = batch.iter().map(|item| item.uid).collect();
		let line = format!(
			"UID FETCH {} (UID FLAGS INTERNALDATE RFC822.SIZE BODY.PEEK[])",
			uid_set(&uids)
		);
		let mut fetched: Vec<Fetched> = Vec::with_capacity(uids.len());
		let mut held = 0u64;
		let mut responses = 0usize;
		let most_responses = uids.len().saturating_mul(4).saturating_add(64);
		let mut metadata = std::mem::take(&mut self.metadata);
		let result = self
			.command_with_limit("FETCH", line.as_bytes(), self.limits.literal, |response| {
				responses += 1;
				if responses > most_responses {
					return Err(ClientError::Protocol(
						"the server sent far more responses than messages asked for".into(),
					));
				}
				let Some(item) = parse::fetch(response)
					.map_err(|error| ClientError::Protocol(error.to_string()))?
				else {
					return Ok(());
				};
				let (Some(body), Ok(at)) = (&item.body, uids.binary_search(&item.uid)) else {
					return Ok(());
				};
				let declared = batch[at].size;
				let actual = body.len() as u64;
				if !size_fits(declared, actual) {
					return Err(ClientError::SizeMismatch {
						uid: item.uid,
						declared,
						actual,
					});
				}
				held = held.saturating_add(actual);
				if held > budget || fetched.len() >= uids.len() {
					return Err(ClientError::BatchTooLarge { budget });
				}
				metadata.charge(
					2 * std::mem::size_of::<Fetched>()
						+ item.flags.capacity() * std::mem::size_of::<String>()
						+ item.flags.iter().map(String::capacity).sum::<usize>(),
				)?;
				fetched.push(item);
				Ok(())
			})
			.await;
		self.metadata = metadata;
		result?;
		Ok(fetched)
	}
}
