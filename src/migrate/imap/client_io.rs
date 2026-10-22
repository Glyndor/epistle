//! Command-wide deadlines and bounded IMAP response collection.

use super::*;
use crate::migrate::imap::wire::read_response;
use tokio::io::AsyncWriteExt;

impl Client {
	pub(super) fn next_tag(&mut self, name: &'static str) -> Vec<u8> {
		self.deadline = Some((tokio::time::Instant::now() + self.limits.response, name));
		self.tag += 1;
		format!("M{}", self.tag).into_bytes()
	}

	/// Send `line` under a fresh tag and hand every untagged data response
	/// to `on_data` until the tagged completion.
	pub(super) async fn command(
		&mut self,
		name: &'static str,
		line: &[u8],
		on_data: impl FnMut(Response) -> Result<(), ClientError>,
	) -> Result<(), ClientError> {
		self.command_with_limit(name, line, MAX_NAME_BYTES.min(self.limits.literal), on_data)
			.await
	}

	pub(super) async fn command_with_limit(
		&mut self,
		name: &'static str,
		line: &[u8],
		literal: usize,
		on_data: impl FnMut(Response) -> Result<(), ClientError>,
	) -> Result<(), ClientError> {
		self.read_literal = literal;
		let tag = self.next_tag(name);
		self.send(&tag, line).await?;
		self.collect(&tag, name, on_data).await
	}

	pub(super) async fn collect(
		&mut self,
		tag: &[u8],
		name: &'static str,
		mut on_data: impl FnMut(Response) -> Result<(), ClientError>,
	) -> Result<(), ClientError> {
		let mut bytes = 0usize;
		loop {
			let response = self.read().await?;
			bytes = bytes.saturating_add(
				response
					.segments
					.iter()
					.map(|s| s.text.len() + 2 + s.literal.as_ref().map_or(0, Vec::len))
					.sum::<usize>(),
			);
			if bytes > self.response_budget {
				return Err(ClientError::Protocol(
					"IMAP command response budget exceeded; run again to resume".into(),
				));
			}
			match parse::kind(&response) {
				Kind::Tagged {
					tag: got,
					status,
					text,
				} if got == tag => {
					return match status {
						Status::Ok => {
							self.note_code(&text);
							Ok(())
						}
						_ => Err(ClientError::Refused {
							command: name,
							text: sanitize(&text),
						}),
					};
				}
				Kind::Tagged { .. } => {
					return Err(ClientError::Protocol("answer to an unknown tag".into()));
				}
				Kind::UntaggedStatus {
					status: Status::Bye,
					text,
				} => return Err(ClientError::Bye(sanitize(&text))),
				Kind::UntaggedStatus { .. } | Kind::Data => on_data(response)?,
				Kind::Continuation => {
					return Err(ClientError::Protocol(format!(
						"unexpected continuation during {name}"
					)));
				}
			}
		}
	}

	pub(super) async fn send(&mut self, tag: &[u8], line: &[u8]) -> Result<(), ClientError> {
		let mut full = Zeroizing::new(Vec::with_capacity(tag.len() + line.len() + 3));
		full.extend_from_slice(tag);
		full.push(b' ');
		full.extend_from_slice(line);
		full.extend_from_slice(b"\r\n");
		self.write(&full).await
	}

	pub(super) async fn write(&mut self, bytes: &[u8]) -> Result<(), ClientError> {
		self.check_deadline()?;
		let deadline = self.deadline;
		let stream = self.conn.get_mut();
		let write = tokio::time::timeout(self.limits.idle, async {
			stream.write_all(bytes).await?;
			stream.flush().await
		});
		let result = match deadline {
			Some((at, command)) => tokio::time::timeout_at(at, write)
				.await
				.map_err(|_| ClientError::CommandTimeout { command })?,
			None => write.await,
		};
		result
			.map_err(|_| WireError::Timeout)?
			.map_err(WireError::Io)?;
		Ok(())
	}

	pub(super) async fn read(&mut self) -> Result<Response, ClientError> {
		self.check_deadline()?;
		let mut limits = self.limits;
		limits.literal = self.read_literal;
		let read = read_response(&mut self.conn, &limits);
		let response = match self.deadline {
			Some((at, command)) => tokio::time::timeout_at(at, read)
				.await
				.map_err(|_| ClientError::CommandTimeout { command })?,
			None => read.await,
		};
		Ok(response?)
	}
	fn check_deadline(&self) -> Result<(), ClientError> {
		if let Some((at, command)) = self.deadline
			&& tokio::time::Instant::now() >= at
		{
			return Err(ClientError::CommandTimeout { command });
		}
		Ok(())
	}
}
