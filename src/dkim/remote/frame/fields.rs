//! Reading and writing the bytes and length-prefixed fields of a frame body.

use super::FrameError;

/// A cursor over a frame body that hands out bytes and fields and refuses
/// to read past the end.
pub(super) struct Fields<'a> {
	rest: &'a [u8],
}

impl<'a> Fields<'a> {
	/// A cursor at the start of `body`.
	pub(super) fn new(body: &'a [u8]) -> Self {
		Fields { rest: body }
	}

	/// The next byte.
	pub(super) fn byte(&mut self) -> Result<u8, FrameError> {
		let (&first, rest) = self.rest.split_first().ok_or(FrameError::Truncated)?;
		self.rest = rest;
		Ok(first)
	}

	/// The next field, refused when its length is over `cap`. The length is
	/// compared before the field is sliced, so a hostile length costs
	/// nothing.
	pub(super) fn field(&mut self, cap: usize) -> Result<&'a [u8], FrameError> {
		let (prefix, rest) = self
			.rest
			.split_first_chunk::<4>()
			.ok_or(FrameError::Truncated)?;
		let len = usize::try_from(u32::from_be_bytes(*prefix)).map_err(|_| FrameError::TooLong)?;
		if len > cap {
			return Err(FrameError::TooLong);
		}
		if rest.len() < len {
			return Err(FrameError::Truncated);
		}
		let (field, rest) = rest.split_at(len);
		self.rest = rest;
		Ok(field)
	}

	/// The next field as UTF-8 text.
	pub(super) fn text(&mut self, cap: usize) -> Result<&'a str, FrameError> {
		std::str::from_utf8(self.field(cap)?).map_err(|_| FrameError::NotUtf8)
	}

	/// Succeeds only when every byte of the body was read.
	pub(super) fn end(self) -> Result<(), FrameError> {
		if self.rest.is_empty() {
			Ok(())
		} else {
			Err(FrameError::Trailing)
		}
	}
}

/// Append `bytes` as a field, refused when it is longer than `cap`.
pub(super) fn put(out: &mut Vec<u8>, bytes: &[u8], cap: usize) -> Result<(), FrameError> {
	if bytes.len() > cap {
		return Err(FrameError::TooLong);
	}
	let len = u32::try_from(bytes.len()).map_err(|_| FrameError::TooLong)?;
	out.extend_from_slice(&len.to_be_bytes());
	out.extend_from_slice(bytes);
	Ok(())
}
