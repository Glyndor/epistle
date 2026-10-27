//! The DER subset RFC 3161 needs, read strictly and written minimally.
//!
//! Only single-byte tags and definite lengths of at most four bytes are
//! read; every length must be minimal and fit in what is left, so a length
//! can never make the reader allocate or skip past its input. Nothing here
//! recurses: each structure is walked by code that knows its shape, so the
//! nesting depth is that of the code, whatever the input claims.

/// A DER decoding error. The input is untrusted, so every refusal is one of
/// these and never a panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerError {
	/// The input ended inside an element.
	Truncated,
	/// A tag number above 30 (multi-byte tag form).
	HighTag,
	/// An indefinite, overlong or non-minimal length.
	BadLength,
	/// An element other than the one the structure requires here.
	Unexpected(u8),
	/// Bytes left after the last element of a structure.
	Trailing,
	/// A value outside what this reader accepts (an integer too large, a
	/// time in another form).
	BadValue,
}

impl std::fmt::Display for DerError {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			DerError::Truncated => formatter.write_str("truncated DER"),
			DerError::HighTag => formatter.write_str("multi-byte DER tag"),
			DerError::BadLength => formatter.write_str("invalid DER length"),
			DerError::Unexpected(tag) => write!(formatter, "unexpected DER tag 0x{tag:02x}"),
			DerError::Trailing => formatter.write_str("trailing bytes after DER structure"),
			DerError::BadValue => formatter.write_str("unsupported DER value"),
		}
	}
}

/// Universal and context tags used here.
pub mod tag {
	/// BOOLEAN
	pub const BOOLEAN: u8 = 0x01;
	/// INTEGER
	pub const INTEGER: u8 = 0x02;
	/// BIT STRING
	pub const BIT_STRING: u8 = 0x03;
	/// OCTET STRING
	pub const OCTET_STRING: u8 = 0x04;
	/// NULL
	pub const NULL: u8 = 0x05;
	/// OBJECT IDENTIFIER
	pub const OID: u8 = 0x06;
	/// GeneralizedTime
	pub const GENERALIZED_TIME: u8 = 0x18;
	/// SEQUENCE
	pub const SEQUENCE: u8 = 0x30;
	/// SET
	pub const SET: u8 = 0x31;
	/// `[0]` constructed
	pub const CONTEXT_0: u8 = 0xa0;
	/// `[1]` constructed
	pub const CONTEXT_1: u8 = 0xa1;
	/// `[0]` primitive
	pub const CONTEXT_0_PRIMITIVE: u8 = 0x80;
}

/// One element: its tag, its content and its whole encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
	/// The tag byte.
	pub tag: u8,
	/// The content octets.
	pub value: &'a [u8],
	/// Tag, length and content.
	pub raw: &'a [u8],
}

impl<'a> Tlv<'a> {
	/// A reader over the content of this (constructed) element.
	pub fn reader(&self) -> Reader<'a> {
		Reader::new(self.value)
	}
}

/// Reads consecutive elements from a buffer.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
	rest: &'a [u8],
}

impl<'a> Reader<'a> {
	/// A reader over `bytes`.
	pub fn new(bytes: &'a [u8]) -> Self {
		Reader { rest: bytes }
	}

	/// Whether every element was read.
	pub fn is_empty(&self) -> bool {
		self.rest.is_empty()
	}

	/// The next element, whatever its tag.
	pub fn read(&mut self) -> Result<Tlv<'a>, DerError> {
		let (tlv, rest) = read_tlv(self.rest)?;
		self.rest = rest;
		Ok(tlv)
	}

	/// The next element, which must carry `tag`.
	pub fn expect(&mut self, tag: u8) -> Result<Tlv<'a>, DerError> {
		let tlv = self.read()?;
		if tlv.tag == tag {
			Ok(tlv)
		} else {
			Err(DerError::Unexpected(tlv.tag))
		}
	}

	/// The next element if it carries `tag`, else nothing is consumed.
	pub fn optional(&mut self, tag: u8) -> Result<Option<Tlv<'a>>, DerError> {
		match self.rest.first() {
			Some(found) if *found == tag => self.read().map(Some),
			_ => Ok(None),
		}
	}

	/// Require that nothing is left.
	pub fn finish(&self) -> Result<(), DerError> {
		if self.rest.is_empty() {
			Ok(())
		} else {
			Err(DerError::Trailing)
		}
	}
}

/// `bytes` as exactly one element with `tag`.
pub fn parse_one(bytes: &[u8], tag: u8) -> Result<Tlv<'_>, DerError> {
	let mut reader = Reader::new(bytes);
	let tlv = reader.expect(tag)?;
	reader.finish()?;
	Ok(tlv)
}

fn read_tlv(input: &[u8]) -> Result<(Tlv<'_>, &[u8]), DerError> {
	let (&tag, after_tag) = input.split_first().ok_or(DerError::Truncated)?;
	if tag & 0x1f == 0x1f {
		return Err(DerError::HighTag);
	}
	let (&first, mut rest) = after_tag.split_first().ok_or(DerError::Truncated)?;
	let length = if first < 0x80 {
		usize::from(first)
	} else {
		let count = usize::from(first & 0x7f);
		if count == 0 || count > 4 || rest.len() < count {
			return Err(if rest.len() < count {
				DerError::Truncated
			} else {
				DerError::BadLength
			});
		}
		let (digits, after) = rest.split_at(count);
		if digits[0] == 0 {
			return Err(DerError::BadLength);
		}
		let length = digits
			.iter()
			.fold(0usize, |length, digit| (length << 8) | usize::from(*digit));
		if length < 0x80 {
			return Err(DerError::BadLength);
		}
		rest = after;
		length
	};
	if rest.len() < length {
		return Err(DerError::Truncated);
	}
	let (value, after) = rest.split_at(length);
	let header = input.len() - rest.len();
	Ok((
		Tlv {
			tag,
			value,
			raw: &input[..header + length],
		},
		after,
	))
}

/// A non-negative INTEGER that fits in a `u64`.
pub fn small_unsigned(tlv: &Tlv<'_>) -> Result<u64, DerError> {
	let digits = tlv.value;
	match digits {
		[] => Err(DerError::BadValue),
		[first, ..] if first & 0x80 != 0 => Err(DerError::BadValue),
		[0, second, ..] if second & 0x80 == 0 => Err(DerError::BadValue),
		_ => {
			let digits = digits.strip_prefix(&[0]).unwrap_or(digits);
			if digits.len() > 8 {
				return Err(DerError::BadValue);
			}
			Ok(digits
				.iter()
				.fold(0u64, |value, digit| (value << 8) | u64::from(*digit)))
		}
	}
}

/// A GeneralizedTime `YYYYMMDDHHMMSS[.f*]Z` as epoch seconds (fractions
/// dropped).
pub fn generalized_time(tlv: &Tlv<'_>) -> Result<u64, DerError> {
	let text = std::str::from_utf8(tlv.value).map_err(|_| DerError::BadValue)?;
	let text = text.strip_suffix('Z').ok_or(DerError::BadValue)?;
	let whole = match text.split_once('.') {
		Some((whole, fraction))
			if !fraction.is_empty() && fraction.bytes().all(|b| b.is_ascii_digit()) =>
		{
			whole
		}
		Some(_) => return Err(DerError::BadValue),
		None => text,
	};
	if whole.len() != 14 || !whole.bytes().all(|b| b.is_ascii_digit()) {
		return Err(DerError::BadValue);
	}
	let number = |range: std::ops::Range<usize>| -> i64 { whole[range].parse().unwrap_or(-1) };
	let (hour, minute, second) = (number(8..10), number(10..12), number(12..14));
	if hour > 23 || minute > 59 || second > 60 {
		return Err(DerError::BadValue);
	}
	let day = crate::evidence::day::Day::parse(&format!(
		"{}-{}-{}",
		&whole[0..4],
		&whole[4..6],
		&whole[6..8]
	))
	.ok_or(DerError::BadValue)?;
	let seconds = day.0 * 86_400 + hour * 3600 + minute * 60 + second;
	u64::try_from(seconds).map_err(|_| DerError::BadValue)
}

/// Encode one element.
pub fn encode(tag: u8, content: &[u8]) -> Vec<u8> {
	let mut out = vec![tag];
	let length = content.len();
	if length < 0x80 {
		out.push(length as u8);
	} else {
		let digits: Vec<u8> = length
			.to_be_bytes()
			.into_iter()
			.skip_while(|digit| *digit == 0)
			.collect();
		out.push(0x80 | digits.len() as u8);
		out.extend_from_slice(&digits);
	}
	out.extend_from_slice(content);
	out
}

/// Encode a SEQUENCE (or any constructed `tag`) of already encoded parts.
pub fn encode_all(tag: u8, parts: &[&[u8]]) -> Vec<u8> {
	encode(tag, &parts.concat())
}

/// The minimal DER INTEGER content of `value`.
pub fn unsigned_content(value: u64) -> Vec<u8> {
	let mut digits: Vec<u8> = value
		.to_be_bytes()
		.into_iter()
		.skip_while(|digit| *digit == 0)
		.collect();
	if digits.first().is_none_or(|first| first & 0x80 != 0) {
		digits.insert(0, 0);
	}
	digits
}

#[cfg(test)]
mod tests;
