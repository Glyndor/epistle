//! RFC 9051 envelope fields retain their original header representation.

use super::{list, raw_header, string};
use mail_parser::{Addr, Address, HeaderName, HeaderValue, Message, parsers::MessageStream};

pub(in crate::imap) fn render(message: &Message<'_>, part_id: usize) -> Vec<u8> {
	let Some(part) = message.parts.get(part_id) else {
		return list((0..10).map(|_| b"NIL".to_vec()));
	};
	let raw = |name| raw_header(message, part, name);
	let from = raw(HeaderName::From);
	list([
		string(raw(HeaderName::Date)),
		string(raw(HeaderName::Subject)),
		addresses(from),
		addresses(raw(HeaderName::Sender).or(from)),
		addresses(raw(HeaderName::ReplyTo).or(from)),
		addresses(raw(HeaderName::To)),
		addresses(raw(HeaderName::Cc)),
		addresses(raw(HeaderName::Bcc)),
		string(raw(HeaderName::InReplyTo)),
		string(raw(HeaderName::MessageId)),
	])
}

fn addresses(raw: Option<&[u8]>) -> Vec<u8> {
	let Some(raw) = raw else {
		return b"NIL".to_vec();
	};
	let mut protected = protect(raw);
	protected.push_str("\r\n");
	let parsed = MessageStream::new(protected.as_bytes()).parse_address();
	let mut out = vec![b'('];
	match parsed {
		HeaderValue::Address(Address::List(items)) => {
			for addr in items {
				out.extend(address(&addr));
			}
		}
		HeaderValue::Address(Address::Group(groups)) => {
			for group in groups {
				if let Some(name) = &group.name {
					out.extend(list([
						b"NIL".to_vec(),
						b"NIL".to_vec(),
						restored(Some(name)),
						b"NIL".to_vec(),
					]));
				}
				for addr in group.addresses {
					out.extend(address(&addr));
				}
				if group.name.is_some() {
					out.extend_from_slice(b"(NIL NIL NIL NIL)");
				}
			}
		}
		_ => return b"NIL".to_vec(),
	}
	if out.len() == 1 {
		return b"NIL".to_vec();
	}
	out.push(b')');
	out
}

fn protect(raw: &[u8]) -> String {
	// Protect encoded words and legacy octets while the address parser handles
	// quoting, comments and groups. Mapping every non-ASCII input byte also
	// protects UTF-8 private-use characters, so these tokens cannot collide
	// with input text. Each byte expands to at most three UTF-8 bytes.
	let mut protected = String::with_capacity(raw.len());
	let mut i = 0;
	while i < raw.len() {
		if raw[i..].starts_with(b"=?") {
			protected.push('\u{f800}');
			i += 2;
		} else if !raw[i].is_ascii() {
			// Adding an octet to U+F700 always produces a valid private-use scalar.
			protected.extend(char::from_u32(0xf700 + u32::from(raw[i])));
			i += 1;
		} else {
			protected.push(char::from(raw[i]));
			i += 1;
		}
	}
	protected
}

fn restored(value: Option<&str>) -> Vec<u8> {
	let Some(value) = value else {
		return b"NIL".to_vec();
	};
	let mut raw = Vec::with_capacity(value.len());
	let mut utf8 = [0; 4];
	for ch in value.chars() {
		match ch {
			'\u{f780}'..='\u{f7ff}' => raw.push((u32::from(ch) - 0xf700) as u8),
			'\u{f800}' => raw.extend_from_slice(b"=?"),
			_ => raw.extend_from_slice(ch.encode_utf8(&mut utf8).as_bytes()),
		}
	}
	string(Some(&raw))
}

fn address(addr: &Addr<'_>) -> Vec<u8> {
	let address = addr.address.as_deref();
	let (route, address) = address
		.and_then(|a| a.split_once(':'))
		.filter(|(route, _)| route.starts_with('@'))
		.map_or((None, address), |(route, address)| {
			(Some(route), Some(address))
		});
	let (mailbox, host) = address
		.map(|a| {
			a.rsplit_once('@')
				.map_or((Some(a), None), |(m, h)| (Some(m), Some(h)))
		})
		.unwrap_or((None, None));
	list([
		restored(addr.name.as_deref()),
		restored(route),
		restored(mailbox),
		restored(host),
	])
}

#[cfg(test)]
#[path = "envelope_tests_protection.rs"]
mod tests_protection;
