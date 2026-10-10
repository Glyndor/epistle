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
	// Protect encoded words and legacy octets while the address parser handles
	// quoting, comments and groups. Restore the original bytes before encoding
	// the IMAP string, so charset conversion cannot alter envelope values.
	let mut marker = "IMAPRAW".to_string();
	while raw
		.windows(marker.len())
		.any(|window| window == marker.as_bytes())
	{
		marker.push('X');
	}
	let mut protected = String::new();
	let mut i = 0;
	while i < raw.len() {
		if raw[i..].starts_with(b"=?") {
			protected.push_str(&marker);
			protected.push('E');
			i += 2;
		} else if !raw[i].is_ascii() {
			protected.push_str(&format!("{marker}B{:02X}", raw[i]));
			i += 1;
		} else {
			protected.push(char::from(raw[i]));
			i += 1;
		}
	}
	protected.push_str("\r\n");
	let parsed = MessageStream::new(protected.as_bytes()).parse_address();
	let mut out = vec![b'('];
	match parsed {
		HeaderValue::Address(Address::List(items)) => {
			for addr in items {
				out.extend(address(&addr, &marker));
			}
		}
		HeaderValue::Address(Address::Group(groups)) => {
			for group in groups {
				if let Some(name) = &group.name {
					out.extend(list([
						b"NIL".to_vec(),
						b"NIL".to_vec(),
						restored(Some(name), &marker),
						b"NIL".to_vec(),
					]));
				}
				for addr in group.addresses {
					out.extend(address(&addr, &marker));
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

fn restored(value: Option<&str>, marker: &str) -> Vec<u8> {
	let Some(value) = value else {
		return b"NIL".to_vec();
	};
	let bytes = value.as_bytes();
	let mut raw = Vec::new();
	let mut i = 0;
	while i < bytes.len() {
		if bytes[i..].starts_with(marker.as_bytes()) {
			let token = i + marker.len();
			if bytes.get(token) == Some(&b'E') {
				raw.extend_from_slice(b"=?");
				i = token + 1;
				continue;
			}
			if bytes.get(token) == Some(&b'B')
				&& let Some(byte) = bytes
					.get(token + 1..token + 3)
					.and_then(|hex| std::str::from_utf8(hex).ok())
					.and_then(|hex| u8::from_str_radix(hex, 16).ok())
			{
				raw.push(byte);
				i = token + 3;
				continue;
			}
		}
		raw.push(bytes[i]);
		i += 1;
	}
	string(Some(&raw))
}

fn address(addr: &Addr<'_>, marker: &str) -> Vec<u8> {
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
		restored(addr.name.as_deref(), marker),
		restored(route, marker),
		restored(mailbox, marker),
		restored(host, marker),
	])
}
