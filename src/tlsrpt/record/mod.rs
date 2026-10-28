//! TLS-RPT record parsing (RFC 8460 section 3).

/// A parsed `_smtp._tls` TLS-RPT policy record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
	/// Report recipients parsed from `rua=` (RFC 8460 §3).
	/// Each element is a `mailto:` or `https:` URI; other schemes are
	/// dropped. A record with no valid URI is malformed, so this is never
	/// empty in an `Ok` result.
	pub rua: Vec<String>,
}

/// Parse a `v=TLSRPTv1` TXT record. Returns `None` for records that are not
/// TLS-RPT at all; `Err` for TLS-RPT records that are malformed (no usable
/// `rua=`). Mirrors the shape of `dmarc::record::parse`.
pub fn parse(text: &str) -> Option<Result<Record, ()>> {
	let mut tags = text.split(';').map(str::trim);
	// v=TLSRPTv1 must be the first tag (RFC 8460 §3).
	if tags.next() != Some("v=TLSRPTv1") {
		return None;
	}

	let mut rua: Option<Vec<String>> = None;

	for tag in tags {
		if tag.is_empty() {
			continue;
		}
		let Some((name, value)) = tag.split_once('=') else {
			return Some(Err(()));
		};
		// Only rua= is defined; unknown tags are ignored (RFC 8460 §3).
		if name.trim() == "rua" {
			rua = Some(parse_rua_list(value.trim()));
		}
	}

	// rua= is required and must yield at least one usable URI.
	match rua {
		Some(uris) if !uris.is_empty() => Some(Ok(Record { rua: uris })),
		_ => Some(Err(())),
	}
}

/// Parse the `rua=` value into a list of report URIs, keeping only the
/// `mailto:` and `https:` schemes defined by RFC 8460 §3. Blank entries and
/// unsupported schemes are dropped.
fn parse_rua_list(value: &str) -> Vec<String> {
	value
		.split(',')
		.filter_map(|uri| {
			let uri = uri.trim();
			let lower = uri.to_ascii_lowercase();
			if lower.starts_with("mailto:") || lower.starts_with("https:") {
				Some(uri.to_string())
			} else {
				None
			}
		})
		.collect()
}

#[cfg(test)]
mod tests;
