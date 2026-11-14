/// `value` without one pair of double quotes that wrap all of it, as a
/// provider that lists every target quoted returns it. A quote that does
/// not wrap the whole value is data (a CAA target is `0 issue "ca.example"`,
/// an HTTPS parameter is `alpn="h2"`) and stays.
pub fn unwrap_quotes(value: &str) -> &str {
	let Some(inner) = value
		.strip_prefix('"')
		.and_then(|rest| rest.strip_suffix('"'))
	else {
		return value;
	};
	// `"a" "b"` starts and ends with a quote and is two strings, not one.
	let mut escaped = false;
	for c in inner.chars() {
		match c {
			'\\' if !escaped => escaped = true,
			'"' if !escaped => return value,
			_ => escaped = false,
		}
	}
	inner
}

/// The four parts of an SRV record, split out from the presentation form
/// `"<prio> <weight> <port> <target>."`. The trailing dot on the target is
/// tolerated (and stripped) so callers can build the value either way. Returns
/// `None` if the value is malformed — providers should treat that as an
/// internal error rather than passing it to the API.
pub fn parse_srv(value: &str) -> Option<(u16, u16, u16, String)> {
	let mut parts = value.split_whitespace();
	let prio: u16 = parts.next()?.parse().ok()?;
	let weight: u16 = parts.next()?.parse().ok()?;
	let port: u16 = parts.next()?.parse().ok()?;
	let target = parts.next()?.trim_end_matches('.').to_string();
	if parts.next().is_some() {
		return None;
	}
	Some((prio, weight, port, target))
}

/// The TXT version tag at the start of `value`, or `None` when the
/// value is empty or its first token is not a tag epistle recognises.
/// The tag is the substring before the first whitespace or `;`; the
/// comparison is case-insensitive on the way in and the function
/// returns the canonical spec form (`v=spf1`, `v=DMARC1`, `v=DKIM1`,
/// `v=STSv1`, `v=TLSRPTv1`). The value is read through
/// [`crate::dns::txt::txt_logical`] first, so surrounding whitespace and
/// the presentation form some providers use (one or several quoted
/// strings) are tolerated; an empty or whitespace-only value returns
/// `None`.
pub fn txt_purpose(value: &str) -> Option<&'static str> {
	let stripped = crate::dns::txt::txt_logical(value);
	if stripped.is_empty() {
		return None;
	}
	let head: String = stripped
		.chars()
		.take_while(|c| !c.is_whitespace() && *c != ';')
		.collect();
	match head.to_ascii_lowercase().as_str() {
		"v=spf1" => Some("v=spf1"),
		"v=dmarc1" => Some("v=DMARC1"),
		"v=dkim1" => Some("v=DKIM1"),
		"v=stsv1" => Some("v=STSv1"),
		"v=tlsrptv1" => Some("v=TLSRPTv1"),
		_ => None,
	}
}

/// Whether two TXT values match under the upsert/delete contract
/// (see the module doc). Two tagged values match when their tag is
/// the same; an untagged value matches only the same logical value
/// ([`crate::dns::txt::same_txt_value`]: whitespace, quoting and
/// 255-octet splitting do not count); a tagged value never matches an
/// untagged one.
pub fn same_txt_purpose(a: &str, b: &str) -> bool {
	match (txt_purpose(a), txt_purpose(b)) {
		(Some(x), Some(y)) => x == y,
		(Some(_), None) | (None, Some(_)) => false,
		(None, None) => crate::dns::txt::same_txt_value(a, b),
	}
}

/// An MX target as a provider API takes it: without the trailing root dot,
/// except the null MX target (RFC 7505), which is the root `.` itself and
/// would otherwise become an empty host.
pub fn mx_target_for_api(target: &str) -> &str {
	if target == "." {
		target
	} else {
		target.trim_end_matches('.')
	}
}
