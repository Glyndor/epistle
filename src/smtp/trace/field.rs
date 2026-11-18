//! Read a header field name the way the readers after us read it, so every
//! operation that acts on a name compares the same bytes.

/// Whether `name` is the field name `wanted`: case folded, and with every
/// ASCII whitespace byte dropped from either side, wherever it appears.
///
/// mail-parser 0.11.9 drops exactly those bytes wherever they are in a name
/// while it looks the name up in its table of the known ones
/// (`parsers/header.rs`, `parse_header_name`), so `List -Id` reaches that
/// reader as `List-Id` and `Authenti cation-Results` as
/// `Authentication-Results`. A field left here under either spelling is a
/// second copy of the header a receiver reads, and the operations that act on
/// a name (the strip, the deduplication and the lookup) all compare through
/// here, so one name can never be two of them.
pub(super) fn same_name(name: &[u8], wanted: &[u8]) -> bool {
	let mut left = name
		.iter()
		.copied()
		.filter(|byte| !byte.is_ascii_whitespace());
	let mut right = wanted
		.iter()
		.copied()
		.filter(|byte| !byte.is_ascii_whitespace());
	loop {
		match (left.next(), right.next()) {
			(Some(one), Some(other)) if one.eq_ignore_ascii_case(&other) => {}
			(None, None) => return true,
			_ => return false,
		}
	}
}

/// The name of the field a header line starts and the rest of the line after
/// its colon, read the way the readers that come after us read it. One
/// extraction for the strip, the deduplication and the lookup, so a name one
/// of them acts on is the name the others see.
///
/// Three folds, each because a reader downstream folds it: every leading `:`
/// and ASCII whitespace byte while the name has not started (mail-parser
/// 0.11.9, `parse_header_name`), the ASCII tail a CR leaves behind, and the
/// trailing whitespace of any code point `char::is_whitespace` knows (DKIM
/// and ARC-AMS call it `name.trim_end()`). `None` for a line with no name.
/// The name comes back as those bytes stand: the whitespace a reader also
/// folds *inside* a name is folded by [`same_name`], which is where two
/// names are compared.
pub(crate) fn split_field(line: &[u8]) -> Option<(&[u8], &[u8])> {
	split_field_from(line, name_start(line))
}

/// [`split_field`] with the name starting at `offset` rather than after the
/// leading `:` and whitespace, so a caller that has to reproduce the reading
/// of a line without those folds can say where the name begins.
pub(crate) fn split_field_from(line: &[u8], offset: usize) -> Option<(&[u8], &[u8])> {
	let rest = line.get(offset..)?;
	let end = rest.iter().position(|&byte| byte == b':')?;
	let name = fold_trailing_space(rest[..end].trim_ascii_end());
	Some((name, &rest[end + 1..]))
}

/// Offset in `line` where the field name starts: while it has not started,
/// every `:` and every ASCII whitespace byte is folded away, so
/// `:X-Epistle-Attachment-Warning: forged` names `X-Epistle-Attachment-Warning`
/// for the readers that fold it, which is what the strip has to act on. The
/// readers that take the first colon as the end of the name read an empty one
/// there, which no reserved name matches, so folding it costs nothing and closes
/// the gap against the reader that does fold it.
pub(crate) fn name_start(line: &[u8]) -> usize {
	line.iter()
		.position(|byte| *byte != b':' && !byte.is_ascii_whitespace())
		.unwrap_or(line.len())
}

/// The name of the field a header line starts, folded the way [`split_field`]
/// folds it; `None` for a line with no name.
pub(super) fn field_name(line: &[u8]) -> Option<&[u8]> {
	split_field(line).map(|(name, _)| name)
}

/// Fold the trailing whitespace of `name` the way DKIM and ARC-AMS fold it
/// when they apply `trim_end()` to each header they read. RFC 5322 section
/// 3.6.8 limits field names to printable ASCII, so a non-ASCII byte at the end
/// is already invalid; folding the 19 code points `char::is_whitespace` knows
/// closes the gap that let a name those readers call `X-Epistle` reach the
/// sink as something else. Invalid UTF-8 is left as it came, since mail-parser
/// rejects it too.
fn fold_trailing_space(name: &[u8]) -> &[u8] {
	let Ok(text) = std::str::from_utf8(name) else {
		return name;
	};
	text.trim_end().as_bytes()
}
