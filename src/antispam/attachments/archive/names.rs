//! Decoding the entry names of a ZIP archive.

use super::*;

/// The name as UTF-8 (lossy); as code page 437, which unzip and Windows
/// use, when it does not claim UTF-8 and is not ASCII; and the Unicode
/// Path field when there is one. Ambiguous when that field is present at
/// all, when the UTF-8 flag is set on bytes that are not UTF-8, or when the
/// name had to be cut.
pub(super) fn names_of(raw: &[u8], flags: u16, extra: &[u8]) -> (Vec<String>, bool) {
	let whole = raw;
	let (raw, cut) = bounded_name(whole);
	let mut names = vec![String::from_utf8_lossy(&raw).into_owned()];
	let mut ambiguous = cut || (flags & EFS != 0 && std::str::from_utf8(&raw).is_err());
	if flags & EFS == 0 && !raw.is_ascii() {
		names.push(raw.iter().map(|&byte| cp437(byte)).collect());
	}
	// C extractors stop at a NUL. When the cut dropped it with the middle
	// of the name, the name up to it is a reading of its own.
	if let Some(nul) = whole.iter().position(|&byte| byte == 0)
		&& cut && !raw.contains(&0)
	{
		let (head, _) = bounded_name(&whole[..nul]);
		names.push(String::from_utf8_lossy(&head).into_owned());
		if flags & EFS == 0 && !head.is_ascii() {
			names.push(head.iter().map(|&byte| cp437(byte)).collect());
		}
	}
	if let Some(body) = extra_field(extra, UNICODE_PATH) {
		ambiguous = true;
		if let Some(path) = body.get(5..) {
			let (path, cut) = bounded_name(path);
			ambiguous |= cut;
			names.push(String::from_utf8_lossy(&path).into_owned());
		}
	}
	names.dedup();
	(names, ambiguous)
}

/// `raw`, or its head and its last [`NAME_TAIL_BYTES`] when it is longer
/// than [`MAX_NAME_BYTES`], with whether it was cut.
pub(super) fn bounded_name(raw: &[u8]) -> (Vec<u8>, bool) {
	if raw.len() <= MAX_NAME_BYTES {
		return (raw.to_vec(), false);
	}
	let mut kept = raw[..MAX_NAME_BYTES - NAME_TAIL_BYTES].to_vec();
	kept.extend_from_slice(&raw[raw.len() - NAME_TAIL_BYTES..]);
	(kept, true)
}

/// One byte as code page 437 reads it.
pub(super) fn cp437(byte: u8) -> char {
	const HIGH: [char; 128] = [
		'Ç', 'ü', 'é', 'â', 'ä', 'à', 'å', 'ç', 'ê', 'ë', 'è', 'ï', 'î', 'ì', 'Ä', 'Å', 'É', 'æ',
		'Æ', 'ô', 'ö', 'ò', 'û', 'ù', 'ÿ', 'Ö', 'Ü', '¢', '£', '¥', '₧', 'ƒ', 'á', 'í', 'ó', 'ú',
		'ñ', 'Ñ', 'ª', 'º', '¿', '⌐', '¬', '½', '¼', '¡', '«', '»', '░', '▒', '▓', '│', '┤', '╡',
		'╢', '╖', '╕', '╣', '║', '╗', '╝', '╜', '╛', '┐', '└', '┴', '┬', '├', '─', '┼', '╞', '╟',
		'╚', '╔', '╩', '╦', '╠', '═', '╬', '╧', '╨', '╤', '╥', '╙', '╘', '╒', '╓', '╫', '╪', '┘',
		'┌', '█', '▄', '▌', '▐', '▀', 'α', 'ß', 'Γ', 'π', 'Σ', 'σ', 'µ', 'τ', 'Φ', 'Θ', 'Ω', 'δ',
		'∞', 'φ', 'ε', '∩', '≡', '±', '≥', '≤', '⌠', '⌡', '÷', '≈', '°', '∙', '·', '√', 'ⁿ', '²',
		'■', '\u{a0}',
	];
	if byte.is_ascii() {
		char::from(byte)
	} else {
		HIGH[usize::from(byte - 0x80)]
	}
}
