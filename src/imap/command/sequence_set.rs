//! Sequence sets: the `1`, `1:5`, `1:*` ranges a command addresses, and
//! the SEARCHRES `$` placeholder (RFC 5182).

/// A `1`, `1:5`, `1:*`, `*` style sequence set (comma-separated ranges), or
/// the SEARCHRES `$` placeholder for the most recent saved result set
/// (RFC 5182).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequenceSet {
	/// Inclusive ranges as `(start, end)` pairs. `end = None` denotes a
	/// single value rather than a range. `0` is the internal encoding for
	/// `*` (the maximum existing value); see [`Self::contains`] for the
	/// resolution rules.
	pub ranges: Vec<(u32, Option<u32>)>,
	/// `true` when the source was `$`. `ranges` is then ignored and the
	/// session's most recent SEARCHRES-saved result set supplies the values.
	pub saved: bool,
}

impl SequenceSet {
	/// A sequence set that resolves to the SEARCHRES `$` placeholder.
	pub const SAVED: SequenceSet = SequenceSet {
		ranges: Vec::new(),
		saved: true,
	};

	/// Whether `value` (a sequence number or UID) is included, given the
	/// maximum existing value for `*` and the SEARCHRES `$` set when
	/// `self.saved == true`. When `saved` is empty and `self.saved == true`
	/// (no recent SAVE), nothing matches.
	pub fn contains(&self, value: u32, max: u32, saved: &[u32]) -> bool {
		if self.saved {
			return saved.contains(&value);
		}
		self.ranges.iter().any(|(start, end)| {
			let start = *start;
			let end = end.unwrap_or(start);
			// `*` is encoded as 0 in the parser; resolve it to `max` on
			// whichever end it appears, then normalize the range so a
			// range written in descending order (e.g. `*:1`) is treated
			// the same as its ascending form (1:*).
			let start = if start == 0 { max } else { start };
			let end = if end == 0 { max } else { end };
			let (low, high) = if start <= end {
				(start, end)
			} else {
				(end, start)
			};
			value >= low && value <= high
		})
	}
}

/// Parse `1`, `1:5`, `1:*`, `*`, comma-separated, or the SEARCHRES `$`
/// placeholder (RFC 5182). `0` encodes `*` here.
pub(super) fn parse_sequence_set(text: &str) -> Option<SequenceSet> {
	let trimmed = text.trim();
	// RFC 5182: the SEARCHRES shortcut is the whole sequence-set, not part of
	// a range. We accept any leading/trailing whitespace but reject mixed
	// forms like `1,$` or `$,5`: those would require resolving $ against an
	// arbitrary other range, which RFC 5182 does not specify. Returning the
	// SAVED placeholder is still useful — the consumer checks emptiness.
	if trimmed == "$" {
		return Some(SequenceSet::SAVED);
	}
	let mut ranges = Vec::new();
	for part in trimmed.split(',') {
		let (start, end) = match part.split_once(':') {
			Some((start, end)) => (parse_seq_number(start)?, Some(parse_seq_number(end)?)),
			None => (parse_seq_number(part)?, None),
		};
		ranges.push((start, end));
	}
	if ranges.is_empty() {
		return None;
	}
	Some(SequenceSet {
		ranges,
		saved: false,
	})
}

pub(super) fn parse_seq_number(text: &str) -> Option<u32> {
	if text == "*" {
		return Some(0);
	}
	let value: u32 = text.parse().ok()?;
	if value == 0 { None } else { Some(value) }
}
