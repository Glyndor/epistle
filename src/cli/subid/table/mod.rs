//! Reading `/etc/subuid` and `/etc/subgid`: which ranges an account holds,
//! whether one of them shares host ids with another account, and whether a
//! rewrite of the table changed only the account's entry.

/// The account the rootless stack runs under.
pub(crate) const ACCOUNT: &str = "glyndor-epistle";

/// One `name:start:count` entry, as the inclusive interval it covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Range<'a> {
	/// The account the entry belongs to.
	pub(crate) owner: &'a str,
	/// The first host id of the range.
	pub(crate) first: u64,
	/// The last host id of the range, inclusive.
	pub(crate) last: u64,
}

/// A block of subordinate ids: `count` ids from `start`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Block {
	/// The first id of the block.
	pub(crate) start: u64,
	/// How many ids the block spans; never zero.
	pub(crate) count: u64,
}

impl Block {
	/// The last id of the block, inclusive.
	pub(crate) fn last(self) -> u64 {
		self.start + self.count - 1
	}

	/// Whether the block shares at least one id with `range`.
	fn meets(self, range: &Range<'_>) -> bool {
		self.start <= range.last && range.first <= self.last()
	}

	/// The `first-last` form `usermod --add-subuids` takes.
	pub(crate) fn span(self) -> String {
		format!("{}-{}", self.start, self.last())
	}
}

/// The entries of a subordinate id table. Blank lines, comments and lines
/// that are not `name:start:count` with a positive count are skipped, the way
/// shadow's own parser skips them.
pub(crate) fn parse(text: &str) -> Vec<Range<'_>> {
	text.lines()
		.filter_map(|line| {
			let mut fields = line.trim().split(':');
			let owner = fields.next()?;
			let first: u64 = fields.next()?.parse().ok()?;
			let count: u64 = fields.next()?.parse().ok()?;
			if owner.is_empty() || owner.starts_with('#') || count == 0 || fields.next().is_some() {
				return None;
			}
			let last = first.checked_add(count - 1)?;
			Some(Range { owner, first, last })
		})
		.collect()
}

/// The block of [`ACCOUNT`] that shares ids with another account's range.
///
/// `Ok(None)` when no range of the account overlaps anyone else's (including
/// when the account holds no range at all). An account holding several
/// ranges, one of which overlaps, is refused: moving one of them by a fixed
/// offset is not a move the stack's storage can follow.
pub(crate) fn overlapping(text: &str) -> Result<Option<Block>, String> {
	let entries = parse(text);
	let (mine, others): (Vec<&Range>, Vec<&Range>) =
		entries.iter().partition(|range| range.owner == ACCOUNT);
	let shared = |own: &Range| {
		others
			.iter()
			.any(|other| own.first <= other.last && other.first <= own.last)
	};
	if !mine.iter().any(|own| shared(own)) {
		return Ok(None);
	}
	match mine.as_slice() {
		[only] => Ok(Some(Block {
			start: only.first,
			count: only.last - only.first + 1,
		})),
		_ => Err(format!(
			"{ACCOUNT} holds {} ranges and one of them overlaps another account's; move them by hand",
			mine.len()
		)),
	}
}

/// Whether `block` shares no id with any entry of the table, the account's
/// own included.
pub(crate) fn is_free(text: &str, block: Block) -> bool {
	!parse(text).iter().any(|range| block.meets(range))
}

/// Check that `after` is `before` with the account's `old` entry replaced by
/// `new` and every other entry unchanged, in any order. `usermod` appends the
/// added range at the end of the file, so the order is not compared.
pub(crate) fn moved(before: &str, after: &str, old: Block, new: Block) -> Result<(), String> {
	let entry = |block: Block| Range {
		owner: ACCOUNT,
		first: block.start,
		last: block.last(),
	};
	let mut expected: Vec<Range> = parse(before)
		.into_iter()
		.filter(|range| *range != entry(old))
		.collect();
	expected.push(entry(new));
	let mut found = parse(after);
	let key = |range: &Range| (range.owner.to_string(), range.first, range.last);
	expected.sort_by_key(key);
	found.sort_by_key(key);
	if expected == found {
		return Ok(());
	}
	let show = |ranges: &[Range]| {
		ranges
			.iter()
			.map(|range| format!("{} {}-{}", range.owner, range.first, range.last))
			.collect::<Vec<_>>()
			.join(", ")
	};
	Err(format!(
		"expected [{}], found [{}]",
		show(&expected),
		show(&found)
	))
}

#[cfg(test)]
mod tests;
