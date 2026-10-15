//! Attachment inspection: what each attachment of a message really is, and
//! whether it is dressed up as something else.
//!
//! epistle never opens or runs an attachment; the risk is the recipient's
//! client. The inspection reads the MIME structure ([`walk`]), identifies
//! every attachment from its magic bytes ([`sniff`]), lists zip entries and
//! Office macro storage without extracting anything ([`archive`]), and
//! applies the [`rules`]. ClamAV still finds known malware; this finds the
//! files that say one thing and carry another.

pub mod archive;
pub mod rules;
pub mod sniff;
pub mod walk;

use rules::{Extensions, Facts, Reason};
use sniff::RealType;
use walk::{Leaf, Limits, Stop};

/// Deepest MIME nesting inspected.
pub const MAX_DEPTH: usize = 10;
/// Most MIME parts inspected in one message.
pub const MAX_PARTS: usize = 1000;

/// One inspected attachment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartReport {
	/// The declared file name, decoded.
	pub filename: Option<String>,
	/// The declared `type/subtype`.
	pub declared_type: String,
	/// What the content really is.
	pub real_type: RealType,
	/// What the rules found, sorted.
	pub reasons: Vec<Reason>,
}

/// The inspection of one message.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
	/// Every attachment, in the order the walk met them.
	pub parts: Vec<PartReport>,
	/// Why the walk stopped early, if it did.
	pub stopped: Option<Stop>,
}

impl Report {
	/// Every reason in the report, sorted and without duplicates. A walk
	/// that stopped early adds [`Reason::MimeTooComplex`].
	pub fn reasons(&self) -> Vec<Reason> {
		let mut all: Vec<Reason> = self
			.parts
			.iter()
			.flat_map(|part| part.reasons.iter().copied())
			.collect();
		if self.stopped.is_some() {
			all.push(Reason::MimeTooComplex);
		}
		all.sort();
		all.dedup();
		all
	}
}

/// Inspect `raw`, decoding at most `max_decoded` bytes of attachment
/// content in total.
pub fn inspect(raw: &[u8], extensions: &Extensions, max_decoded: usize) -> Report {
	let limits = Limits {
		max_depth: MAX_DEPTH,
		max_parts: MAX_PARTS,
		max_decoded,
	};
	let mut report = Report::default();
	let outcome = walk::walk(raw, &limits, |leaf| {
		if leaf.attachment {
			report.parts.push(judge_leaf(&leaf, extensions));
		}
	});
	report.stopped = outcome.err();
	report
}

fn judge_leaf(leaf: &Leaf, extensions: &Extensions) -> PartReport {
	let mut real_type = sniff::sniff(&leaf.content);
	// A truncated zip has lost its central directory; listing it from the
	// prefix alone would miss entries, so only a complete one is listed.
	let listing =
		(real_type == RealType::Zip && !leaf.truncated).then(|| archive::list_zip(&leaf.content));
	if listing.as_ref().is_some_and(archive::is_ooxml) {
		real_type = RealType::Ooxml;
	}
	let ole_macros = real_type == RealType::Ole2 && archive::ole2_has_macros(&leaf.content);
	let reasons = rules::judge(
		&Facts {
			filename: leaf.filename.as_deref(),
			declared_type: &leaf.declared_type,
			real_type,
			listing: listing.as_ref(),
			ole_macros,
		},
		extensions,
	);
	PartReport {
		filename: leaf.filename.clone(),
		declared_type: leaf.declared_type.clone(),
		real_type,
		reasons,
	}
}

#[cfg(test)]
#[path = "corpus.rs"]
pub(crate) mod corpus;

#[cfg(test)]
#[path = "inspect_tests.rs"]
mod tests;
