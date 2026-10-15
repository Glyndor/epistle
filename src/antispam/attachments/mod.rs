//! Attachment inspection: what each attachment of a message really is, and
//! whether it is dressed up as something else.
//!
//! epistle never opens or runs an attachment; the risk is the recipient's
//! client. The inspection reads the MIME structure ([`walk`]), identifies
//! every attachment from its magic bytes ([`sniff`]), lists zip entries and
//! Office macro storage without extracting anything ([`archive`]), and
//! applies the [`rules`]. What the server then does is the [`policy`]'s
//! decision. ClamAV still finds known malware; this finds the files that
//! say one thing and carry another.

pub mod archive;
pub mod decode;
pub mod header;
pub mod policy;
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
	/// The structure itself could be split differently by another reader.
	pub ambiguous: bool,
}

impl Report {
	/// Every reason in the report, sorted and without duplicates. A walk
	/// that stopped early adds [`Reason::ScanLimit`].
	pub fn reasons(&self) -> Vec<Reason> {
		let mut all: Vec<Reason> = self
			.parts
			.iter()
			.flat_map(|part| part.reasons.iter().copied())
			.collect();
		if self.stopped.is_some() {
			all.push(Reason::ScanLimit);
		}
		if self.ambiguous {
			all.push(Reason::AmbiguousMime);
		}
		all.sort();
		all.dedup();
		all
	}
}

/// How much one inspection may spend.
#[derive(Clone, Copy, Debug)]
pub struct Budget {
	/// Decoded bytes across every part.
	pub max_decoded: usize,
	/// When to give up; what was not reached gets [`Reason::ScanLimit`].
	pub deadline: Option<std::time::Instant>,
}

impl Budget {
	/// A byte budget and no deadline.
	pub fn bytes(max_decoded: usize) -> Self {
		Self {
			max_decoded,
			deadline: None,
		}
	}
}

/// Inspect `raw` within `budget`. Whatever could not be inspected
/// completely carries a reason; nothing unread is reported clean.
pub fn inspect(raw: &[u8], extensions: &Extensions, budget: Budget) -> Report {
	let limits = Limits {
		max_depth: MAX_DEPTH,
		max_parts: MAX_PARTS,
		max_decoded: budget.max_decoded,
		deadline: budget.deadline,
	};
	let mut report = Report::default();
	let walked = walk::walk(raw, &limits, |leaf| {
		let part = judge_leaf(&leaf, extensions);
		if leaf.attachment || !part.reasons.is_empty() {
			report.parts.push(part);
		}
	});
	report.stopped = walked.stopped;
	report.ambiguous = walked.ambiguous;
	report
}

fn judge_leaf(leaf: &Leaf, extensions: &Extensions) -> PartReport {
	let mut real_type = sniff::sniff(&leaf.content);
	// A zip opens from its end record, wherever it starts: one with data
	// in front, or glued behind a PDF or an image, is listed too. A
	// truncated part has lost its end record; the truncation is a
	// scan-limit of its own.
	let opens_as_zip =
		!leaf.truncated && (real_type == RealType::Zip || archive::has_end_record(&leaf.content));
	if real_type == RealType::Unknown && opens_as_zip {
		real_type = RealType::Zip;
	}
	// Message text is only judged when its bytes are a binary format; a
	// text part that is really a program or an archive is a disguise.
	let text_body = !leaf.attachment;
	let disguised = text_body
		&& (real_type.is_binary() || opens_as_zip)
		&& (real_type != RealType::Pdf || leaf.content.starts_with(b"%PDF-"));
	if text_body && !disguised {
		return PartReport {
			filename: leaf.filename().map(str::to_string),
			declared_type: leaf.declared_type.clone(),
			real_type,
			reasons: limits_only(leaf),
		};
	}
	let listing = opens_as_zip.then(|| archive::list_zip(&leaf.content));
	if real_type == RealType::Zip && listing.as_ref().is_some_and(archive::is_ooxml) {
		real_type = RealType::Ooxml;
	}
	let ole = (real_type == RealType::Ole2).then(|| archive::inspect_ole2(&leaf.content));
	let mut reasons = rules::judge(
		&Facts {
			filenames: &leaf.names,
			declared_types: &leaf.declared_types,
			real_type,
			listing: listing.as_ref(),
			ole,
		},
		extensions,
	);
	reasons.extend(limits_only(leaf));
	if disguised {
		reasons.push(Reason::TypeMismatch);
	}
	reasons.sort();
	reasons.dedup();
	PartReport {
		filename: leaf.filename().map(str::to_string),
		declared_type: leaf.declared_type.clone(),
		real_type,
		reasons,
	}
}

/// The reasons a part earns for how it was read, whatever it contains.
fn limits_only(leaf: &Leaf) -> Vec<Reason> {
	let mut reasons = Vec::new();
	if leaf.ambiguous {
		reasons.push(Reason::AmbiguousMime);
	}
	if leaf.truncated {
		reasons.push(Reason::ScanLimit);
	}
	reasons
}

#[cfg(test)]
#[path = "corpus.rs"]
pub(crate) mod corpus;

#[cfg(test)]
#[path = "inspect_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "inspect_tests_evasion.rs"]
mod tests_evasion;

#[cfg(test)]
#[path = "inspect_tests_failclosed.rs"]
mod tests_failclosed;

#[cfg(test)]
#[path = "inspect_tests_regressions.rs"]
mod tests_regressions;
