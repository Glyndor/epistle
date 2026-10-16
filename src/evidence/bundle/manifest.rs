//! What a bundle says it covers, and the check that it covers it entirely.
//!
//! The records in a bundle are proved one by one against the signed root of
//! their day, which cannot show that a record was left out. What can be
//! shown is that the ones present contradict nothing: every message has its
//! acceptance, and an acceptance has either an abandonment or an outcome for
//! every recipient the bundle covers. Taking out the abandonment, or a
//! bounce, then leaves a message that is not accounted for, and the check
//! fails. The manifest names the recipients the bundle covers, since a
//! bundle of one recipient does not hold the others' outcomes.

use std::collections::{BTreeMap, BTreeSet};
use std::io::BufReader;
use std::path::Path;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::MAX_RECORDS;
use super::check::read;
use super::export::Selector;
use crate::evidence::day::Day;
use crate::evidence::hidden::is_hidden;
use crate::evidence::lines::{Line, Lines};
use crate::evidence::record::{Accepted, Entry, Record};

/// The file's name.
pub(super) const FILE: &str = "manifest.json";
/// The format version.
const VERSION: u32 = 1;

/// What the bundle was exported for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "snake_case", deny_unknown_fields)]
enum Scope {
	/// Every recipient of one message.
	Message { message_id: String },
	/// One recipient, over the days given.
	Recipient {
		address: String,
		from: String,
		to: String,
	},
}

/// The manifest file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Manifest {
	v: u32,
	#[serde(flatten)]
	scope: Scope,
}

/// What the reader says the bundle must be about.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Expectation {
	/// The `Message-ID` the bundle must be of.
	pub message_id: Option<String>,
	/// A recipient the bundle must cover.
	pub recipient: Option<String>,
	/// The first day the bundle must cover.
	pub from: Option<crate::evidence::day::Day>,
	/// The last day the bundle must cover.
	pub to: Option<crate::evidence::day::Day>,
}

/// Write the manifest of an export made for `selector`.
pub(super) fn write(out: &Path, selector: &Selector) -> std::io::Result<()> {
	let scope = match selector {
		Selector::MessageId(id) => Scope::Message {
			message_id: id.clone(),
		},
		Selector::Recipient { address, from, to } => Scope::Recipient {
			address: address.clone(),
			from: from.name(),
			to: to.name(),
		},
	};
	let bytes = serde_json::to_vec_pretty(&Manifest { v: VERSION, scope })
		.map_err(std::io::Error::other)?;
	super::write_file(&out.join(FILE), &bytes)
}

/// What the bundle holds of one message.
#[derive(Default)]
struct Held {
	accepted: Vec<(Day, Accepted)>,
	abandoned: bool,
	outcomes: Vec<String>,
}

impl Scope {
	/// What the bundle was made for, in words.
	fn describe(&self) -> String {
		match self {
			Scope::Message { message_id } => format!("message {message_id}"),
			Scope::Recipient { address, .. } => format!("recipient {address}"),
		}
	}
}

/// Whether `text` can be shown on a terminal as it is: no control character
/// and none of the format characters that reorder or hide text.
fn plain(text: &str) -> bool {
	!text.is_empty() && text.chars().all(|c| !c.is_control() && !is_hidden(c))
}

/// The manifest in `dir`, read as the untrusted thing it is: every field
/// has to be what it says it is before anything of it is used or shown.
fn load(dir: &Path) -> Result<(Manifest, Option<(Day, Day)>), String> {
	let manifest: Manifest =
		serde_json::from_slice(&read(&dir.join(FILE)).map_err(|why| format!("{FILE}: {why}"))?)
			.map_err(|_| format!("{FILE}: not a manifest"))?;
	if manifest.v != VERSION {
		return Err(format!("{FILE}: unknown version"));
	}
	let not = || format!("{FILE}: not a manifest");
	let range = match &manifest.scope {
		Scope::Message { message_id } if plain(message_id) => None,
		Scope::Recipient { address, from, to } if plain(address) => {
			let (from, to) = (
				Day::parse(from).ok_or_else(not)?,
				Day::parse(to).ok_or_else(not)?,
			);
			Some((from, to))
		}
		_ => return Err(not()),
	};
	Ok((manifest, range))
}

/// Check that every message in the bundle in `dir` is accounted for, for the
/// recipients its manifest names, and that the manifest is what `expected`
/// asks for and what the records are about. Only the records of `verified`
/// days count: a day that did not verify proves nothing. Returns what was
/// verified, to be told to the reader.
pub(super) fn complete(
	dir: &Path,
	expected: &Expectation,
	verified: &BTreeSet<String>,
) -> Result<String, String> {
	let (manifest, range) = load(dir)?;
	if let Some(wanted) = &expected.message_id {
		match &manifest.scope {
			Scope::Message { message_id } if message_id == wanted => {}
			other => {
				return Err(format!(
					"the bundle was made for {}, not for message {wanted}",
					other.describe()
				));
			}
		}
	}
	if let Some(wanted) = &expected.recipient
		&& let Scope::Recipient { address, .. } = &manifest.scope
		&& !address.eq_ignore_ascii_case(wanted)
	{
		return Err(format!(
			"the bundle was made for recipient {address}, not for recipient {wanted}"
		));
	}
	if let Some((from, to)) = range
		&& (expected.from.is_some_and(|asked| asked < from)
			|| expected.to.is_some_and(|asked| asked > to))
	{
		return Err(format!(
			"the manifest ({} to {}) does not cover the days asked",
			from.name(),
			to.name()
		));
	}
	let mut held: BTreeMap<Uuid, Held> = BTreeMap::new();
	let mut total = 0usize;
	for name in verified {
		let Some(day) = Day::parse(name) else {
			continue;
		};
		let path = dir.join("records").join(format!("{name}.jsonl"));
		if !std::fs::symlink_metadata(&path).is_ok_and(|meta| meta.file_type().is_file()) {
			continue;
		}
		let file = std::fs::File::open(&path).map_err(|error| error.kind().to_string())?;
		let mut lines = Lines::new(BufReader::new(file));
		while let Some((_, line)) = lines
			.next_line()
			.map_err(|error| error.kind().to_string())?
		{
			total += 1;
			if total > MAX_RECORDS {
				return Err("more records than a bundle holds".into());
			}
			let Line::Complete(bytes) = line else {
				continue;
			};
			let Ok(record) = Record::parse_canonical(bytes) else {
				continue;
			};
			match record.entry {
				Entry::Accepted(accepted) => held
					.entry(accepted.spool_id)
					.or_default()
					.accepted
					.push((day, accepted)),
				Entry::Abandoned(abandoned) => {
					held.entry(abandoned.spool_id).or_default().abandoned = true
				}
				Entry::Outcome(outcome) => held
					.entry(outcome.spool_id)
					.or_default()
					.outcomes
					.push(outcome.recipient.to_ascii_lowercase()),
				_ => {}
			}
		}
	}
	let mut checked = 0usize;
	let mut asked_found = (false, false);
	let mut days: Vec<Day> = Vec::new();
	for (id, message) in &held {
		let [(day, accepted)] = message.accepted.as_slice() else {
			return Err(match message.accepted.is_empty() {
				true => format!("{id}: a record of this message is here without its acceptance"),
				false => format!("{id}: accepted more than once"),
			});
		};
		match &manifest.scope {
			Scope::Message { message_id } if accepted.message_id.as_deref() != Some(message_id) => {
				return Err(format!(
					"{id}: its Message-ID is not the Message-ID the manifest names"
				));
			}
			Scope::Recipient { address, .. }
				if !accepted
					.recipients
					.iter()
					.any(|r| r.eq_ignore_ascii_case(address)) =>
			{
				return Err(format!("{id}: was not sent to {address}"));
			}
			_ => {}
		}
		if let Some((from, to)) = range
			&& (*day < from || *day > to)
		{
			return Err(format!(
				"{id}: accepted on {}, outside the days the manifest names ({} to {})",
				day.name(),
				from.name(),
				to.name()
			));
		}
		if expected.from.is_some_and(|asked| *day < asked)
			|| expected.to.is_some_and(|asked| *day > asked)
		{
			return Err(format!(
				"{id}: accepted on {}, outside the days asked",
				day.name()
			));
		}
		if let Some(wanted) = &expected.recipient
			&& !accepted
				.recipients
				.iter()
				.any(|recipient| recipient.eq_ignore_ascii_case(wanted))
		{
			return Err(format!("{id}: was not sent to {wanted}"));
		}
		asked_found.0 |= expected
			.message_id
			.as_ref()
			.is_some_and(|wanted| accepted.message_id.as_ref() == Some(wanted));
		asked_found.1 |= expected.recipient.as_ref().is_some_and(|wanted| {
			accepted
				.recipients
				.iter()
				.any(|recipient| recipient.eq_ignore_ascii_case(wanted))
		});
		let covered: Vec<String> = match &manifest.scope {
			Scope::Message { .. } => accepted
				.recipients
				.iter()
				.map(|recipient| recipient.to_ascii_lowercase())
				.collect(),
			Scope::Recipient { address, .. } => vec![address.to_ascii_lowercase()],
		};
		checked += 1;
		days.push(*day);
		if message.abandoned {
			if !message.outcomes.is_empty() {
				return Err(format!("{id}: abandoned, and yet it has outcomes"));
			}
			continue;
		}
		for outcome in &message.outcomes {
			let known = accepted
				.recipients
				.iter()
				.any(|recipient| recipient.eq_ignore_ascii_case(outcome));
			if !known {
				return Err(format!(
					"{id}: an outcome for a recipient it was not accepted for"
				));
			}
		}
		for recipient in &covered {
			if !message.outcomes.contains(recipient) {
				return Err(format!(
					"{id}: no outcome for {recipient}, and not abandoned: a record is missing, or the message is still in the queue"
				));
			}
		}
	}
	// A story is about something: with nothing accepted that matches it,
	// nothing was checked.
	if let Some(wanted) = &expected.message_id
		&& !asked_found.0
	{
		return Err(format!(
			"the bundle holds no acceptance of message {wanted}"
		));
	}
	if let Some(wanted) = &expected.recipient
		&& !asked_found.1
	{
		return Err(format!(
			"the bundle holds no acceptance for recipient {wanted}"
		));
	}
	if checked == 0 {
		return Err(format!(
			"the bundle holds no acceptance of {}",
			manifest.scope.describe()
		));
	}
	days.sort();
	let found = match (days.first(), days.last()) {
		(Some(first), Some(last)) => format!("acceptances on {} to {}", first.name(), last.name()),
		_ => String::new(),
	};
	Ok(match &manifest.scope {
		Scope::Message { .. } => format!(
			"scope: {}: every recipient was checked ({checked} acceptance, {found})",
			manifest.scope.describe()
		),
		Scope::Recipient { .. } => format!(
			"scope: {} ({checked} acceptances, {found}): the outcomes of the other recipients were NOT checked, and the bundle does not say whether they exist",
			manifest.scope.describe()
		),
	})
}
