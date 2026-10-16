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

use std::collections::BTreeMap;
use std::io::BufReader;
use std::path::Path;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::check::read;
use super::export::Selector;
use super::{MAX_FILES, MAX_RECORDS};
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
	accepted: Vec<Accepted>,
	abandoned: bool,
	outcomes: Vec<String>,
}

/// Check that every message in the bundle in `dir` is accounted for, for the
/// recipients its manifest names.
pub(super) fn complete(dir: &Path) -> Result<(), String> {
	let manifest: Manifest =
		serde_json::from_slice(&read(&dir.join(FILE)).map_err(|why| format!("{FILE}: {why}"))?)
			.map_err(|_| format!("{FILE}: not a manifest"))?;
	if manifest.v != VERSION {
		return Err(format!("{FILE}: unknown version"));
	}
	let mut held: BTreeMap<Uuid, Held> = BTreeMap::new();
	let mut total = 0usize;
	let entries =
		std::fs::read_dir(dir.join("records")).map_err(|error| error.kind().to_string())?;
	for (files, entry) in entries.enumerate() {
		if files >= MAX_FILES {
			return Err("more record files than a bundle holds".into());
		}
		let path = entry.map_err(|error| error.kind().to_string())?.path();
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
					.push(accepted),
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
	for (id, message) in &held {
		let [accepted] = message.accepted.as_slice() else {
			return Err(match message.accepted.is_empty() {
				true => format!("{id}: a record of this message is here without its acceptance"),
				false => format!("{id}: accepted more than once"),
			});
		};
		let covered: Vec<String> = match &manifest.scope {
			Scope::Message { .. } => accepted
				.recipients
				.iter()
				.map(|recipient| recipient.to_ascii_lowercase())
				.collect(),
			Scope::Recipient { address, .. } => vec![address.to_ascii_lowercase()],
		};
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
	Ok(())
}
