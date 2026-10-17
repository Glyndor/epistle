//! `epistle evidence export`: the records of one message or one recipient,
//! with everything a third party needs to check them without the server.

use std::collections::{BTreeMap, BTreeSet};
use std::io::BufReader;
use std::path::{Path, PathBuf};

use uuid::Uuid;

use super::{BundleError, MAX_RECORDS, MAX_SCAN_DAYS, write_file};
use crate::evidence::chain::{CHAIN_DIR, Chain, day_file, open_day};
use crate::evidence::checkpoint::{self, files};
use crate::evidence::day::Day;
use crate::evidence::lines::{Line, Lines};
use crate::evidence::merkle::{TreeBuilder, leaf_hash};
use crate::evidence::record::{Entry, Record, RetentionMode, sha256, to_hex};
use crate::storage::MessageCrypto;

/// Which records to export.
#[derive(Debug, Clone)]
pub enum Selector {
	/// One message, by its `Message-ID` (exact, as recorded).
	MessageId(String),
	/// Every message to one recipient accepted between two days.
	Recipient {
		/// The recipient address (case-insensitive).
		address: String,
		/// First day of acceptance.
		from: Day,
		/// Last day of acceptance.
		to: Day,
	},
}

/// What an export wrote.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Exported {
	/// The messages in the bundle.
	pub messages: Vec<Uuid>,
	/// Records written.
	pub records: usize,
	/// Days whose records could not be included because they are not
	/// sealed yet.
	pub unsealed: Vec<Day>,
}

/// Outcomes can arrive up to the queue's give-up window after acceptance.
const OUTCOME_DAYS: i64 = 7;

/// Export what `selector` names from `evidence_root` into `out`, a
/// directory that must not exist yet and whose parent must. The directory is
/// created by one call that fails when anything, a link included, is already
/// there, so a path planted between a check and the creation is not followed.
pub fn export(
	evidence_root: &Path,
	crypto: &MessageCrypto,
	selector: &Selector,
	out: &Path,
) -> Result<Exported, BundleError> {
	let days = Chain::open(evidence_root)?.days()?;
	let (first, last) = match selector {
		Selector::MessageId(_) => (days.first().copied(), days.last().copied()),
		Selector::Recipient { from, to, .. } => (Some(*from), Some(Day(to.0 + OUTCOME_DAYS))),
	};
	let (Some(first), Some(last)) = (first, last) else {
		return Err(BundleError::Refused("no evidence matches".into()));
	};
	let span: Vec<Day> = days
		.into_iter()
		.filter(|day| *day >= first && *day <= last)
		.collect();
	if span.len() > MAX_SCAN_DAYS {
		return Err(BundleError::Refused(format!(
			"narrow the range: at most {MAX_SCAN_DAYS} days are scanned"
		)));
	}
	let mut picked: BTreeMap<Day, Vec<(u64, Vec<u8>)>> = BTreeMap::new();
	let mut spool_ids: BTreeSet<Uuid> = BTreeSet::new();
	let mut kept: Vec<(Uuid, Day, u32, String)> = Vec::new();
	let mut accepted: Vec<(Uuid, Day)> = Vec::new();
	let mut total = 0usize;
	for day in &span {
		scan_day(
			evidence_root,
			*day,
			selector,
			&mut spool_ids,
			|index, record, line| {
				// Past the cap nothing more is held in memory; the export fails below.
				total += 1;
				if total > MAX_RECORDS {
					return;
				}
				if let Entry::Accepted(made) = &record.entry {
					accepted.push((made.spool_id, *day));
					if made.retention.mode == RetentionMode::Full {
						kept.push((
							made.spool_id,
							*day,
							made.retention.days,
							made.sha256.clone(),
						));
					}
				}
				picked.entry(*day).or_default().push((index, line.to_vec()));
			},
		)?;
		if total > MAX_RECORDS {
			return Err(BundleError::Refused(format!(
				"narrow the selection: at most {MAX_RECORDS} records go in one bundle"
			)));
		}
	}
	if spool_ids.is_empty() {
		return Err(BundleError::Refused("no evidence matches".into()));
	}
	super::create_root(out)?;
	let mut done = Exported::default();
	let mut keys: BTreeSet<String> = BTreeSet::new();
	let mut written: BTreeSet<Day> = BTreeSet::new();
	for (day, lines) in &picked {
		let Some((checkpoint, json)) = checkpoint::load(evidence_root, *day)? else {
			done.unsealed.push(*day);
			continue;
		};
		write_day(evidence_root, out, *day, lines, &checkpoint, &json)?;
		keys.insert(checkpoint.key.clone());
		done.records += lines.len();
		written.insert(*day);
	}
	write_keys(evidence_root, out, keys)?;
	// Only what the bundle covers is named or carried: a message of a day
	// that is not sealed yet is neither.
	done.messages = accepted
		.iter()
		.filter(|(_, day)| written.contains(day))
		.map(|(id, _)| *id)
		.collect();
	for (id, day, days, digest) in kept
		.into_iter()
		.filter(|(_, day, _, _)| written.contains(day))
	{
		let stored = find_kept(evidence_root, id, day, days)?;
		let bytes = if stored.starts_with(crate::storage::MAGIC) {
			crypto
				.decode_with_aad(&stored, id.as_bytes())
				.map_err(|_| BundleError::Refused("a kept message cannot be decrypted".into()))?
		} else {
			stored
		};
		if to_hex(&sha256(&bytes)) != digest {
			return Err(BundleError::Refused(
				"a kept message does not match its record".into(),
			));
		}
		write_file(&out.join("messages").join(format!("{id}.eml")), &bytes)?;
	}
	super::manifest::write(out, selector)?;
	super::readme::write(out, &done)?;
	super::sums::write(out)?;
	Ok(done)
}

/// The bytes of the message kept for `id`: under the day of its record or,
/// when the clock that kept it read the next or the previous one across
/// midnight, under that. A message recorded as kept and not there stops the
/// export: a bundle must not say less than the log does.
fn find_kept(evidence_root: &Path, id: Uuid, day: Day, days: u32) -> Result<Vec<u8>, BundleError> {
	for candidate in [day, Day(day.0 + 1), Day(day.0 - 1)] {
		let path = evidence_root
			.join(crate::evidence::service::MESSAGES_DIR)
			.join(candidate.name())
			.join(days.to_string())
			.join(format!("{id}.eml"));
		match crate::evidence::checkpoint::read_bounded(&path, super::MAX_FILE) {
			Ok(Some(stored)) => return Ok(stored),
			Ok(None) => {}
			Err(error) => return Err(error.into()),
		}
	}
	Err(BundleError::Refused(format!(
		"the message {id} is recorded as kept and is not in the evidence directory"
	)))
}

/// A small file of the evidence directory (a key, a signature, a statement):
/// refused when it is larger than any of them, missing when it is not there.
fn read_small(path: &Path) -> std::io::Result<Vec<u8>> {
	crate::evidence::checkpoint::read_bounded(path, 256 * 1024)?
		.ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
}

/// Write the public keys that signed the exported days and, for each, the
/// signed hand-overs back to the oldest key they lead to, with the keys they
/// name: what a reader needs to follow a signer to a key it anchored.
fn write_keys(
	evidence_root: &Path,
	out: &Path,
	signers: BTreeSet<String>,
) -> Result<(), BundleError> {
	use crate::evidence::rotation;
	let mut keys = signers.clone();
	let mut statements = BTreeSet::new();
	for signer in &signers {
		for rotation in rotation::ancestry(evidence_root, signer) {
			keys.insert(rotation.old.clone());
			keys.insert(rotation.new.clone());
			statements.insert(rotation.new);
		}
	}
	for key in keys {
		let pem = read_small(&crate::evidence::key::public_key_path(evidence_root, &key))?;
		write_file(&out.join("keys").join(format!("{key}.pem")), &pem)?;
	}
	for new in statements {
		let bytes = read_small(&rotation::path(evidence_root, &new))?;
		write_file(
			&out.join("keys")
				.join("rotations")
				.join(format!("{new}.json")),
			&bytes,
		)?;
	}
	Ok(())
}

/// Call `pick` with each record of `day` the selector wants, with its
/// 0-based index and its line, and collect the spool ids it names.
fn scan_day(
	evidence_root: &Path,
	day: Day,
	selector: &Selector,
	spool_ids: &mut BTreeSet<Uuid>,
	mut pick: impl FnMut(u64, &Record, &[u8]),
) -> Result<(), BundleError> {
	let file = open_day(&day_file(&evidence_root.join(CHAIN_DIR), day))?;
	let mut lines = Lines::new(BufReader::new(file));
	while let Some((number, line)) = lines.next_line()? {
		let Line::Complete(bytes) = line else {
			continue;
		};
		let Ok(record) = Record::parse_canonical(bytes) else {
			continue;
		};
		let wanted = match (&record.entry, selector) {
			(Entry::Accepted(accepted), Selector::MessageId(id)) => {
				accepted.message_id.as_deref() == Some(id.as_str())
			}
			(Entry::Accepted(accepted), Selector::Recipient { address, from, to }) => {
				day >= *from
					&& day <= *to && accepted
					.recipients
					.iter()
					.any(|r| r.eq_ignore_ascii_case(address))
			}
			(Entry::Outcome(outcome), Selector::Recipient { address, .. }) => {
				spool_ids.contains(&outcome.spool_id)
					&& outcome.recipient.eq_ignore_ascii_case(address)
			}
			(entry, _) => entry.spool_id().is_some_and(|id| spool_ids.contains(&id)),
		};
		if wanted {
			if let Entry::Accepted(accepted) = &record.entry {
				spool_ids.insert(accepted.spool_id);
			}
			pick(number - 1, &record, bytes);
		}
	}
	Ok(())
}

/// Write the picked lines of `day`, their inclusion proofs, the checkpoint
/// with its signature and token, and the token's certificate chain.
fn write_day(
	evidence_root: &Path,
	out: &Path,
	day: Day,
	lines: &[(u64, Vec<u8>)],
	checkpoint: &checkpoint::Checkpoint,
	json: &[u8],
) -> Result<(), BundleError> {
	let targets: Vec<u64> = lines.iter().map(|(index, _)| *index).collect();
	let mut tree = TreeBuilder::for_proofs(checkpoint.records, &targets);
	let file = open_day(&day_file(&evidence_root.join(CHAIN_DIR), day))?;
	let mut reader = Lines::new(BufReader::new(file));
	while let Some((_, line)) = reader.next_line()? {
		if let Line::Complete(bytes) = line {
			tree.push(leaf_hash(&sha256(bytes)));
		}
	}
	let (root, proofs) = tree.finish(&targets);
	if to_hex(&root) != checkpoint.merkle_root {
		return Err(BundleError::Refused(format!(
			"{day}: the records no longer match their checkpoint: run epistle evidence verify"
		)));
	}
	let mut records = Vec::new();
	let mut proof_entries = Vec::new();
	for (index, line) in lines {
		records.extend_from_slice(line);
		records.push(b'\n');
		proof_entries.push(super::ProofEntry {
			index: *index,
			sha256: to_hex(&sha256(line)),
			proof: proofs
				.get(index)
				.map(|path| path.iter().map(|hash| to_hex(hash)).collect())
				.unwrap_or_default(),
		});
	}
	let name = day.name();
	write_file(&out.join("records").join(format!("{name}.jsonl")), &records)?;
	let proof = super::DayProof {
		day: name.clone(),
		tree_size: checkpoint.records,
		merkle_root: checkpoint.merkle_root.clone(),
		entries: proof_entries,
	};
	let proof_json = serde_json::to_vec_pretty(&proof).map_err(std::io::Error::other)?;
	write_file(
		&out.join("proofs").join(format!("{name}.json")),
		&proof_json,
	)?;
	let paths = files(evidence_root, day);
	write_file(&out.join("checkpoints").join(format!("{name}.json")), json)?;
	write_file(
		&out.join("checkpoints").join(format!("{name}.sig")),
		&read_small(&paths.sig)?,
	)?;
	if let Ok(Some(token)) = crate::evidence::checkpoint::read_bounded(
		&paths.tsr,
		crate::evidence::tsa::token::MAX_RESPONSE as u64,
	) {
		write_file(&out.join("checkpoints").join(format!("{name}.tsr")), &token)?;
		if let Ok(chain) = super::token_chain_pem(&token) {
			write_file(
				&out.join("tsa").join(format!("{name}-chain.pem")),
				chain.as_bytes(),
			)?;
		}
	}
	Ok(())
}

/// The bundle's files, relative to its root, for the checksum list.
pub(super) fn relative_files(out: &Path) -> std::io::Result<Vec<PathBuf>> {
	let mut found = Vec::new();
	let mut pending = vec![out.to_path_buf()];
	let mut directories = 0usize;
	while let Some(dir) = pending.pop() {
		for entry in std::fs::read_dir(&dir)? {
			let entry = entry?;
			let kind = entry.file_type()?;
			if kind.is_dir() {
				// Empty ones count as well: they are work and memory too.
				directories += 1;
				if directories > super::MAX_FILES {
					return Err(std::io::Error::other("too many files in the bundle"));
				}
				pending.push(entry.path());
			} else if kind.is_file()
				&& let Ok(relative) = entry.path().strip_prefix(out)
			{
				found.push(relative.to_path_buf());
			}
		}
		if found.len() > super::MAX_FILES {
			return Err(std::io::Error::other("too many files in the bundle"));
		}
	}
	found.sort();
	Ok(found)
}
