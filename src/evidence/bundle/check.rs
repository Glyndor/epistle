//! `epistle evidence check <bundle>`: verify a bundle offline.
//!
//! Nothing here reads the server's configuration or data: only the bundle,
//! and the anchors the caller trusts: the timestamp authority keys (the
//! built-in default's, and any given with `--anchor`) and the evidence key
//! (`--key`). A key carried by the bundle is never trusted on its own word:
//! a day counts only when its signer is the anchored key, or took over from
//! it by a chain of hand-overs, each signed by the key before.

use std::collections::BTreeSet;
use std::io::BufReader;
use std::path::Path;

use super::anchor::{self, Anchors};
pub use super::manifest::Expectation;
use super::{BundleError, DayProof, MAX_FILE, MAX_RECORDS};
use crate::evidence::checkpoint::{CHECKPOINT_VERSION, Checkpoint};
use crate::evidence::day::Day;
use crate::evidence::key;
use crate::evidence::lines::{Line, Lines};
use crate::evidence::merkle::{leaf_hash, verify_inclusion};
use crate::evidence::record::{Entry, Record, hash_from_hex, sha256, to_hex};
use crate::evidence::rotation::Rotation;
use crate::evidence::tsa::{Check, Expected, Outcome};

/// One named check and its result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
	/// What was checked.
	pub name: String,
	/// `Ok` or why it failed.
	pub result: Result<(), String>,
}

/// Every check of a bundle.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CheckReport {
	/// The findings, in the order they were made.
	pub findings: Vec<Finding>,
	/// What was not checked, for the reader.
	pub notes: Vec<String>,
}

/// What the report says about revocation, always.
pub const REVOCATION_NOTE: &str = "revocation (CRL, OCSP) of the timestamp authority's certificates: not checked; they are judged valid at the stamped time";

impl CheckReport {
	/// Whether every check passed.
	pub fn passed(&self) -> bool {
		!self.findings.is_empty() && self.findings.iter().all(|finding| finding.result.is_ok())
	}

	fn add(&mut self, name: impl Into<String>, result: Result<(), String>) {
		self.findings.push(Finding {
			name: name.into(),
			result,
		});
	}
}

/// A regular file of the bundle, never through a link.
pub(super) fn read(path: &Path) -> Result<Vec<u8>, String> {
	match std::fs::symlink_metadata(path) {
		Ok(meta) if !meta.file_type().is_file() => return Err("not a regular file".into()),
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Err("missing".into()),
		Err(error) => return Err(format!("unreadable ({})", error.kind())),
		Ok(_) => {}
	}
	crate::evidence::checkpoint::read_bounded(path, MAX_FILE)
		.map_err(|error| format!("unreadable ({})", error.kind()))?
		.ok_or_else(|| "missing".to_string())
}

/// How long after a day ends its token may be dated: the audit's grace for a
/// missing token, plus a day for the seal itself.
const STAMP_WINDOW_SECS: u64 = crate::evidence::audit::TOKEN_GRACE_SECS + 86_400;

/// Check the bundle in `dir`, trusting the timestamp keys in `anchors` and
/// the evidence keys whose ids are in `keys`. Without a key the check
/// fails: a bundle cannot vouch for the key that signed it.
pub fn check(
	dir: &Path,
	anchors: &[[u8; 32]],
	keys: &[String],
) -> Result<CheckReport, BundleError> {
	check_expecting(dir, anchors, keys, &Expectation::default())
}

/// [`check`], also requiring the bundle to be about what the reader asked
/// for. A bundle's own manifest says what it covers but is not signed, so a
/// reader who knows which message or recipient the story is about says so.
pub fn check_expecting(
	dir: &Path,
	anchors: &[[u8; 32]],
	keys: &[String],
	expected: &Expectation,
) -> Result<CheckReport, BundleError> {
	let mut report = CheckReport::default();
	report.add(
		"SHA256SUMS lists every file, and every file matches",
		sums(dir),
	);
	let mut days = Vec::new();
	let checkpoints = dir.join("checkpoints");
	for entry in std::fs::read_dir(&checkpoints)? {
		let name = entry?.file_name();
		if let Some(day) = name
			.to_str()
			.and_then(|n| n.strip_suffix(".json"))
			.and_then(Day::parse)
		{
			days.push(day);
		}
	}
	days.sort();
	days.dedup();
	report.add(
		"the bundle holds at least one sealed day",
		match days.is_empty() {
			true => Err("no checkpoint".into()),
			false => Ok(()),
		},
	);
	let trust = Anchors::parse(keys);
	report.add(
		"the evidence key is anchored",
		trust.as_ref().map(|_| ()).map_err(Clone::clone),
	);
	let handovers = anchor::statements(dir);
	report.add(
		"every hand-over in the bundle is signed by the key it replaces",
		handovers.as_ref().map(|_| ()).map_err(Clone::clone),
	);
	let trusted = trust.is_ok() && handovers.is_ok();
	let (trust, handovers) = (trust.unwrap_or_default(), handovers.unwrap_or_default());
	let mut vouched = BTreeSet::new();
	for day in days {
		let before = report.findings.len();
		let files = check_day(dir, day, anchors, (&trust, &handovers), &mut report);
		// Only a day every one of whose checks passed vouches for its files.
		if trusted
			&& report.findings[before..]
				.iter()
				.all(|finding| finding.result.is_ok())
		{
			vouched.extend(files);
		}
	}
	let scope = super::manifest::complete(dir, expected);
	if let Ok(words) = &scope {
		report.notes.push(words.clone());
	}
	report.add("every message is accounted for", scope.map(|_| ()));
	report.add(
		"every file belongs to a verified day or an accepted record",
		strays(dir, &vouched),
	);
	report.notes.push(REVOCATION_NOTE.into());
	Ok(report)
}

fn sums(dir: &Path) -> Result<(), String> {
	let listed = String::from_utf8(read(&dir.join(super::sums::FILE))?)
		.map_err(|_| "not text".to_string())?;
	let mut names = BTreeSet::new();
	for line in listed.lines() {
		if names.len() >= super::MAX_FILES {
			return Err("more files than a bundle holds".into());
		}
		let (hash, name) = line
			.split_once("  ")
			.ok_or("a line is not `<hash>  <file>`")?;
		if name.contains("..") || name.starts_with('/') {
			return Err(format!("{name}: not a path inside the bundle"));
		}
		let bytes = read(&dir.join(name)).map_err(|why| format!("{name}: {why}"))?;
		if to_hex(&sha256(&bytes)) != hash {
			return Err(format!("{name}: does not match its checksum"));
		}
		if !names.insert(name.to_string()) {
			return Err(format!("{name}: listed twice"));
		}
	}
	for file in super::export::relative_files(dir).map_err(|error| error.kind().to_string())? {
		let name = file.to_string_lossy().to_string();
		if name != super::sums::FILE && !names.contains(name.as_str()) {
			return Err(format!("{name}: not listed"));
		}
	}
	Ok(())
}

/// The bundle-relative paths a verified day accounts for.
type Files = Vec<String>;

/// The files nothing vouched for: everything below the bundle's root except
/// its README and its checksum list, whatever the checksum list says.
/// Links and other special files count, listed or not.
fn strays(dir: &Path, vouched: &BTreeSet<String>) -> Result<(), String> {
	let mut pending = vec![(dir.to_path_buf(), String::new(), 0usize)];
	let mut seen = 0usize;
	let mut stray = BTreeSet::new();
	while let Some((path, prefix, depth)) = pending.pop() {
		for entry in std::fs::read_dir(&path).map_err(|error| error.kind().to_string())? {
			let entry = entry.map_err(|error| error.kind().to_string())?;
			seen += 1;
			if seen > super::MAX_FILES {
				return Err("more files than a bundle holds".into());
			}
			let name = format!("{prefix}{}", entry.file_name().to_string_lossy());
			let kind = entry
				.file_type()
				.map_err(|error| error.kind().to_string())?;
			if kind.is_dir() {
				if depth >= 2 {
					return Err(format!("{name}: nested deeper than a bundle goes"));
				}
				pending.push((entry.path(), format!("{name}/"), depth + 1));
			} else if !vouched.contains(&name)
				&& !["README.md", super::sums::FILE, super::manifest::FILE].contains(&name.as_str())
			{
				stray.insert(name);
			}
		}
	}
	// The first in name order, so the message does not depend on the disk.
	match stray.first() {
		None => Ok(()),
		Some(first) if stray.len() == 1 => Err(format!("{first}: not vouched for by any check")),
		Some(first) => Err(format!(
			"{first}: not vouched for by any check (and {} more)",
			stray.len() - 1
		)),
	}
}

fn check_day(
	dir: &Path,
	day: Day,
	anchors: &[[u8; 32]],
	(trust, handovers): (&Anchors, &[Rotation]),
	report: &mut CheckReport,
) -> Files {
	let name = day.name();
	let base = dir.join("checkpoints").join(&name);
	let json = match read(&base.with_extension("json")) {
		Ok(json) => json,
		Err(why) => {
			report.add(format!("{name}: checkpoint"), Err(why));
			return Files::new();
		}
	};
	let checkpoint: Checkpoint = match serde_json::from_slice(&json) {
		Ok(checkpoint) => checkpoint,
		Err(_) => {
			report.add(
				format!("{name}: checkpoint"),
				Err("not a checkpoint".into()),
			);
			return Files::new();
		}
	};
	report.add(format!("{name}: checkpoint version and day"), {
		if checkpoint.v != CHECKPOINT_VERSION || checkpoint.day != name {
			Err("unknown version, or another day".into())
		} else {
			Ok(())
		}
	});
	report.add(
		format!("{name}: signed by the evidence key it names"),
		signature(dir, &base, &checkpoint, &json),
	);
	let followed = anchor::vouch(&checkpoint.key, day, trust, handovers);
	report.add(
		format!("{name}: the signing key is the anchored key or took over from it"),
		followed.as_ref().map(|_| ()).map_err(Clone::clone),
	);
	let hand_overs = followed.unwrap_or_default();
	if checkpoint.timestamp == "enabled" {
		timestamp(dir, &base, &name, day, &json, anchors, report);
	} else {
		report.add(
			format!("{name}: timestamp token"),
			Err("timestamps were disabled: the day rests on the evidence key alone".into()),
		);
	}
	let included = inclusion(dir, &name, &checkpoint);
	let mut files: Files = ["json", "sig", "tsr"]
		.iter()
		.map(|extension| format!("checkpoints/{name}.{extension}"))
		.collect();
	files.extend([
		format!("records/{name}.jsonl"),
		format!("proofs/{name}.json"),
		format!("tsa/{name}-chain.pem"),
		format!("keys/{}.pem", checkpoint.key),
	]);
	files.extend(hand_overs);
	if let Ok(messages) = &included {
		files.extend(messages.iter().map(|id| format!("messages/{id}.eml")));
	}
	report.add(
		format!("{name}: every record is included under the signed root"),
		included.map(|_| ()),
	);
	files
}

fn signature(dir: &Path, base: &Path, checkpoint: &Checkpoint, json: &[u8]) -> Result<(), String> {
	// The id names a file: only a hex hash may.
	if hash_from_hex(&checkpoint.key).is_none() {
		return Err("the checkpoint names a key that is not a key id".into());
	}
	let pem = read(&dir.join("keys").join(format!("{}.pem", checkpoint.key)))?;
	let public = std::str::from_utf8(&pem)
		.ok()
		.and_then(key::parse_public_pem)
		.ok_or("the key file is not an Ed25519 public key")?;
	if key::key_id(&public) != checkpoint.key {
		return Err("the key file is not the key the checkpoint names".into());
	}
	let signature = read(&base.with_extension("sig"))?;
	match key::verify(&public, json, &signature) {
		true => Ok(()),
		false => Err("the signature does not verify".into()),
	}
}

fn timestamp(
	dir: &Path,
	base: &Path,
	name: &str,
	day: Day,
	json: &[u8],
	anchors: &[[u8; 32]],
	report: &mut CheckReport,
) {
	let token = match read(&base.with_extension("tsr")) {
		Ok(token) => token,
		Err(why) => return report.add(format!("{name}: timestamp token"), Err(why)),
	};
	let expected = Expected {
		digest: &sha256(json),
		nonce: None,
		anchors,
		policy: None,
	};
	let checked = match crate::evidence::tsa::check(&token, &expected) {
		Ok(checked) => checked,
		Err(error) => {
			return report.add(format!("{name}: timestamp token"), Err(error.to_string()));
		}
	};
	for (check, outcome) in &checked.checks {
		if *check == Check::Nonce {
			continue;
		}
		let result = match outcome {
			Outcome::Passed | Outcome::NotApplicable => Ok(()),
			Outcome::Failed(why) => Err((*why).to_string()),
		};
		report.add(format!("{name}: timestamp {}", check.label()), result);
	}
	// The README tells the reader to verify with this file as the untrusted
	// intermediates: it must be what the token carries, not what a re-sum
	// of SHA256SUMS lets through.
	report.add(
		format!("{name}: the certificate chain file is the one the token carries"),
		match (
			read(&dir.join("tsa").join(format!("{name}-chain.pem"))),
			super::token_chain_pem(&token),
		) {
			(Ok(file), Ok(carried)) if file == carried.as_bytes() => Ok(()),
			(Err(why), _) => Err(why),
			_ => Err("differs from the certificates in the token".into()),
		},
	);
	report.add(
		format!("{name}: stamped after the day ended"),
		match checked.gen_time >= Day(day.0 + 1).start_epoch() {
			true => Ok(()),
			false => Err("the token predates the end of the day".into()),
		},
	);
	// A key holder can re-sign a day long afterwards and have it stamped
	// then; only a token close to the day vouches for when it was sealed.
	report.add(
		format!("{name}: stamped within days of the day ending"),
		match checked.gen_time <= Day(day.0 + 1).start_epoch() + STAMP_WINDOW_SECS {
			true => Ok(()),
			false => Err(
				"the token was issued long after the day ended: it shows when the day was sealed, not when its mail was sent"
					.into(),
			),
		},
	);
}

/// Check every record of the day against the signed root; returns the
/// spool ids of the acceptances whose kept message is in the bundle.
fn inclusion(dir: &Path, name: &str, checkpoint: &Checkpoint) -> Result<Vec<uuid::Uuid>, String> {
	let proof: DayProof =
		serde_json::from_slice(&read(&dir.join("proofs").join(format!("{name}.json")))?)
			.map_err(|_| "the proof file is malformed".to_string())?;
	if proof.tree_size != checkpoint.records || proof.merkle_root != checkpoint.merkle_root {
		return Err("the proof file does not match the checkpoint".into());
	}
	let root = hash_from_hex(&checkpoint.merkle_root).ok_or("bad root")?;
	let path = dir.join("records").join(format!("{name}.jsonl"));
	if !std::fs::symlink_metadata(&path).is_ok_and(|meta| meta.file_type().is_file()) {
		return Err("the records file is missing or not a regular file".into());
	}
	let file = std::fs::File::open(&path).map_err(|error| error.kind().to_string())?;
	let mut lines = Lines::new(BufReader::new(file));
	let mut entries = proof.entries.iter();
	let mut count = 0usize;
	let mut kept_messages = Vec::new();
	while let Some((number, line)) = lines
		.next_line()
		.map_err(|error| error.kind().to_string())?
	{
		count += 1;
		if count > MAX_RECORDS {
			return Err("more records than a bundle holds".into());
		}
		let Line::Complete(bytes) = line else {
			return Err(format!("record {number}: not a complete line"));
		};
		let record =
			Record::parse_canonical(bytes).map_err(|why| format!("record {number}: {why}"))?;
		if Day::of_epoch(record.time).name() != name {
			return Err(format!("record {number}: not of this day"));
		}
		let entry = entries.next().ok_or(format!("record {number}: no proof"))?;
		let hash = sha256(bytes);
		let path: Vec<[u8; 32]> = entry
			.proof
			.iter()
			.filter_map(|hex| hash_from_hex(hex))
			.collect();
		if to_hex(&hash) != entry.sha256
			|| path.len() != entry.proof.len()
			|| !verify_inclusion(
				entry.index,
				checkpoint.records,
				&leaf_hash(&hash),
				&path,
				&root,
			) {
			return Err(format!(
				"record {number}: not included under the signed root"
			));
		}
		if let Entry::Accepted(accepted) = &record.entry {
			let kept = dir
				.join("messages")
				.join(format!("{}.eml", accepted.spool_id));
			if std::fs::symlink_metadata(&kept).is_ok() {
				if to_hex(&sha256(&read(&kept)?)) != accepted.sha256 {
					return Err(format!(
						"message {}: does not match its record",
						accepted.spool_id
					));
				}
				kept_messages.push(accepted.spool_id);
			}
		}
	}
	if entries.next().is_some() {
		return Err("a proof has no record".into());
	}
	Ok(kept_messages)
}
