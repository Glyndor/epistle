//! The per-day proofs of a bundle: signature, timestamp and inclusion.

use super::*;

pub(super) fn signature(
	dir: &Path,
	base: &Path,
	checkpoint: &Checkpoint,
	json: &[u8],
) -> Result<(), String> {
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

pub(super) fn timestamp(
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
			super::super::token_chain_pem(&token),
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
pub(super) fn inclusion(
	dir: &Path,
	name: &str,
	checkpoint: &Checkpoint,
) -> Result<Vec<uuid::Uuid>, String> {
	let proof: DayProof = serde_json::from_slice(&read_up_to(
		&dir.join("proofs").join(format!("{name}.json")),
		super::super::MAX_PROOF_FILE,
	)?)
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
	let mut last_index: Option<u64> = None;
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
		if Some(Day::of_epoch(record.time)) != Day::parse(name) {
			return Err(format!("record {number}: not of this day"));
		}
		let entry = entries.next().ok_or(format!("record {number}: no proof"))?;
		// The records come in the order of the day: a bundle whose proofs
		// run backwards, or repeat, is arranged to be read another way.
		if last_index.is_some_and(|last| entry.index <= last) {
			return Err(format!(
				"record {number}: its place in the day does not come after the record before it"
			));
		}
		last_index = Some(entry.index);
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
