//! Purge statements and acknowledgements across a key rotation.

use super::tests::{DAY, short_lived, verified};
use super::*;
use crate::evidence::test_support::at;

#[test]
fn a_purge_after_a_rotation_must_be_signed_by_the_key_in_force() {
	let (dir, old, tsa, _chain) = short_lived();
	crate::evidence::rotation::rotate(dir.path(), true, at(DAY + 5, 1)).expect("rotate");
	let new = EvidenceKey::load_or_create(dir.path()).expect("current key");
	assert_ne!(new.id(), old.id());
	// The same purge, statement signed by the key that handed over.
	let swept = sweep(dir.path(), &old, &[tsa.anchor], at(DAY + 5, 12)).expect("sweep");
	assert_eq!(swept.days, 3, "{:?}", swept.refused);
	let report = verified(dir.path(), &tsa, at(DAY + 5, 13));
	assert_eq!(
		report
			.first_break
			.map(|at| crate::evidence::audit::tests::plain(at.to_string()))
			.as_deref(),
		Some(
			"2026-10-19 line 2: checkpoint: the purge statement was not signed by the evidence key in force"
		)
	);
}

#[test]
fn a_purge_after_a_rotation_signed_by_the_key_in_force_verifies() {
	let (dir, _old, tsa, _chain) = short_lived();
	crate::evidence::rotation::rotate(dir.path(), true, at(DAY + 5, 1)).expect("rotate");
	let new = EvidenceKey::load_or_create(dir.path()).expect("current key");
	let swept = sweep(dir.path(), &new, &[tsa.anchor], at(DAY + 5, 12)).expect("sweep");
	assert_eq!(swept.days, 3, "{:?}", swept.refused);
	assert_eq!(
		verified(dir.path(), &tsa, at(DAY + 5, 13)).first_break,
		None
	);
}

#[test]
fn acknowledging_a_purge_statement_break_does_not_cover_a_change_in_its_files() {
	use crate::evidence::ack::{Operator, acknowledge_at};
	for file in ["json", "sig"] {
		let (dir, key, tsa, _chain) = short_lived();
		let swept = sweep(dir.path(), &key, &[tsa.anchor], at(DAY + 5, 12)).expect("sweep");
		assert_eq!(swept.days, 3, "{:?}", swept.refused);
		let path = dir
			.path()
			.join(PURGES_DIR)
			.join(format!("{}.json", Day(DAY + 2).name()));
		// The statement edited: the record no longer names it.
		let edited = std::fs::read_to_string(&path)
			.expect("read")
			.replace("\"records\": 3", "\"records\": 2");
		std::fs::write(&path, edited).expect("write");
		let first = verified(dir.path(), &tsa, at(DAY + 5, 13))
			.first_break
			.expect("a break");
		acknowledge_at(
			dir.path(),
			&key,
			&first,
			"edited by hand",
			&Operator::named("uid=0 host=mail"),
			at(DAY + 5, 14),
		)
		.expect("acknowledge");
		assert_eq!(
			verified(dir.path(), &tsa, at(DAY + 5, 15)).first_break,
			None
		);
		// The same break, with another file under it.
		let other = path.with_extension(file);
		let mut bytes = std::fs::read(&other).expect("read");
		bytes.push(b' ');
		std::fs::write(&other, bytes).expect("write");
		let second = verified(dir.path(), &tsa, at(DAY + 5, 16))
			.first_break
			.unwrap_or_else(|| panic!("{file}: the old acknowledgement covers the new state"));
		assert_ne!(second.to_string(), first.to_string(), "{file}");
	}
}
