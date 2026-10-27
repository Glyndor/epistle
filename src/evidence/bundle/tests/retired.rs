//! A key that handed over cannot seal a day after the hand-over, whoever
//! holds it and whichever key the reader anchored.

use super::base::{exported, failures, resum};
use super::*;
use crate::evidence::audit::tests::base::{DAY, Fixture};
use crate::evidence::chain::Chain;
use crate::evidence::checkpoint::{files, seal_closed_days};
use crate::evidence::day::Day;
use crate::evidence::key::EvidenceKey;
use crate::evidence::record::sha256;
use crate::evidence::rotation::rotate_at;
use crate::evidence::test_support::{accepted, at, delivered};
use crate::evidence::tsa::fake::FakeTsa;
use crate::evidence::tsa::request::{build, random_nonce};

/// The day of the hand-over, as the statement names it.
const R: &str = "2026-10-17";

fn selector(n: u32) -> Selector {
	Selector::MessageId(format!("<{n}@example.org>"))
}

fn stamp(root: &std::path::Path, tsa: &mut FakeTsa, key: &EvidenceKey, now: u64) {
	seal_closed_days(root, key, true, now).expect("seal");
	tsa.gen_time = now + 3600;
	for offset in 0..8 {
		let paths = files(root, Day(DAY + offset));
		if paths.json.exists() && !paths.tsr.exists() {
			let json = std::fs::read(&paths.json).expect("json");
			std::fs::write(
				&paths.tsr,
				tsa.respond(&build(&sha256(&json), random_nonce()).der),
			)
			.expect("tsr");
		}
	}
}

/// A server that signed with K1 until the rotation on `R`, then with K2.
fn rotated() -> (Fixture, String, String, Vec<u8>) {
	let mut fixture = Fixture::new();
	let k1 = fixture.key.id();
	// What leaks while K1 is still in force.
	let leaked = std::fs::read(fixture.root().join("key.pk8")).expect("pk8");
	Chain::open(fixture.root())
		.expect("chain")
		.append_at(at(DAY + 3, 1), accepted(7))
		.expect("append");
	Chain::open(fixture.root())
		.expect("chain")
		.append_at(at(DAY + 3, 2), delivered(7))
		.expect("outcome");
	let k2 = rotate_at(fixture.root(), at(DAY + 3, 5)).expect("rotate");
	let current = EvidenceKey::load_or_create(fixture.root()).expect("k2");
	let Fixture { dir, tsa, .. } = &mut fixture;
	stamp(dir.path(), tsa, &current, at(DAY + 4, 0));
	(fixture, k1, k2, leaked)
}

/// A directory that holds only the leaked K1 and signs a day that never
/// existed, the day after the rotation.
fn forged(leaked: &[u8]) -> (Fixture, Selector) {
	let evil = tempfile::tempdir().expect("evil");
	crate::storage::write_secret(&evil.path().join("key.pk8"), leaked).expect("plant");
	let key = EvidenceKey::load_or_create(evil.path()).expect("k1 again");
	Chain::open(evil.path())
		.expect("chain")
		.append_at(at(DAY + 4, 1), accepted(99))
		.expect("forged acceptance");
	Chain::open(evil.path())
		.expect("chain")
		.append_at(at(DAY + 4, 2), delivered(99))
		.expect("outcome");
	let mut fixture = Fixture {
		dir: evil,
		key,
		tsa: FakeTsa::new(at(DAY + 5, 1)),
	};
	let Fixture { dir, tsa, key } = &mut fixture;
	stamp(dir.path(), tsa, key, at(DAY + 5, 0));
	(fixture, selector(99))
}

#[test]
fn a_retired_key_forging_a_recent_day_is_refused_with_both_keys_anchored() {
	let (_server, k1, k2, leaked) = rotated();
	let (evil, wanted) = forged(&leaked);
	let (_out, bundle) = exported(&evil, &wanted);
	// Bare, both keys look current: the reader must say which one ended.
	let bare = check(&bundle, &[evil.tsa.anchor], &[k1.clone(), k2.clone()]).expect("check");
	assert!(!bare.passed(), "{:?}", failures(&bare));
	assert_eq!(
		failures(&bare)[0],
		"the evidence key is anchored: give the period of every key but the current one (KEY@YYYY-MM-DD)"
	);
	// With its period, the retired key cannot seal the day after it.
	let timed = check(
		&bundle,
		&[evil.tsa.anchor],
		&[format!("{k1}@{R}"), k2.clone()],
	)
	.expect("check");
	assert!(
		failures(&timed).iter().any(|f| f.ends_with(&format!(
			"signed by key {k1} on 2026-10-18, but it was in force only until {R}"
		))),
		"{:?}",
		failures(&timed)
	);
}

#[test]
fn a_hand_over_in_the_bundle_retires_the_old_key_even_when_it_is_the_anchor() {
	let (server, k1, k2, leaked) = rotated();
	let (_out, genuine) = exported(&server, &selector(7));
	let (evil, wanted) = forged(&leaked);
	let (_out2, bundle) = exported(&evil, &wanted);
	// The forger keeps the public hand-over in the bundle.
	let name = format!("{k2}.json");
	std::fs::create_dir_all(bundle.join("keys/rotations")).expect("dir");
	std::fs::copy(
		genuine.join("keys/rotations").join(&name),
		bundle.join("keys/rotations").join(&name),
	)
	.expect("copy");
	std::fs::copy(
		genuine.join("keys").join(format!("{k2}.pem")),
		bundle.join("keys").join(format!("{k2}.pem")),
	)
	.expect("copy");
	resum(&bundle);
	let report = check(&bundle, &[evil.tsa.anchor], std::slice::from_ref(&k1)).expect("check");
	assert!(
		failures(&report).iter().any(|f| f.contains(&format!(
			"signed by key {k1} on 2026-10-18, but it handed over on {R}"
		))),
		"{:?}",
		failures(&report)
	);
}

#[test]
fn days_on_both_sides_of_the_hand_over_pass_with_the_period_given() {
	let (server, k1, k2, _) = rotated();
	let anchors = [server.tsa.anchor];
	let keys = [format!("{k1}@{R}"), k2.clone()];
	for n in [1, 7] {
		let (_out, bundle) = exported(&server, &selector(n));
		let report = check(&bundle, &anchors, &keys).expect("check");
		assert!(report.passed(), "message {n}: {:?}", failures(&report));
	}
	// The current key alone, bare, follows the hand-over back to nothing:
	// only the days it sealed pass.
	let (_out, bundle) = exported(&server, &selector(7));
	let report = check(&bundle, &anchors, &[k2]).expect("check");
	assert!(report.passed(), "{:?}", failures(&report));
}

#[test]
fn a_new_key_cannot_seal_a_day_before_the_day_it_took_over() {
	use crate::evidence::rotation::{ROTATIONS_DIR, Rotation, path};
	let mut fixture = Fixture::new();
	let old = EvidenceKey::load_or_create(fixture.root()).expect("k1");
	Chain::open(fixture.root())
		.expect("chain")
		.append_at(at(DAY + 3, 1), accepted(7))
		.expect("append");
	Chain::open(fixture.root())
		.expect("chain")
		.append_at(at(DAY + 3, 2), delivered(7))
		.expect("outcome");
	let new = EvidenceKey::stage_next(fixture.root()).expect("stage");
	// The hand-over is dated three days after the day the new key seals.
	let rotation = Rotation::signed(&old, &new.id(), "2026-10-20");
	crate::evidence::chain::create_private_dir(&fixture.root().join(ROTATIONS_DIR)).expect("dir");
	std::fs::write(
		path(fixture.root(), &new.id()),
		serde_json::to_vec(&rotation).expect("json"),
	)
	.expect("statement");
	EvidenceKey::promote_next(fixture.root(), &new.id()).expect("promote");
	let Fixture { dir, tsa, .. } = &mut fixture;
	stamp(dir.path(), tsa, &new, at(DAY + 4, 0));
	let (_out, bundle) = exported(&fixture, &selector(7));
	let report = check(&bundle, &[fixture.tsa.anchor], &[old.id()]).expect("check");
	assert!(
		failures(&report).iter().any(|f| f.ends_with(&format!(
			"signed by key {} on 2026-10-17, before it took over on 2026-10-20",
			new.id()
		))),
		"{:?}",
		failures(&report)
	);
}

/// A bundle of a day nobody sealed, made by whoever holds the leaked K1: its
/// own hand-over from K1 to a key of its own, dated `taken`, and a day
/// sealed by that key.
fn forged_by_a_successor_of_the_leaked_key(leaked: &[u8], taken: &str) -> (Fixture, Selector) {
	use crate::evidence::rotation::{ROTATIONS_DIR, Rotation, path};
	let evil = tempfile::tempdir().expect("evil");
	crate::storage::write_secret(&evil.path().join("key.pk8"), leaked).expect("plant");
	let k1 = EvidenceKey::load_or_create(evil.path()).expect("k1 again");
	let k3 = EvidenceKey::stage_next(evil.path()).expect("k3");
	crate::evidence::chain::create_private_dir(&evil.path().join(ROTATIONS_DIR)).expect("dir");
	std::fs::write(
		path(evil.path(), &k3.id()),
		serde_json::to_vec(&Rotation::signed(&k1, &k3.id(), taken)).expect("json"),
	)
	.expect("statement");
	EvidenceKey::promote_next(evil.path(), &k3.id()).expect("promote");
	Chain::open(evil.path())
		.expect("chain")
		.append_at(at(DAY + 4, 1), accepted(99))
		.expect("forged acceptance");
	Chain::open(evil.path())
		.expect("chain")
		.append_at(at(DAY + 4, 2), delivered(99))
		.expect("outcome");
	let mut fixture = Fixture {
		dir: evil,
		key: k3,
		tsa: FakeTsa::new(at(DAY + 5, 1)),
	};
	let Fixture { dir, tsa, key } = &mut fixture;
	stamp(dir.path(), tsa, key, at(DAY + 5, 0));
	(fixture, selector(99))
}

#[test]
fn an_anchor_with_a_period_cannot_hand_over_to_a_key_the_reader_did_not_anchor() {
	let (_server, k1, k2, leaked) = rotated();
	// Dated after the period, on it, and before it: none validates a key the
	// reader never named.
	for taken in ["2026-10-18", R, "2026-10-15"] {
		let (evil, wanted) = forged_by_a_successor_of_the_leaked_key(&leaked, taken);
		let (_out, bundle) = exported(&evil, &wanted);
		let report = check(
			&bundle,
			&[evil.tsa.anchor],
			&[format!("{k1}@{R}"), k2.clone()],
		)
		.expect("check");
		assert!(!report.passed(), "{taken}: the forged hand-over validated");
		assert!(
			failures(&report)
				.iter()
				.any(|f| f.contains("did not anchor")
					|| f.contains("names another day than the period")),
			"{taken}: {:?}",
			failures(&report)
		);
	}
}

#[test]
fn a_hand_over_dated_other_than_the_period_given_is_refused_even_to_an_anchored_key() {
	let (server, k1, k2, _) = rotated();
	let (_out, bundle) = exported(&server, &selector(7));
	// The reader says K1 ended a day later than the statement says.
	let report = check(
		&bundle,
		&[server.tsa.anchor],
		&[format!("{k1}@2026-10-18"), k2],
	)
	.expect("check");
	assert!(
		failures(&report)
			.iter()
			.any(|f| f.contains("names another day than the period")),
		"{:?}",
		failures(&report)
	);
}

#[test]
fn a_day_sealed_by_an_intermediate_key_after_its_period_fails() {
	let (mut server, k1, k2, _) = rotated();
	// K2 leaks, then hands over to K3 on the next day.
	let leaked_k2 = std::fs::read(server.root().join("key.pk8")).expect("k2");
	let k3 = rotate_at(server.root(), at(DAY + 4, 5)).expect("second rotation");
	let current = EvidenceKey::load_or_create(server.root()).expect("k3");
	let Fixture { dir, tsa, .. } = &mut server;
	stamp(dir.path(), tsa, &current, at(DAY + 5, 0));
	let (evil, wanted) = forged(&leaked_k2);
	let (_out, bundle) = exported(&evil, &wanted);
	let report = check(
		&bundle,
		&[evil.tsa.anchor],
		&[format!("{k1}@{R}"), format!("{k2}@2026-10-18"), k3],
	)
	.expect("check");
	assert!(
		failures(&report).iter().any(|f| f.contains(&format!(
			"signed by key {k2} on 2026-10-18, but it was in force only until 2026-10-18"
		))),
		"{:?}",
		failures(&report)
	);
}

#[test]
fn an_old_publication_and_the_current_key_validate_the_current_keys_days_without_the_ones_between()
{
	let (mut server, k1, _k2, _) = rotated();
	let k3 = rotate_at(server.root(), at(DAY + 4, 5)).expect("second rotation");
	let chain = Chain::open(server.root()).expect("chain");
	chain
		.append_at(at(DAY + 5, 1), accepted(8))
		.expect("accepted");
	chain
		.append_at(at(DAY + 5, 2), delivered(8))
		.expect("outcome");
	let current = EvidenceKey::load_or_create(server.root()).expect("k3");
	let Fixture { dir, tsa, .. } = &mut server;
	stamp(dir.path(), tsa, &current, at(DAY + 6, 0));
	let (_out, bundle) = exported(&server, &selector(8));
	// K1 from the publication of its day, the current key bare: K2 is not
	// among them. The day was sealed by K3, which the reader anchored.
	let report = check(
		&bundle,
		&[server.tsa.anchor],
		&[format!("{k1}@{R}"), k3.clone()],
	)
	.expect("check");
	assert!(report.passed(), "{:?}", failures(&report));
	// The current key alone passes the same bundle.
	let alone = check(&bundle, &[server.tsa.anchor], &[k3]).expect("check");
	assert!(alone.passed(), "{:?}", failures(&alone));
}
