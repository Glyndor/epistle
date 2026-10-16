//! A key that handed over cannot seal a day after the hand-over, whoever
//! holds it and whichever key the reader anchored.

use super::tests::{exported, failures, resum};
use super::*;
use crate::evidence::audit::tests::{DAY, Fixture};
use crate::evidence::chain::Chain;
use crate::evidence::checkpoint::{files, seal_closed_days};
use crate::evidence::day::Day;
use crate::evidence::key::EvidenceKey;
use crate::evidence::record::sha256;
use crate::evidence::rotation::rotate;
use crate::evidence::test_support::{accepted, at};
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
	let k2 = rotate(fixture.root(), true, at(DAY + 3, 5)).expect("rotate");
	let current = EvidenceKey::load_or_create(fixture.root()).expect("k2");
	let Fixture { dir, tsa, .. } = &mut fixture;
	stamp(dir.path(), tsa, &current, at(DAY + 4, 0));
	(fixture, k1, k2, leaked)
}

/// A directory that holds only the leaked K1 and signs a day that never
/// existed, the day after the rotation.
fn forged(leaked: &[u8]) -> (Fixture, Selector) {
	let evil = tempfile::tempdir().expect("evil");
	std::fs::write(evil.path().join("key.pk8"), leaked).expect("plant");
	let key = EvidenceKey::load_or_create(evil.path()).expect("k1 again");
	Chain::open(evil.path())
		.expect("chain")
		.append_at(at(DAY + 4, 1), accepted(99))
		.expect("forged acceptance");
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
	let report = check(&bundle, &[evil.tsa.anchor], &[k1.clone()]).expect("check");
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
