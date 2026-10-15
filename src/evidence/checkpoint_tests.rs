use super::*;
use crate::evidence::chain::Chain;
use crate::evidence::key::verify as verify_signature;
use crate::evidence::test_support::{accepted, accepted_for, at, delivered};

const DAY: i64 = 20_740;

fn two_days() -> (tempfile::TempDir, Vec<[u8; 32]>) {
	let dir = tempfile::tempdir().expect("tempdir");
	let chain = Chain::open(dir.path()).expect("open");
	let hashes = vec![
		chain
			.append_at(at(DAY, 1), accepted_for(1, 30))
			.expect("append"),
		chain.append_at(at(DAY, 2), delivered(1)).expect("append"),
		chain
			.append_at(at(DAY + 1, 3), accepted_for(2, 10))
			.expect("append"),
	];
	(dir, hashes)
}

#[test]
fn a_closed_day_is_sealed_with_its_root_hashes_and_signature() {
	let (dir, hashes) = two_days();
	let key = EvidenceKey::load_or_create(dir.path()).expect("key");
	let sealed = seal_closed_days(dir.path(), &key, true, at(DAY + 2, 0)).expect("seal");
	assert_eq!(sealed, vec![Day(DAY), Day(DAY + 1)]);
	let (first, first_bytes) = load(dir.path(), Day(DAY)).expect("load").expect("first");
	let mut tree = TreeBuilder::new();
	tree.push(leaf_hash(&hashes[0]));
	tree.push(leaf_hash(&hashes[1]));
	let (root, _) = tree.finish(&[]);
	assert_eq!(first.records, 2);
	assert_eq!(first.merkle_root, to_hex(&root));
	assert_eq!(first.first_prev, to_hex(&GENESIS));
	assert_eq!(first.last_hash, to_hex(&hashes[1]));
	assert_eq!(first.prev_checkpoint, None);
	assert_eq!(first.retain_until, Day(DAY + 365).name());
	assert_eq!(first.timestamp, "enabled");
	assert_eq!(first.key, key.id());
	let signature = std::fs::read(files(dir.path(), Day(DAY)).sig).expect("sig");
	assert!(verify_signature(
		&key.public_key(),
		&first_bytes,
		&signature
	));
	let (second, _) = load(dir.path(), Day(DAY + 1))
		.expect("load")
		.expect("second");
	assert_eq!(second.first_prev, to_hex(&hashes[1]));
	assert_eq!(second.prev_checkpoint, Some(to_hex(&sha256(&first_bytes))));
	assert_eq!(second.retain_until, Day(DAY + 1 + 10).name());
}

#[test]
fn today_is_not_sealed_and_sealing_twice_changes_nothing() {
	let (dir, _) = two_days();
	let key = EvidenceKey::load_or_create(dir.path()).expect("key");
	let sealed = seal_closed_days(dir.path(), &key, false, at(DAY + 1, 12)).expect("seal");
	assert_eq!(sealed, vec![Day(DAY)]);
	let before = std::fs::read(files(dir.path(), Day(DAY)).json).expect("json");
	let again = seal_closed_days(dir.path(), &key, false, at(DAY + 9, 0)).expect("seal");
	assert_eq!(again, vec![Day(DAY + 1)]);
	let after = std::fs::read(files(dir.path(), Day(DAY)).json).expect("json");
	assert!(before == after, "an existing checkpoint was rewritten");
}

#[test]
fn a_broken_day_is_not_sealed() {
	let (dir, _) = two_days();
	let path = Chain::open(dir.path()).expect("open").day_file(Day(DAY));
	let text = std::fs::read_to_string(&path).expect("read");
	std::fs::write(&path, text.replace("Notice 1", "Notice X")).expect("tamper");
	let key = EvidenceKey::load_or_create(dir.path()).expect("key");
	match seal_closed_days(dir.path(), &key, true, at(DAY + 2, 0)) {
		Err(SealError::Broken(at)) => assert_eq!((at.day, at.line), (Day(DAY), 2)),
		other => panic!("sealed a broken day: {:?}", other.map(|days| days.len())),
	}
	assert!(!files(dir.path(), Day(DAY)).json.exists());
}

#[test]
fn a_day_that_does_not_follow_the_previous_checkpoint_is_not_sealed() {
	let (dir, _) = two_days();
	let key = EvidenceKey::load_or_create(dir.path()).expect("key");
	seal_closed_days(dir.path(), &key, true, at(DAY + 1, 12)).expect("seal first");
	// Rewrite the second day so it chains onto something else.
	let chain = Chain::open(dir.path()).expect("open");
	std::fs::remove_file(chain.day_file(Day(DAY + 1))).expect("remove");
	std::fs::remove_file(chain.day_file(Day(DAY))).expect("remove");
	chain
		.append_at(at(DAY + 1, 3), accepted(5))
		.expect("append");
	match seal_closed_days(dir.path(), &key, true, at(DAY + 2, 0)) {
		Err(SealError::Broken(at)) => assert_eq!((at.day, at.line), (Day(DAY + 1), 1)),
		other => panic!(
			"sealed a day off the chain: {:?}",
			other.map(|days| days.len())
		),
	}
}
