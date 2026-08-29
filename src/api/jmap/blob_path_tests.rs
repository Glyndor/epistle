use super::*;

fn id(tail: &str) -> Uuid {
	// A v7-shaped id: timestamp-led, random tail. Only the tail matters here.
	Uuid::parse_str(&format!("0198f2c1-9a4b-7000-8000-00000000{tail}")).expect("fixture is a uuid")
}

#[test]
fn the_shard_comes_from_the_tail_because_v7_ids_share_their_head() {
	let dir = std::path::Path::new("/data");
	// Two ids minted in the same millisecond are identical for their first
	// twenty characters. Sharding on the head would file both together and
	// the layout would look sharded while behaving exactly like the flat
	// directory it replaced — a failure whose only symptom is the one it was
	// supposed to fix.
	let a = id("aabb");
	let b = id("ccdd");
	assert_eq!(
		&a.to_string()[..20],
		&b.to_string()[..20],
		"the fixture must share a head",
	);
	assert_ne!(
		shard_dir(dir, a),
		shard_dir(dir, b),
		"ids differing only in their tail must land in different buckets",
	);
	assert!(shard_dir(dir, a).ends_with("aa/bb"));
}

#[test]
fn a_write_goes_to_the_shard_and_a_sidecar_goes_beside_it() {
	let dir = std::path::Path::new("/data");
	let blob = id("aabb");
	assert!(write_path(dir, blob, "").ends_with(format!("aa/bb/{blob}")));
	assert!(write_path(dir, blob, ".owner").ends_with(format!("aa/bb/{blob}.owner")));
}

#[test]
fn a_blob_written_by_an_older_version_is_still_found() {
	// The upgrade has no migration step, so the flat fallback is the whole
	// compatibility story: drop it and every blob predating the change stops
	// being served.
	let dir = tempfile::tempdir().expect("tempdir");
	let blob = id("aabb");
	let flat = blob_root(dir.path()).join(blob.to_string());
	std::fs::create_dir_all(blob_root(dir.path())).expect("root");
	std::fs::write(&flat, b"old").expect("write flat");
	assert_eq!(read_path(dir.path(), blob, ""), flat);
}

#[test]
fn the_sharded_copy_wins_when_both_exist() {
	let dir = tempfile::tempdir().expect("tempdir");
	let blob = id("aabb");
	std::fs::create_dir_all(blob_root(dir.path())).expect("root");
	std::fs::write(blob_root(dir.path()).join(blob.to_string()), b"old").expect("flat");
	let sharded = write_path(dir.path(), blob, "");
	std::fs::create_dir_all(sharded.parent().expect("parent")).expect("shard dir");
	std::fs::write(&sharded, b"new").expect("sharded");
	assert_eq!(read_path(dir.path(), blob, ""), sharded);
}

#[test]
fn the_walk_finds_both_layouts_and_skips_anything_that_is_not_a_blob() {
	let dir = tempfile::tempdir().expect("tempdir");
	let old = id("1111");
	let new = id("aabb");
	std::fs::create_dir_all(blob_root(dir.path())).expect("root");
	std::fs::write(blob_root(dir.path()).join(old.to_string()), b"old").expect("flat");
	std::fs::write(blob_root(dir.path()).join(format!("{old}.owner")), b"alice")
		.expect("flat sidecar");
	// Anything that is not a UUID was not written by us and must be ignored
	// rather than fed back out as a blob id.
	std::fs::write(blob_root(dir.path()).join("README"), b"not a blob").expect("stray");
	let sharded = write_path(dir.path(), new, "");
	std::fs::create_dir_all(sharded.parent().expect("parent")).expect("shard dir");
	std::fs::write(&sharded, b"new").expect("sharded");
	std::fs::write(write_path(dir.path(), new, ".owner"), b"bob").expect("sharded sidecar");

	let mut found: Vec<Uuid> = walk(dir.path()).into_iter().map(|(id, _)| id).collect();
	found.sort();
	let mut want = vec![old, new];
	want.sort();
	assert_eq!(
		found, want,
		"the sweep must see both layouts and nothing else"
	);
}
