use super::*;

fn id(tail: &str) -> String {
	// A v7-shaped id: timestamp-led, random tail. Only the tail matters here.
	format!("0198f2c1-9a4b-7000-8000-00000000{tail}")
}

#[test]
fn the_shard_comes_from_the_tail_because_v7_ids_share_their_head() {
	let dir = std::path::Path::new("/data");
	// Two ids minted in the same millisecond are identical for their first
	// twenty characters. Sharding on the head would file both together and
	// the layout would look sharded while behaving exactly like a flat
	// directory — a failure with no symptom other than the one it was
	// supposed to fix.
	let a = id("aabb");
	let b = id("ccdd");
	assert_eq!(&a[..20], &b[..20], "the fixture must share a head");
	assert_ne!(
		shard_dir(dir, &a).expect("shard"),
		shard_dir(dir, &b).expect("shard"),
		"ids differing only in their tail must land in different buckets",
	);
	assert!(shard_dir(dir, &a).expect("shard").ends_with("aa/bb"));
}

#[test]
fn an_id_that_is_not_a_uuid_never_becomes_a_path() {
	// Every caller parses the id before it gets here, but this codebase has
	// already shipped a check that lived in only one of the four places it
	// was needed. The helper that builds the path refuses on its own.
	let dir = std::path::Path::new("/data");
	for bad in ["../../etc/passwd", "..", "a/b", "", "not-a-uuid"] {
		assert!(shard_dir(dir, bad).is_none(), "shard_dir accepted {bad:?}");
		assert!(
			write_path(dir, bad, "").is_none(),
			"write_path accepted {bad:?}"
		);
		assert!(
			read_path(dir, bad, "").is_none(),
			"read_path accepted {bad:?}"
		);
	}
}

#[test]
fn a_write_goes_to_the_shard_and_a_sidecar_goes_beside_it() {
	let dir = std::path::Path::new("/data");
	let blob = id("aabb");
	assert!(
		write_path(dir, &blob, "")
			.expect("path")
			.ends_with(format!("aa/bb/{blob}"))
	);
	assert!(
		write_path(dir, &blob, ".owner")
			.expect("path")
			.ends_with(format!("aa/bb/{blob}.owner"))
	);
}

#[test]
fn a_blob_written_by_an_older_version_is_still_found() {
	// The upgrade has no migration step, so the flat fallback is the whole
	// compatibility story: drop it and every blob predating the change stops
	// being served.
	let dir = tempfile::tempdir().expect("tempdir");
	let blob = id("aabb");
	let flat = blob_root(dir.path()).join(&blob);
	std::fs::create_dir_all(blob_root(dir.path())).expect("root");
	std::fs::write(&flat, b"old").expect("write flat");
	assert_eq!(read_path(dir.path(), &blob, "").expect("path"), flat);
}

#[test]
fn the_sharded_copy_wins_when_both_exist() {
	let dir = tempfile::tempdir().expect("tempdir");
	let blob = id("aabb");
	std::fs::create_dir_all(blob_root(dir.path())).expect("root");
	std::fs::write(blob_root(dir.path()).join(&blob), b"old").expect("flat");
	let sharded = write_path(dir.path(), &blob, "").expect("path");
	std::fs::create_dir_all(sharded.parent().expect("parent")).expect("shard dir");
	std::fs::write(&sharded, b"new").expect("sharded");
	assert_eq!(read_path(dir.path(), &blob, "").expect("path"), sharded);
}

#[test]
fn the_walk_finds_both_layouts_and_skips_sidecars() {
	let dir = tempfile::tempdir().expect("tempdir");
	let old = id("1111");
	let new = id("aabb");
	std::fs::create_dir_all(blob_root(dir.path())).expect("root");
	std::fs::write(blob_root(dir.path()).join(&old), b"old").expect("flat");
	std::fs::write(blob_root(dir.path()).join(format!("{old}.owner")), b"alice")
		.expect("flat sidecar");
	let sharded = write_path(dir.path(), &new, "").expect("path");
	std::fs::create_dir_all(sharded.parent().expect("parent")).expect("shard dir");
	std::fs::write(&sharded, b"new").expect("sharded");
	std::fs::write(
		write_path(dir.path(), &new, ".owner").expect("path"),
		b"bob",
	)
	.expect("sharded sidecar");

	let mut found: Vec<String> = walk(dir.path()).into_iter().map(|(id, _)| id).collect();
	found.sort();
	let mut want = vec![old, new];
	want.sort();
	assert_eq!(
		found, want,
		"the sweep must see both layouts and no sidecars"
	);
}
