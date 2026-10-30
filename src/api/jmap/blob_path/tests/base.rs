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

#[test]
fn a_shard_name_is_exactly_what_the_store_writes() {
	// `parse` accepts the rendering of every index and nothing else. The
	// rejected spellings are the ones a walk that trusted the listing would
	// have joined into a path: a longer name, uppercase, a dot-dot.
	for index in 0..=u8::MAX {
		let name = Shard(index).dir_name();
		assert_eq!(name.len(), Shard::NAME_LEN);
		assert_eq!(Shard::parse(&name), Some(Shard(index)), "{name}");
	}
	for rejected in ["", "a", "abc", "AB", "Ab", "g0", "..", "a/", "0x"] {
		assert_eq!(Shard::parse(rejected), None, "{rejected:?}");
	}
}

/// Sets up a store holding one valid sharded payload, then plants the
/// things an operator, a stray tool or an attacker with write access to the
/// volume could leave beside it. Returns the root and the one id the walk
/// must report.
fn store_with_strays(root: &std::path::Path) -> Uuid {
	let blob = id("aabb");
	let sharded = write_path(root.parent().expect("data dir"), blob, "");
	std::fs::create_dir_all(sharded.parent().expect("parent")).expect("shard dir");
	std::fs::write(&sharded, b"ours").expect("sharded");
	// Directories the store never writes, each holding a UUID-named file
	// that would be reported if the walk descended into them.
	for foreign in ["tmp", "lost+found", "AA", "abc", "a"] {
		let dir = root.join(foreign).join("cd");
		std::fs::create_dir_all(&dir).expect("foreign dir");
		std::fs::write(dir.join(id("1234").to_string()), b"theirs").expect("foreign payload");
	}
	// A shard-shaped outer name with a foreign inner name.
	let inner = root.join("aa").join("zz");
	std::fs::create_dir_all(&inner).expect("foreign inner");
	std::fs::write(inner.join(id("5678").to_string()), b"theirs").expect("foreign payload");
	// A payload one level down, which is neither layout the store writes.
	std::fs::write(root.join("aa").join(id("9abc").to_string()), b"theirs").expect("mid payload");
	blob
}

#[test]
fn a_directory_the_store_did_not_write_is_not_walked() {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = blob_root(dir.path());
	let ours = store_with_strays(&root);
	let found: Vec<Uuid> = walk(dir.path()).into_iter().map(|(id, _)| id).collect();
	assert_eq!(found, vec![ours], "only the shard the store wrote is swept");
}

#[cfg(unix)]
#[test]
fn a_symlink_with_a_shard_name_is_not_followed() {
	// The name fits, so a walk that checked the name alone would descend
	// into whatever the link points at: here a directory outside the store.
	let dir = tempfile::tempdir().expect("tempdir");
	let root = blob_root(dir.path());
	let ours = store_with_strays(&root);
	let outside = dir.path().join("elsewhere").join("cd");
	std::fs::create_dir_all(&outside).expect("outside");
	std::fs::write(outside.join(id("dead").to_string()), b"theirs").expect("outside payload");
	std::os::unix::fs::symlink(dir.path().join("elsewhere"), root.join("ee")).expect("symlink");
	let found: Vec<Uuid> = walk(dir.path()).into_iter().map(|(id, _)| id).collect();
	assert_eq!(found, vec![ours], "a symlinked shard is not descended into");
}

#[test]
fn a_file_whose_name_is_not_exactly_a_blob_id_is_skipped() {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = blob_root(dir.path());
	std::fs::create_dir_all(&root).expect("root");
	let ours = id("aabb");
	std::fs::write(root.join(ours.to_string()), b"ours").expect("flat");
	// Spellings that parse as a UUID but are not what `write_path` renders,
	// plus the sidecars and a name that does not parse at all.
	let upper = ours.to_string().to_uppercase();
	let simple = ours.simple().to_string();
	for stray in [
		upper.as_str(),
		simple.as_str(),
		&format!("{ours}.owner"),
		&format!("{ours}.type"),
		&format!("{ours}.tmp"),
		"README",
	] {
		std::fs::write(root.join(stray), b"theirs").expect("stray");
	}
	let found: Vec<(Uuid, std::path::PathBuf)> = walk(dir.path());
	assert_eq!(found, vec![(ours, root.join(ours.to_string()))]);
}

#[test]
fn every_walked_path_is_rebuilt_under_the_root_and_exists() {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = blob_root(dir.path());
	let sharded = id("aabb");
	let flat = id("1111");
	let path = write_path(dir.path(), sharded, "");
	std::fs::create_dir_all(path.parent().expect("parent")).expect("shard dir");
	std::fs::write(&path, b"new").expect("sharded");
	std::fs::write(root.join(flat.to_string()), b"old").expect("flat");

	let walked = walk(dir.path());
	assert_eq!(walked.len(), 2);
	for (id, path) in &walked {
		assert!(
			path.starts_with(&root),
			"{} escapes the store",
			path.display()
		);
		assert!(
			path.is_file(),
			"{} was rebuilt to a file that exists",
			path.display()
		);
		assert_eq!(path, &read_path(dir.path(), *id, ""));
	}
}
