//! A long name is for the member right after it only.

use super::*;

fn member(tar: &mut Vec<u8>, header: &[u8; 512], data: &[u8]) {
	tar.extend_from_slice(header);
	tar.extend_from_slice(data);
	tar.resize(tar.len().div_ceil(512) * 512, 0);
}

#[test]
fn a_long_name_before_a_directory_does_not_rename_the_next_file() {
	let record = pax_record("path", "data/aaa");
	let mut tar = Vec::new();
	member(
		&mut tar,
		&header(b"PaxHeaders/x", 0o644, record.len(), b'x'),
		&record,
	);
	member(&mut tar, &header(b"data/dir/", 0o755, 0, b'5'), b"");
	member(&mut tar, &header(b"data/ccc", 0o644, 3, b'0'), b"abc");
	tar.extend_from_slice(&[0u8; 1024]);
	let entries = read_entries(&tar).expect("read");
	assert_eq!(
		entries,
		vec![("data/ccc".to_string(), 0o644, b"abc".to_vec())]
	);
}

#[test]
fn a_long_name_before_a_file_still_names_it() {
	let record = pax_record("path", "data/aaa");
	let mut tar = Vec::new();
	member(
		&mut tar,
		&header(b"PaxHeaders/x", 0o644, record.len(), b'x'),
		&record,
	);
	member(&mut tar, &header(b"data/ccc", 0o644, 3, b'0'), b"abc");
	tar.extend_from_slice(&[0u8; 1024]);
	let entries = read_entries(&tar).expect("read");
	assert_eq!(
		entries,
		vec![("data/aaa".to_string(), 0o644, b"abc".to_vec())]
	);
}
