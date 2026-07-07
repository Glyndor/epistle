//! Tests for the backup archive builder.

use super::*;
use flate2::read::GzDecoder;
use std::io::Read;

/// Gunzip an archive and return its raw tar bytes.
fn gunzip(data: &[u8]) -> Vec<u8> {
	let mut decoder = GzDecoder::new(data);
	let mut out = Vec::new();
	decoder.read_to_end(&mut out).expect("gunzip");
	out
}

/// Walk a tar's 512-byte blocks, returning (name, content) for each file.
fn read_tar(tar: &[u8]) -> Vec<(String, Vec<u8>)> {
	let mut out = Vec::new();
	let mut offset = 0;
	while offset + 512 <= tar.len() {
		let header = &tar[offset..offset + 512];
		if header.iter().all(|&b| b == 0) {
			break; // end-of-archive zero block
		}
		// USTAR magic must be present.
		assert_eq!(&header[257..262], b"ustar", "missing ustar magic");
		let name_end = header[..100].iter().position(|&b| b == 0).unwrap_or(100);
		let name = String::from_utf8_lossy(&header[..name_end]).into_owned();
		let size_str = String::from_utf8_lossy(&header[124..135]);
		let size = usize::from_str_radix(size_str.trim_matches('\0').trim(), 8).unwrap_or(0);
		offset += 512;
		out.push((name, tar[offset..offset + size].to_vec()));
		offset += size.div_ceil(512) * 512;
	}
	out
}

#[test]
fn tar_gz_round_trips_entries() {
	let entries = vec![
		("data/a.eml".to_string(), b"hello".to_vec()),
		("data/sub/b.eml".to_string(), b"world!!".to_vec()),
	];
	let archive = tar_gz(&entries).expect("build");
	let files = read_tar(&gunzip(&archive));
	assert_eq!(files.len(), 2);
	assert_eq!(files[0].0, "data/a.eml");
	assert_eq!(files[0].1, b"hello");
	assert_eq!(files[1].1, b"world!!");
}

#[test]
fn ustar_header_checksum_is_valid() {
	let header = ustar_header("data/x", 5).expect("header");
	// The stored checksum equals the sum of the header with the field spaced.
	let stored = usize::from_str_radix(
		String::from_utf8_lossy(&header[148..154])
			.trim_matches('\0')
			.trim(),
		8,
	)
	.expect("octal");
	let mut spaced = header;
	spaced[148..156].copy_from_slice(b"        ");
	let computed: usize = spaced.iter().map(|&b| b as usize).sum();
	assert_eq!(stored, computed);
}

#[test]
fn header_rejects_overlong_name() {
	let long = "data/".to_string() + &"x".repeat(200);
	assert!(ustar_header(&long, 0).is_err());
}

#[test]
fn run_archives_the_data_dir() {
	let dir = tempfile::tempdir().expect("tempdir");
	let new = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&new).expect("dirs");
	std::fs::write(new.join("m1.eml"), b"Subject: hi\r\n\r\nbody").expect("write");

	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n",
		dir.path().display()
	);
	let config: Config = toml::from_str(&toml).expect("config");

	let mut out = Vec::new();
	assert_eq!(run(&config, &mut out), ExitCode::SUCCESS);
	let files = read_tar(&gunzip(&out));
	assert!(
		files.iter().any(|(n, _)| n.ends_with("alice/new/m1.eml")),
		"message archived: {:?}",
		files.iter().map(|(n, _)| n).collect::<Vec<_>>()
	);
}
