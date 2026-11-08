//! The decompression ceiling of a restore: a gzip bomb is refused by name,
//! and an archive that expands to exactly the ceiling still restores.

use std::io::Write;

use super::gunzip::{FLOOR, MAX_RATIO, expansion_limit, gunzip_archive, gunzip_capped};

fn gzip(data: &[u8]) -> Vec<u8> {
	let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
	encoder.write_all(data).expect("compress");
	encoder.finish().expect("finish")
}

#[test]
fn a_gzip_bomb_is_refused_for_its_expansion() {
	// One MiB of zeros compresses to about a kilobyte: a thousand times.
	let bomb = gzip(&vec![0u8; 1 << 20]);
	assert!(bomb.len() < 4096, "the bomb is small");
	let error = gunzip_capped(&bomb, 64 * 1024).expect_err("refused");
	assert!(
		error.to_string().contains("expands past 65536 bytes"),
		"refused for its size, not something else: {error}"
	);
}

#[test]
fn an_archive_that_reaches_the_ceiling_exactly_is_read() {
	let data = vec![7u8; 64 * 1024];
	let archive = gzip(&data);
	assert_eq!(gunzip_capped(&archive, 64 * 1024).expect("read"), data);
	let over = gzip(&vec![7u8; 64 * 1024 + 1]);
	assert!(gunzip_capped(&over, 64 * 1024).is_err());
}

#[test]
fn the_ceiling_is_a_ratio_of_the_archive_with_a_floor() {
	assert_eq!(expansion_limit(0), FLOOR);
	assert_eq!(expansion_limit(1024), FLOOR);
	let large = 64 << 20;
	assert_eq!(expansion_limit(large), large as u64 * MAX_RATIO);
	assert_eq!(expansion_limit(usize::MAX), u64::MAX);
}

#[test]
fn the_restore_reads_through_the_ceiling() {
	// Under the floor, what the archive holds comes back whole.
	let data = b"a backup".repeat(1000);
	assert_eq!(gunzip_archive(&gzip(&data)).expect("read"), data);
	// A damaged stream is an error, not a panic or an empty archive.
	assert!(gunzip_archive(b"\x1f\x8b not gzip").is_err());
}
