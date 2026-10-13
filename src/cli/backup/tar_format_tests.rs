//! The archive format: ustar entries, with a PAX `path` record in front of
//! any name over 100 bytes.

use super::*;
use std::io::Write;

fn gunzip(data: &[u8]) -> Vec<u8> {
	let mut out = Vec::new();
	std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(data), &mut out).unwrap();
	out
}

fn round_trip(entries: &[Entry]) -> Vec<Entry> {
	read_entries(&gunzip(&tar_gz(entries).unwrap())).unwrap()
}

/// The header `epistle backup` wrote up to 0.11, copied from that release:
/// a regular ustar entry whose name must fit in 100 bytes.
fn legacy_header(name: &str, mode: u32, size: usize) -> [u8; 512] {
	assert!(name.len() <= 100);
	let mut header = [0u8; 512];
	header[..name.len()].copy_from_slice(name.as_bytes());
	let field = |header: &mut [u8; 512], offset: usize, value: &str| {
		header[offset..offset + value.len()].copy_from_slice(value.as_bytes());
	};
	field(&mut header, 100, &format!("{:07o}", mode & 0o7777));
	field(&mut header, 108, "0000000");
	field(&mut header, 116, "0000000");
	field(&mut header, 124, &format!("{size:011o}"));
	field(&mut header, 136, "00000000000");
	header[156] = b'0';
	header[257..263].copy_from_slice(b"ustar\0");
	header[263..265].copy_from_slice(b"00");
	header[148..156].copy_from_slice(b"        ");
	let sum: u32 = header.iter().map(|&b| u32::from(b)).sum();
	let chksum = format!("{sum:06o}\0 ");
	header[148..148 + chksum.len()].copy_from_slice(chksum.as_bytes());
	header
}

fn legacy_archive(entries: &[Entry]) -> Vec<u8> {
	let mut tar = Vec::new();
	for (name, mode, data) in entries {
		tar.extend_from_slice(&legacy_header(name, *mode, data.len()));
		tar.extend_from_slice(data);
		tar.resize(tar.len().div_ceil(512) * 512, 0);
	}
	tar.extend_from_slice(&[0u8; 1024]);
	tar
}

#[test]
fn names_of_every_length_and_contents_of_every_padding_round_trip() {
	let mut entries = Vec::new();
	for (index, length) in [1usize, 99, 100, 101, 150, 255, 256, 1000]
		.into_iter()
		.enumerate()
	{
		let name = format!("data/{index}{}", "n".repeat(length.saturating_sub(6)));
		let size = [0, 1, 511, 512, 513, 4096, 70_000, 3][index];
		entries.push((name, 0o600 | (index as u32 & 0o7), vec![index as u8; size]));
	}
	entries.push((
		"data/correo/ñandú/ünïcödé-ಠ_ಠ-".to_string() + &"é".repeat(60),
		0o644,
		b"u".to_vec(),
	));
	assert_eq!(round_trip(&entries), entries);
}

#[test]
fn short_names_are_written_exactly_as_before() {
	let entries = vec![
		("data/a".to_string(), 0o600, b"one".to_vec()),
		(format!("data/{}", "x".repeat(95)), 0o644, vec![7; 600]),
	];
	assert_eq!(gunzip(&tar_gz(&entries).unwrap()), legacy_archive(&entries));
}

#[test]
fn an_archive_from_the_previous_release_still_reads() {
	let entries = vec![
		(
			"data/accounts.toml".to_string(),
			0o600,
			b"[accounts]".to_vec(),
		),
		("database.sql".to_string(), 0o644, b"SELECT 1;".to_vec()),
	];
	assert_eq!(read_entries(&legacy_archive(&entries)).unwrap(), entries);
}

#[test]
fn only_regular_and_pax_entries_are_written() {
	let entries = vec![(format!("data/{}", "l".repeat(300)), 0o600, vec![1; 10])];
	let tar = gunzip(&tar_gz(&entries).unwrap());
	let types: Vec<u8> = tar
		.chunks(512)
		.take_while(|block| block.iter().any(|&byte| byte != 0))
		.filter(|block| &block[257..262] == b"ustar")
		.map(|block| block[156])
		.collect();
	assert_eq!(
		types,
		[b'x', b'0'],
		"no sparse or GNU entries, which Podman rejects"
	);
}

#[test]
fn gnu_tar_reads_the_long_names_the_same_way() {
	let Ok(version) = std::process::Command::new("tar").arg("--version").output() else {
		eprintln!("skipped: no tar on PATH, so the archive was not checked against it");
		return;
	};
	assert!(version.status.success());
	let dir = tempfile::tempdir().unwrap();
	let name = format!("data/{}/{}", "a".repeat(64), "b".repeat(200));
	let archive = dir.path().join("backup.tar.gz");
	std::fs::write(
		&archive,
		tar_gz(&[(name.clone(), 0o600, b"bytes".to_vec())]).unwrap(),
	)
	.unwrap();
	let out = dir.path().join("out");
	std::fs::create_dir(&out).unwrap();
	let status = std::process::Command::new("tar")
		.arg("-xzf")
		.arg(&archive)
		.arg("-C")
		.arg(&out)
		.status()
		.unwrap();
	assert!(status.success());
	assert_eq!(std::fs::read(out.join(&name)).unwrap(), b"bytes");
}

#[test]
fn a_gnu_long_name_entry_is_read_too() {
	let name = format!("data/{}", "g".repeat(150));
	let mut tar = legacy_header("././@LongLink", 0o644, name.len() + 1).to_vec();
	tar[156] = b'L';
	tar[148..156].copy_from_slice(b"        ");
	let sum: u32 = tar.iter().map(|&b| u32::from(b)).sum();
	tar[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
	tar.extend_from_slice(name.as_bytes());
	tar.push(0);
	tar.resize(1024, 0);
	tar.extend_from_slice(&legacy_header(&name[..100], 0o600, 2));
	tar.write_all(b"ok").unwrap();
	tar.resize(tar.len().div_ceil(512) * 512 + 1024, 0);
	assert_eq!(
		read_entries(&tar).unwrap(),
		vec![(name, 0o600, b"ok".to_vec())]
	);
}

#[test]
fn a_link_a_truncated_body_and_a_bad_checksum_are_refused() {
	let mut link = legacy_archive(&[("data/l".to_string(), 0o600, Vec::new())]);
	link[156] = b'2';
	link[148..156].copy_from_slice(b"        ");
	let sum: u32 = link[..512].iter().map(|&b| u32::from(b)).sum();
	link[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
	let error = read_entries(&link).unwrap_err().to_string();
	assert!(error.contains("type '2'"), "{error}");

	let full = legacy_archive(&[("data/t".to_string(), 0o600, vec![1; 2000])]);
	let error = read_entries(&full[..1024]).unwrap_err().to_string();
	assert!(error.contains("truncated"), "{error}");

	let mut bad = full.clone();
	bad[0] = b'X';
	let error = read_entries(&bad).unwrap_err().to_string();
	assert!(error.contains("checksum"), "{error}");
	assert_eq!(read_entries(&full).unwrap()[0].2.len(), 2000);
}
