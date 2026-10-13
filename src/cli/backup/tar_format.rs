//! The tar layout of `epistle backup`, written and read here by hand.
//!
//! Every member is a regular ustar entry, as releases up to 0.11 wrote
//! them, so their archives still restore. A name over the 100 bytes a ustar
//! header holds gets a POSIX PAX extended header (`x`) in front carrying a
//! `path` record; the correspondent store alone names files
//! `correspondents/<64 hex>/<64 hex>`, and those releases refused to back
//! them up. GNU tar and Podman read PAX. Nothing here writes sparse or GNU
//! entries, which Podman refuses.

use std::io::{self, Write};

use flate2::Compression;
use flate2::write::GzEncoder;

/// One archive member: name, permission bits, contents.
pub(super) type Entry = (String, u32, Vec<u8>);

/// The bytes a ustar header keeps for a name.
const NAME_FIELD: usize = 100;

/// Build a gzip-compressed archive from `entries`.
pub(super) fn tar_gz(entries: &[Entry]) -> io::Result<Vec<u8>> {
	let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
	for (name, mode, data) in entries {
		if name.len() > NAME_FIELD {
			let record = pax_record("path", name);
			let label = format!("PaxHeaders/{name}");
			write_member(
				&mut encoder,
				&header(label.as_bytes(), 0o644, record.len(), b'x'),
				&record,
			)?;
		}
		write_member(
			&mut encoder,
			&header(name.as_bytes(), *mode, data.len(), b'0'),
			data,
		)?;
	}
	// Two zero blocks mark the end of the archive.
	encoder.write_all(&[0u8; 1024])?;
	encoder.finish()
}

fn write_member(out: &mut impl Write, header: &[u8; 512], data: &[u8]) -> io::Result<()> {
	out.write_all(header)?;
	out.write_all(data)?;
	out.write_all(&vec![0u8; (512 - data.len() % 512) % 512])
}

/// One PAX record, `<length> <key>=<value>\n`, where the length counts the
/// whole record including its own digits.
fn pax_record(key: &str, value: &str) -> Vec<u8> {
	let body = format!(" {key}={value}\n");
	let mut length = body.len();
	while length != body.len() + length.to_string().len() {
		length = body.len() + length.to_string().len();
	}
	format!("{length}{body}").into_bytes()
}

/// A 512-byte ustar header. `name` is cut to the 100 bytes the field holds;
/// a longer name travels in a PAX record before it. `mode` is masked to the
/// permission, setuid, setgid and sticky bits.
pub(super) fn header(name: &[u8], mode: u32, size: usize, kind: u8) -> [u8; 512] {
	let mut header = [0u8; 512];
	let name = &name[..name.len().min(NAME_FIELD)];
	header[..name.len()].copy_from_slice(name);
	write_field(&mut header, 100, 8, &format!("{:07o}", mode & 0o7777));
	write_field(&mut header, 108, 8, "0000000"); // uid
	write_field(&mut header, 116, 8, "0000000"); // gid
	write_field(&mut header, 124, 12, &format!("{size:011o}"));
	write_field(&mut header, 136, 12, "00000000000"); // mtime
	header[156] = kind;
	header[257..263].copy_from_slice(b"ustar\0");
	header[263..265].copy_from_slice(b"00");
	// The checksum is the sum of the header with its own field as spaces,
	// computed last: a checksum over a field written after it is one tar
	// rejects.
	header[148..156].copy_from_slice(b"        ");
	let chksum = format!("{:06o}\0 ", checksum(&header));
	header[148..156].copy_from_slice(chksum.as_bytes());
	header
}

fn write_field(header: &mut [u8; 512], offset: usize, len: usize, value: &str) {
	let bytes = value.as_bytes();
	let n = bytes.len().min(len - 1);
	header[offset..offset + n].copy_from_slice(&bytes[..n]);
}

fn checksum(header: &[u8]) -> u32 {
	header
		.iter()
		.enumerate()
		.map(|(index, &byte)| {
			if (148..156).contains(&index) {
				32
			} else {
				u32::from(byte)
			}
		})
		.sum()
}

fn octal(field: &[u8], what: &str) -> io::Result<u64> {
	let text = String::from_utf8_lossy(field);
	let text = text.trim_matches(|c| c == '\0' || c == ' ');
	u64::from_str_radix(text, 8)
		.map_err(|_| io::Error::other(format!("archive header has a {what} that is not octal")))
}

/// Every regular file in `tar`, with the name a PAX `path` record or a GNU
/// long name gave it. Fails on a damaged header, a truncated member, or a
/// member that is not a file: the restore lays down files and nothing else.
pub(super) fn read_entries(tar: &[u8]) -> io::Result<Vec<Entry>> {
	let mut out = Vec::new();
	let mut long_name: Option<String> = None;
	let mut offset = 0;
	while offset + 512 <= tar.len() {
		let header = &tar[offset..offset + 512];
		if header.iter().all(|&byte| byte == 0) {
			return Ok(out);
		}
		if &header[257..262] != b"ustar" {
			return Err(io::Error::other("archive member is not a ustar header"));
		}
		if octal(&header[148..156], "checksum")? != u64::from(checksum(header)) {
			return Err(io::Error::other("archive header checksum does not match"));
		}
		let size = usize::try_from(octal(&header[124..136], "size")?)
			.map_err(|_| io::Error::other("archive member size does not fit in memory"))?;
		let start = offset + 512;
		let data = tar
			.get(start..start.saturating_add(size))
			.ok_or_else(|| io::Error::other("archive is truncated inside a member"))?;
		offset = start + size.div_ceil(512) * 512;
		match header[156] {
			b'0' | 0 => {
				let name = match long_name.take() {
					Some(name) => name,
					None => header_name(header),
				};
				let mode = octal(&header[100..108], "mode")? as u32;
				out.push((name, mode, data.to_vec()));
			}
			b'x' => long_name = pax_path(data)?.or(long_name),
			b'L' => {
				let end = data
					.iter()
					.position(|&byte| byte == 0)
					.unwrap_or(data.len());
				long_name = Some(String::from_utf8_lossy(&data[..end]).into_owned());
			}
			b'g' | b'5' => {}
			kind => {
				return Err(io::Error::other(format!(
					"archive member of type '{}' is not a regular file",
					char::from(kind)
				)));
			}
		}
	}
	Err(io::Error::other(
		"archive is truncated before its end marker",
	))
}

/// The name in a ustar header: `prefix/name` when the prefix field is set.
fn header_name(header: &[u8]) -> String {
	let field = |range: std::ops::Range<usize>| {
		let bytes = &header[range];
		let end = bytes
			.iter()
			.position(|&byte| byte == 0)
			.unwrap_or(bytes.len());
		String::from_utf8_lossy(&bytes[..end]).into_owned()
	};
	let (prefix, name) = (field(345..500), field(0..100));
	if prefix.is_empty() {
		name
	} else {
		format!("{prefix}/{name}")
	}
}

/// The `path` record of a PAX extended header, if it has one.
fn pax_path(mut records: &[u8]) -> io::Result<Option<String>> {
	let mut path = None;
	while !records.is_empty() {
		let malformed = || io::Error::other("archive has a malformed PAX record");
		let space = records
			.iter()
			.position(|&byte| byte == b' ')
			.ok_or_else(malformed)?;
		let length: usize = std::str::from_utf8(&records[..space])
			.ok()
			.and_then(|digits| digits.parse().ok())
			.ok_or_else(malformed)?;
		let record = records.get(space + 1..length).ok_or_else(malformed)?;
		let record = record.strip_suffix(b"\n").ok_or_else(malformed)?;
		if let Some(value) = record.strip_prefix(b"path=") {
			path = Some(String::from_utf8(value.to_vec()).map_err(|_| malformed())?);
		}
		records = &records[length..];
	}
	Ok(path)
}

#[cfg(test)]
#[path = "tar_format_tests.rs"]
mod tests;
