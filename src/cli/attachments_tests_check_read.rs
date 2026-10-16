//! How `check` reads the file it is given: only a regular file, never a
//! link, at most the message size limit, and never waiting on it.

use std::path::Path;

use super::check::{read_bounded, read_capped};

fn refusal(file: &Path, limit: usize) -> String {
	match read_bounded(file, limit) {
		Err(error) => error.to_string(),
		Ok(raw) => format!("read {} bytes", raw.len()),
	}
}

#[test]
fn a_file_whose_size_is_not_what_it_says_is_still_cut_at_the_limit() {
	// /proc files report a size of 0 and then produce kilobytes: only the
	// bound on the read itself stops them.
	let maps = Path::new("/proc/self/maps");
	assert_eq!(std::fs::metadata(maps).unwrap().len(), 0);
	assert_eq!(
		refusal(maps, 10),
		"/proc/self/maps is larger than the message size limit (10 bytes)"
	);
}

#[test]
fn a_fifo_is_refused_without_waiting_for_a_writer() {
	let dir = tempfile::tempdir().unwrap();
	let fifo = dir.path().join("pipe.eml");
	let name = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
	// SAFETY: `name` is a valid NUL-terminated path for the whole call.
	assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
	assert_eq!(
		refusal(&fifo, 1024),
		format!("{} is not a regular file", fifo.display())
	);
}

#[test]
fn a_link_is_refused_and_not_followed() {
	let dir = tempfile::tempdir().unwrap();
	let target = dir.path().join("real.eml");
	std::fs::write(&target, b"Subject: s\r\n\r\nbody\r\n").unwrap();
	let link = dir.path().join("link.eml");
	std::os::unix::fs::symlink(&target, &link).unwrap();
	assert_eq!(
		refusal(&link, 1024),
		format!("{} is a link; links are not followed", link.display())
	);
}

#[test]
fn a_regular_file_at_the_limit_is_read_whole() {
	let dir = tempfile::tempdir().unwrap();
	let file = dir.path().join("ok.eml");
	std::fs::write(&file, vec![b'a'; 64]).unwrap();
	assert_eq!(refusal(&file, 64), "read 64 bytes");
	assert_eq!(
		refusal(&file, 63),
		format!(
			"{} is larger than the message size limit (63 bytes)",
			file.display()
		)
	);
}

#[test]
fn the_read_stops_one_byte_past_the_limit() {
	// A reader that would go on for 1000 bytes is cut at 11 for a limit of 10.
	let source = std::io::Cursor::new(vec![b'a'; 1000]);
	assert_eq!(read_capped(source, 10).unwrap().len(), 11);
	let short = std::io::Cursor::new(vec![b'a'; 4]);
	assert_eq!(read_capped(short, 10).unwrap().len(), 4);
}
