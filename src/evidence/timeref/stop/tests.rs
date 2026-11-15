use super::{StopNote, clear, current_boot_id, note, read, record};

#[test]
fn a_recorded_stop_is_read_back_until_it_is_cleared() {
	let dir = tempfile::tempdir().expect("tempdir");
	assert_eq!(read(dir.path()), None);
	record(dir.path(), 1_792_000_000, Some("boot-a")).expect("record");
	assert_eq!(
		read(dir.path()),
		Some((1_792_000_000, Some("boot-a".to_string())))
	);
	clear(dir.path());
	assert_eq!(read(dir.path()), None);
}

#[test]
fn a_file_that_is_not_a_stop_says_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::write(dir.path().join("clean-stop.json"), b"{\"time\": \"soon\"}").expect("write");
	assert_eq!(read(dir.path()), None);
	std::fs::write(dir.path().join("clean-stop.json"), vec![b'x'; 10_000]).expect("write");
	assert_eq!(read(dir.path()), None);
}

#[test]
fn a_stop_recorded_by_this_host_in_this_boot_is_the_same_boot() {
	let Some(boot) = current_boot_id() else {
		return;
	};
	let dir = tempfile::tempdir().expect("tempdir");
	record(dir.path(), 1_792_000_000, Some(&boot)).expect("record");
	assert_eq!(note(dir.path()), Some(StopNote::SameBoot));
	record(dir.path(), 1_792_000_000, Some("another-boot")).expect("record");
	assert_eq!(note(dir.path()), Some(StopNote::Rebooted(1_792_000_000)));
	record(dir.path(), 1_792_000_000, None).expect("record");
	assert_eq!(note(dir.path()), Some(StopNote::BootUnknown));
}
