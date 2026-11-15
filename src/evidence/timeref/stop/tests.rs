use super::{clear, read, record};

#[test]
fn a_recorded_stop_is_read_back_until_it_is_cleared() {
	let dir = tempfile::tempdir().expect("tempdir");
	assert_eq!(read(dir.path()), None);
	record(dir.path(), 1_792_000_000).expect("record");
	assert_eq!(read(dir.path()), Some(1_792_000_000));
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
