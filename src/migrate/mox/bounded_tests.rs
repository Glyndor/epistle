use super::*;

#[test]
fn a_stalled_read_has_a_deadline_and_keeps_one_worker() {
	let (release, wait) = std::sync::mpsc::channel();
	let started = Instant::now();
	let result = within(Duration::from_millis(100), move || {
		let _ = wait.recv_timeout(Duration::from_secs(2));
		Ok(())
	});
	assert_eq!(result.expect_err("timeout").kind(), io::ErrorKind::TimedOut);
	assert!(started.elapsed() < Duration::from_secs(2));
	assert!(
		READING.load(Ordering::Acquire),
		"the outstanding reader keeps its slot"
	);
	let second = within(Duration::from_millis(20), || Ok(()));
	assert_eq!(second.expect_err("busy").kind(), io::ErrorKind::TimedOut);
	release.send(()).expect("release");
	assert!(within(Duration::from_secs(2), || Ok(())).is_ok());
}

#[test]
fn regular_input_is_bounded_and_must_be_utf8() {
	let dir = tempfile::tempdir().expect("dir");
	let file = dir.path().join("key");
	std::fs::write(&file, b"abcd").expect("write");
	assert_eq!(read(&file, 4).expect("read"), "abcd");
	assert!(
		read(&file, 3)
			.expect_err("size")
			.to_string()
			.contains("larger than 3")
	);
	std::fs::write(&file, [0xff]).expect("write");
	assert_eq!(
		read(&file, 4).expect_err("utf8").kind(),
		io::ErrorKind::InvalidData
	);
	assert!(read(dir.path(), 4).is_err());
}
