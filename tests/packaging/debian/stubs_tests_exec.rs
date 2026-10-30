use super::write_stub;
use std::fs::File;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

#[test]
fn published_stub_executes_while_an_old_write_descriptor_is_open() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("stub");
	// A fork can retain a writer after the creating thread closes its copy.
	let old_writer = File::create(&path).unwrap();
	write_stub(&path, "printf 'stub-ready\\n'\nexit 17");
	let output = Command::new("/bin/sh")
		.args(["-c", "\"$1\"", "stub-test"])
		.arg(&path)
		.output()
		.unwrap();
	assert_eq!(
		output.status.code(),
		Some(17),
		"published stub must execute even while an old write descriptor remains open"
	);
	assert_eq!(
		String::from_utf8(output.stdout).unwrap(),
		"stub-ready\n",
		"published stub must execute the complete replacement body"
	);
	assert_eq!(
		path.metadata().unwrap().permissions().mode() & 0o777,
		0o755,
		"published stub must have executable permissions"
	);
	drop(old_writer);
}
