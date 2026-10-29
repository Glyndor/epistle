use super::*;
use std::os::unix::fs::PermissionsExt;

fn os(list: &[&str]) -> Vec<OsString> {
	list.iter().map(OsString::from).collect()
}

fn keep(_: &File, _: &Path) -> io::Result<()> {
	Ok(())
}

#[test]
fn a_message_named_for_check_is_copied_and_the_line_points_at_the_copy() {
	let source = tempfile::tempdir().unwrap();
	let home = tempfile::tempdir().unwrap();
	let eml = source.path().join("mail.eml");
	fs::write(&eml, b"Subject: s\r\n\r\nbody\r\n").unwrap();
	fs::set_permissions(&eml, fs::Permissions::from_mode(0o600)).unwrap();
	let line = os(&["attachments", "check", eml.to_str().unwrap(), "--json"]);
	let stage = Stage::prepare(&line, home.path(), 0, &keep).unwrap();
	let staged = PathBuf::from(&stage.args()[2]);
	assert!(
		staged.starts_with(home.path()),
		"the staged copy is not under the home"
	);
	assert_eq!(fs::read(&staged).unwrap(), b"Subject: s\r\n\r\nbody\r\n");
	assert_eq!(stage.args()[..2], line[..2]);
	assert_eq!(stage.args()[3], OsString::from("--json"));
	assert_eq!(
		shown::decode(&stage.shown_env().unwrap()),
		[(
			staged.to_str().unwrap().to_owned(),
			eml.to_str().unwrap().to_owned()
		)]
	);
}

#[test]
fn a_message_over_the_staging_limit_is_refused_and_leaves_nothing() {
	let source = tempfile::tempdir().unwrap();
	let home = tempfile::tempdir().unwrap();
	let eml = source.path().join("big.eml");
	let small = [Staged {
		command: &["attachments", "check"],
		arg: "file",
		kind: Kind::ReadFile {
			limit: 8,
			secret: false,
		},
	}];
	fs::write(&eml, b"more than eight bytes").unwrap();
	let line = os(&["attachments", "check", eml.to_str().unwrap()]);
	let error = Stage::prepare_with(&line, home.path(), 0, &keep, &small)
		.err()
		.expect("a file past the limit is not staged");
	assert!(error.to_string().contains("big.eml"), "{error}");
	assert_eq!(fs::read_dir(home.path()).unwrap().count(), 0);
}
