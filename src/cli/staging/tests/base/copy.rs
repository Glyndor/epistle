//! Copying the arguments the account reads into a private staging directory.

use super::*;

#[test]
fn a_password_file_is_copied_private_and_the_argument_points_at_the_copy() {
	let (home, source) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
	let secret = source.path().join("srcpw");
	write(&secret, "s3cret\n", 0o600);
	let owner = Owner::default();
	let line = imap(&["--password-file", secret.to_str().unwrap()]);
	let stage = Stage::prepare(&line, home.path(), me(), &owner.chown()).unwrap();

	let dir = &stage.dir.as_ref().expect("a staging directory").path;
	assert_eq!(
		dir.parent(),
		Some(home.path()),
		"staged under the account's home"
	);
	let staged = dir.join("0/srcpw");
	assert_eq!(
		stage.args()[9],
		staged.as_os_str(),
		"the argument names the copy"
	);
	assert_eq!(
		&stage.args()[..9],
		&line[..9],
		"every other argument is kept"
	);
	assert_eq!(fs::read_to_string(&staged).unwrap(), "s3cret\n");
	assert_eq!(mode(dir), 0o700);
	assert_eq!(mode(&dir.join("0")), 0o700);
	assert_eq!(mode(&staged), 0o600);
	assert_eq!(
		owner.handed(),
		[
			(PathBuf::from("0/srcpw"), 0o600),
			(PathBuf::from("0"), 0o700),
			(PathBuf::new(), 0o700),
		],
		"the copy, its directory and the staging directory go to the account"
	);
	assert!(stage.shown_env().unwrap().contains("srcpw"));
	drop(stage);
	assert!(
		entries(home.path()).is_empty(),
		"the staging directory is removed"
	);
	assert_eq!(
		fs::read_to_string(&secret).unwrap(),
		"s3cret\n",
		"the source stays"
	);
}

#[test]
fn the_joined_spelling_is_rewritten_in_place() {
	let (home, source) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
	let ca = source.path().join("ca.pem");
	write(&ca, "-----BEGIN CERTIFICATE-----\n", 0o644);
	let line = imap(&[&format!("--ca-file={}", ca.display())]);
	let stage = Stage::prepare(&line, home.path(), me(), &Owner::default().chown()).unwrap();
	let dir = &stage.dir.as_ref().unwrap().path;
	let expected = format!("--ca-file={}", dir.join("0/ca.pem").display());
	assert_eq!(stage.args()[8], OsString::from(expected));
}

#[test]
fn a_command_line_without_paths_stages_nothing() {
	let home = tempfile::tempdir().unwrap();
	let line = os(&["queue", "list", "--config", "/etc/epistle/mail.toml"]);
	let stage = Stage::prepare(&line, home.path(), me(), &|_, _| {
		panic!("nothing to hand over")
	})
	.unwrap();
	assert_eq!(stage.args(), line.as_slice());
	assert!(stage.shown_env().is_none());
	assert!(entries(home.path()).is_empty(), "no directory is made");
	stage.finish(true).unwrap();
}

#[test]
fn a_maildir_tree_is_copied_with_private_modes() {
	let (home, source) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
	let maildir = source.path().join("Maildir");
	write(&maildir.join("cur/1:2,S"), "one", 0o644);
	write(&maildir.join(".Work/cur/2:2,"), "two", 0o640);
	fs::create_dir_all(maildir.join("new")).unwrap();
	let owner = Owner::default();
	let line = os(&[
		"import",
		"--account",
		"alice",
		"--maildir",
		maildir.to_str().unwrap(),
	]);
	let stage = Stage::prepare(&line, home.path(), me(), &owner.chown()).unwrap();
	let staged = stage.dir.as_ref().unwrap().path.join("0/Maildir");
	assert_eq!(stage.args()[4], staged.as_os_str());
	assert_eq!(fs::read_to_string(staged.join("cur/1:2,S")).unwrap(), "one");
	assert_eq!(
		fs::read_to_string(staged.join(".Work/cur/2:2,")).unwrap(),
		"two"
	);
	for path in [
		staged.join("cur"),
		staged.join(".Work/cur"),
		staged.join("new"),
	] {
		assert_eq!(mode(&path), 0o700, "{}", path.display());
	}
	assert_eq!(mode(&staged.join(".Work/cur/2:2,")), 0o600);
	let handed: Vec<PathBuf> = owner.handed().into_iter().map(|(path, _)| path).collect();
	for rel in [
		"0/Maildir/cur/1:2,S",
		"0/Maildir/.Work/cur",
		"0/Maildir/new",
		"0/Maildir",
		"",
	] {
		assert!(
			handed.contains(&PathBuf::from(rel)),
			"{rel} handed over: {handed:?}"
		);
	}
}

#[test]
fn a_mox_file_brings_its_directory() {
	let (home, source) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
	let config = source.path().join("config");
	write(&config.join("mox.conf"), "DataDir: ../data\n", 0o640);
	write(&config.join("domains.conf"), "Domains:\n", 0o640);
	write(&config.join("dkim/key.pem"), "key", 0o600);
	let conf = config.join("mox.conf");
	let line = os(&[
		"migrate",
		"mox",
		"--from",
		conf.to_str().unwrap(),
		"--password-reset",
	]);
	let stage = Stage::prepare(&line, home.path(), me(), &Owner::default().chown()).unwrap();
	let staged = stage.dir.as_ref().unwrap().path.join("0/config");
	assert_eq!(stage.args()[3], staged.join("mox.conf").as_os_str());
	assert_eq!(
		fs::read_to_string(staged.join("dkim/key.pem")).unwrap(),
		"key"
	);
	let shown = shown::decode(&stage.shown_env().unwrap());
	assert_eq!(
		shown,
		[(staged.display().to_string(), config.display().to_string())],
		"messages about the staged directory name the operator's"
	);
}
