use super::*;
use std::cell::RefCell;
use std::fs::Permissions;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

/// Records every hand-over to the account instead of changing owners, so
/// the staging runs without root.
#[derive(Default)]
struct Owner(RefCell<Vec<(PathBuf, u32)>>);

impl Owner {
	fn chown(&self) -> impl Fn(&File, &Path) -> io::Result<()> + '_ {
		|file, rel| {
			let mode = file.metadata()?.permissions().mode() & 0o7777;
			self.0.borrow_mut().push((rel.to_path_buf(), mode));
			Ok(())
		}
	}

	fn handed(&self) -> Vec<(PathBuf, u32)> {
		self.0.borrow().clone()
	}
}

/// The account's uid in these tests: this process plays the account and
/// writes the outputs.
fn me() -> u32 {
	// SAFETY: geteuid takes no arguments and cannot fail.
	unsafe { libc::geteuid() }
}

fn os(list: &[&str]) -> Vec<OsString> {
	list.iter().map(OsString::from).collect()
}

fn imap(extra: &[&str]) -> Vec<OsString> {
	let mut line = os(&[
		"migrate",
		"imap",
		"--account",
		"alice",
		"--host",
		"imap.example.org",
		"--user",
		"alice",
	]);
	line.extend(os(extra));
	line
}

fn mode(path: &Path) -> u32 {
	fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
}

fn entries(dir: &Path) -> Vec<PathBuf> {
	fs::read_dir(dir)
		.unwrap()
		.map(|entry| entry.unwrap().path())
		.collect()
}

fn write(path: &Path, text: &str, mode: u32) {
	fs::create_dir_all(path.parent().unwrap()).unwrap();
	fs::write(path, text).unwrap();
	fs::set_permissions(path, Permissions::from_mode(mode)).unwrap();
}

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

/// Every refusal leaves no staging directory behind.
fn refused(line: &[OsString], home: &Path, table: &[Staged]) -> String {
	let error = Stage::prepare_with(line, home, me(), &Owner::default().chown(), table)
		.err()
		.expect("refused");
	assert!(entries(home).is_empty(), "a refused stage leaves nothing");
	error.to_string()
}

#[test]
fn symbolic_links_are_never_followed() {
	let (home, source) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
	let target = source.path().join("shadow");
	write(&target, "root secret", 0o600);
	let link = source.path().join("pw");
	std::os::unix::fs::symlink(&target, &link).unwrap();
	let message = refused(
		&imap(&["--password-file", link.to_str().unwrap()]),
		home.path(),
		table::STAGED,
	);
	assert!(
		message.contains("is a symbolic link; links are not followed"),
		"{message}"
	);

	let maildir = source.path().join("Maildir");
	write(&maildir.join("cur/1:2,"), "mail", 0o600);
	std::os::unix::fs::symlink(&target, maildir.join("cur/2:2,")).unwrap();
	let line = os(&[
		"import",
		"--account",
		"a",
		"--maildir",
		maildir.to_str().unwrap(),
	]);
	let message = refused(&line, home.path(), table::STAGED);
	assert!(
		message.contains("2:2,") && message.contains("is a symbolic link; links are not followed"),
		"{message}"
	);
}

#[test]
fn special_files_are_refused() {
	let (home, source) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
	let socket = source.path().join("pw.sock");
	let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
	let message = refused(
		&imap(&["--password-file", socket.to_str().unwrap()]),
		home.path(),
		table::STAGED,
	);
	assert!(message.contains("not a regular file"), "{message}");

	let maildir = source.path().join("Maildir");
	write(&maildir.join("cur/1:2,"), "mail", 0o600);
	let _inside = std::os::unix::net::UnixListener::bind(maildir.join("cur/sock")).unwrap();
	let line = os(&[
		"import",
		"--account",
		"a",
		"--maildir",
		maildir.to_str().unwrap(),
	]);
	let message = refused(&line, home.path(), table::STAGED);
	assert!(
		message.contains("sock") && message.contains("not a regular file"),
		"{message}"
	);
}

#[test]
fn the_size_bound_stops_a_copy() {
	let (home, source) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
	let small = [
		Staged {
			command: &["migrate", "imap"],
			arg: "password_file",
			kind: Kind::ReadFile {
				limit: 8,
				secret: true,
			},
		},
		Staged {
			command: &["import"],
			arg: "maildir",
			kind: Kind::ReadDir { limit: 10 },
		},
	];
	let file = source.path().join("pw");
	write(&file, "12345678", 0o600);
	let line = imap(&["--password-file", file.to_str().unwrap()]);
	Stage::prepare_with(&line, home.path(), me(), &Owner::default().chown(), &small)
		.expect("a file at the bound is copied");
	write(&file, "123456789", 0o600);
	let message = refused(&line, home.path(), &small);
	assert!(message.contains("larger than the 8 bytes"), "{message}");

	let maildir = source.path().join("Maildir");
	write(&maildir.join("cur/1"), "123456", 0o600);
	write(&maildir.join("new/2"), "123456", 0o600);
	let line = os(&[
		"import",
		"--account",
		"a",
		"--maildir",
		maildir.to_str().unwrap(),
	]);
	let message = refused(&line, home.path(), &small);
	assert!(
		message.contains("larger than the 10 bytes"),
		"the bound is the tree's total: {message}"
	);
}

fn mox_out(source: &Path, out: &Path) -> Vec<OsString> {
	write(&source.join("mox.conf"), "", 0o600);
	os(&[
		"migrate",
		"mox",
		"--from",
		source.to_str().unwrap(),
		"--passwords-out",
		out.to_str().unwrap(),
	])
}

#[test]
fn the_password_list_moves_to_the_requested_path_only_on_success() {
	for success in [true, false] {
		let (home, source, out) = (
			tempfile::tempdir().unwrap(),
			tempfile::tempdir().unwrap(),
			tempfile::tempdir().unwrap(),
		);
		let requested = out.path().join("passwords.txt");
		let line = mox_out(source.path(), &requested);
		let stage = Stage::prepare(&line, home.path(), me(), &Owner::default().chown()).unwrap();
		let staged = PathBuf::from(&stage.args()[5]);
		assert!(
			staged.starts_with(home.path()),
			"the run writes into the staging directory"
		);
		assert!(!requested.exists(), "nothing is written before the run");
		// The delegated run writes the list.
		write(&staged, "bob\tpassword\n", 0o600);
		stage.finish(success).unwrap();
		assert!(
			entries(home.path()).is_empty(),
			"the staging directory goes either way"
		);
		if success {
			assert_eq!(fs::read_to_string(&requested).unwrap(), "bob\tpassword\n");
			assert_eq!(mode(&requested), 0o600);
			let owner = fs::metadata(&requested).unwrap().uid();
			// SAFETY: geteuid takes no arguments and cannot fail.
			assert_eq!(
				owner,
				unsafe { libc::geteuid() },
				"owned by the root parent"
			);
		} else {
			assert!(
				!requested.exists(),
				"a failed run leaves nothing at the path"
			);
		}
	}
}

#[test]
fn an_output_is_refused_before_the_run_when_it_cannot_be_delivered() {
	let (home, source, out) = (
		tempfile::tempdir().unwrap(),
		tempfile::tempdir().unwrap(),
		tempfile::tempdir().unwrap(),
	);
	let existing = out.path().join("passwords.txt");
	write(&existing, "keep", 0o600);
	let message = refused(
		&mox_out(source.path(), &existing),
		home.path(),
		table::STAGED,
	);
	assert!(message.contains("already exists"), "{message}");
	assert_eq!(fs::read_to_string(&existing).unwrap(), "keep");
	let nowhere = out.path().join("missing/passwords.txt");
	let message = refused(
		&mox_out(source.path(), &nowhere),
		home.path(),
		table::STAGED,
	);
	assert!(message.contains("does not exist"), "{message}");

	let full = out.path().join("export");
	write(&full.join("cur/old"), "old", 0o600);
	let line = os(&[
		"export",
		"--account",
		"a",
		"--maildir",
		full.to_str().unwrap(),
	]);
	let message = refused(&line, home.path(), table::STAGED);
	assert!(message.contains("not an empty directory"), "{message}");
}

#[test]
fn a_link_left_by_the_account_is_not_moved() {
	let (home, source, out) = (
		tempfile::tempdir().unwrap(),
		tempfile::tempdir().unwrap(),
		tempfile::tempdir().unwrap(),
	);
	let secret = source.path().join("shadow");
	write(&secret, "root only", 0o600);
	let requested = out.path().join("passwords.txt");
	let stage = Stage::prepare(
		&mox_out(&source.path().join("mox"), &requested),
		home.path(),
		me(),
		&Owner::default().chown(),
	)
	.unwrap();
	std::os::unix::fs::symlink(&secret, PathBuf::from(&stage.args()[5])).unwrap();
	assert!(
		stage.finish(true).is_err(),
		"a link in place of the output is refused"
	);
	assert!(!requested.exists());
	assert!(entries(home.path()).is_empty());
	assert_eq!(fs::read_to_string(&secret).unwrap(), "root only");
}

#[test]
fn an_export_moves_its_tree_on_success_only() {
	for success in [true, false] {
		let (home, out) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
		let requested = out.path().join("backup/Maildir");
		let line = os(&[
			"export",
			"--account",
			"a",
			"--maildir",
			requested.to_str().unwrap(),
		]);
		let stage = Stage::prepare(&line, home.path(), me(), &Owner::default().chown()).unwrap();
		let staged = PathBuf::from(&stage.args()[4]);
		write(&staged.join("cur/1:2,S"), "mail", 0o644);
		write(&staged.join(".Work/cur/2:2,"), "work", 0o644);
		stage.finish(success).unwrap();
		assert!(entries(home.path()).is_empty());
		if success {
			assert_eq!(
				fs::read_to_string(requested.join(".Work/cur/2:2,")).unwrap(),
				"work"
			);
			assert_eq!(mode(&requested), 0o700);
			assert_eq!(mode(&requested.join("cur/1:2,S")), 0o600);
		} else {
			assert!(!requested.exists());
		}
	}
}
