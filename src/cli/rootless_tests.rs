use super::*;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;

#[test]
fn root_delegation_builds_exact_command_and_rootless_environment() {
	let args = ["stack", "logs", "--follow", "mail"].map(OsString::from);
	let mut spawned = false;
	let result = delegate(
		0,
		|| {
			Ok(Some(ServiceUser {
				uid: 987,
				gid: 987,
				home: "/var/lib/glyndor/epistle".into(),
			}))
		},
		|path| path == Path::new("/run/user/987"),
		Path::new("/usr/bin/epistle"),
		&args,
		|args, user| Stage::prepare(args, &user.home, &|_, _| panic!("nothing to stage")),
		|command| {
			spawned = true;
			assert_eq!(command.get_program(), "runuser");
			assert_eq!(
				command.get_args().collect::<Vec<_>>(),
				[
					"-u",
					"glyndor-epistle",
					"--",
					"/usr/bin/epistle",
					"stack",
					"logs",
					"--follow",
					"mail"
				],
				"delegation must preserve the executable and every argument"
			);
			let env: std::collections::BTreeMap<_, _> = command.get_envs().collect();
			for (key, value) in [
				("HOME", "/var/lib/glyndor/epistle"),
				("XDG_RUNTIME_DIR", "/run/user/987"),
				("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/987/bus"),
			] {
				assert_eq!(
					env.get(std::ffi::OsStr::new(key)).copied().flatten(),
					Some(std::ffi::OsStr::new(value)),
					"delegation must set the rootless environment"
				);
			}
			assert_eq!(
				command.get_current_dir(),
				Some(Path::new("/var/lib/glyndor/epistle"))
			);
			Ok(ExitStatus::from_raw(7 << 8))
		},
	)
	.unwrap();
	assert!(
		spawned,
		"root init and stack must spawn runuser for the service account"
	);
	assert_eq!(
		result,
		Some(ExitCode::from(7)),
		"delegation must propagate the child's exit code"
	);
}

#[test]
fn missing_runtime_names_the_linger_repair() {
	let result = delegate(
		0,
		|| {
			Ok(Some(ServiceUser {
				uid: 987,
				gid: 987,
				home: "/var/lib/glyndor/epistle".into(),
			}))
		},
		|_| false,
		Path::new("/usr/bin/epistle"),
		&[],
		|_, _| panic!("missing runtime must not stage"),
		|_| panic!("missing runtime must not spawn"),
	);
	assert_eq!(
		result.err().map(|error| error.to_string()),
		Some("/run/user/987 does not exist; run `loginctl enable-linger glyndor-epistle`".into()),
		"missing runtime must tell the operator exactly how to enable linger"
	);
}

#[test]
fn nonroot_and_uninstalled_account_continue_without_spawning() {
	for euid in [0, 1000] {
		let result = delegate(
			euid,
			|| Ok(None),
			|_| panic!("no service account must not probe runtime"),
			Path::new("/usr/bin/epistle"),
			&[],
			|_, _| panic!("no service account must not stage"),
			|_| panic!("no service account must not spawn"),
		)
		.unwrap();
		assert_eq!(result, None);
	}
}

/// A root run (`euid` 0, injected) of `args` against an account whose home
/// is `home`, with `child` standing in for the account's run.
fn root_run(
	home: &Path,
	args: &[OsString],
	handed: &std::cell::RefCell<Vec<PathBuf>>,
	child: impl FnOnce(&[&std::ffi::OsStr]) -> i32,
) -> io::Result<Option<ExitCode>> {
	delegate(
		0,
		|| {
			Ok(Some(ServiceUser {
				uid: 987,
				gid: 986,
				home: home.to_path_buf(),
			}))
		},
		|_| true,
		Path::new("/usr/bin/epistle"),
		args,
		|args, user| {
			Stage::prepare(args, &user.home, &|_, rel| {
				handed.borrow_mut().push(rel.to_path_buf());
				Ok(())
			})
		},
		|command| {
			let argv: Vec<_> = command.get_args().skip(4).collect();
			Ok(ExitStatus::from_raw(child(&argv) << 8))
		},
	)
}

#[test]
fn a_root_run_hands_the_account_a_copy_of_the_password_file() {
	let (home, operator) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
	let password = operator.path().join("srcpw");
	std::fs::write(&password, "s3cret\n").unwrap();
	let args = [
		"migrate",
		"imap",
		"--account",
		"alice",
		"--host",
		"imap.example.org",
		"--user",
		"alice",
		"--password-file",
		password.to_str().unwrap(),
	]
	.map(OsString::from);
	let handed = std::cell::RefCell::new(Vec::new());
	let code = root_run(home.path(), &args, &handed, |argv| {
		let staged = Path::new(argv[9]);
		assert!(
			staged.starts_with(home.path()),
			"the account must be handed a copy in its home, not {}",
			staged.display()
		);
		assert_eq!(std::fs::read_to_string(staged).unwrap(), "s3cret\n");
		0
	})
	.unwrap();
	assert_eq!(code, Some(ExitCode::SUCCESS));
	assert!(
		handed.borrow().iter().any(|rel| rel.ends_with("srcpw")),
		"the copy goes to the account: {:?}",
		handed.borrow()
	);
	assert_eq!(
		std::fs::read_dir(home.path()).unwrap().count(),
		0,
		"the staging directory is removed after the run"
	);
}

#[test]
fn a_root_run_moves_the_password_list_only_when_the_account_succeeds() {
	for (exit, kept) in [(0, true), (1, false)] {
		let (home, operator) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
		std::fs::write(operator.path().join("mox.conf"), "").unwrap();
		let requested = operator.path().join("passwords.txt");
		let args = [
			"migrate",
			"mox",
			"--from",
			operator.path().to_str().unwrap(),
			"--passwords-out",
			requested.to_str().unwrap(),
		]
		.map(OsString::from);
		let handed = std::cell::RefCell::new(Vec::new());
		let code = root_run(home.path(), &args, &handed, |argv| {
			std::fs::write(argv[5], "bob\tpw\n").unwrap();
			exit
		})
		.unwrap();
		assert_eq!(code, Some(ExitCode::from(exit as u8)));
		assert_eq!(requested.exists(), kept);
		assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
	}
}
