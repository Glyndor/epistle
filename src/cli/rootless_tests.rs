use super::*;
use std::os::unix::process::ExitStatusExt;

#[test]
fn root_delegation_builds_exact_command_and_rootless_environment() {
	let args = ["stack", "logs", "--follow", "mail"].map(OsString::from);
	let mut spawned = false;
	let result = delegate(
		0,
		|| {
			Ok(Some(ServiceUser {
				uid: 987,
				home: "/var/lib/glyndor/epistle".into(),
			}))
		},
		|path| path == Path::new("/run/user/987"),
		Path::new("/usr/bin/epistle"),
		&args,
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
				home: "/var/lib/glyndor/epistle".into(),
			}))
		},
		|_| false,
		Path::new("/usr/bin/epistle"),
		&[],
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
			|_| panic!("no service account must not spawn"),
		)
		.unwrap();
		assert_eq!(result, None);
	}
}
