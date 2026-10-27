use super::*;
use std::os::unix::process::ExitStatusExt;

#[test]
fn absent_socket_enables_the_current_user_socket_once() {
	let mut calls = 0;
	ensure_with(
		Path::new("/run/user/103"),
		|path| {
			assert_eq!(path, Path::new("/run/user/103/podman/podman.sock"));
			false
		},
		|command| {
			calls += 1;
			assert_eq!(command.get_program(), "systemctl");
			assert_eq!(
				command.get_args().collect::<Vec<_>>(),
				["--user", "enable", "--now", "podman.socket"],
				"socket repair must enable and start the user API socket"
			);
			Ok(ExitStatus::from_raw(0))
		},
	)
	.unwrap();
	assert_eq!(calls, 1, "absent socket must spawn systemctl exactly once");
}

#[test]
fn existing_socket_does_not_spawn_systemctl() {
	let mut calls = 0;
	ensure_with(
		Path::new("/run/user/103"),
		|_| true,
		|_| {
			calls += 1;
			Ok(ExitStatus::from_raw(0))
		},
	)
	.unwrap();
	assert_eq!(calls, 0, "existing socket must leave systemctl untouched");
}

#[test]
fn socket_start_failures_name_the_exact_repair_command() {
	for spawn_error in [false, true] {
		let result = ensure_with(
			Path::new("/run/user/103"),
			|_| false,
			|_| {
				if spawn_error {
					Err(io::Error::from(io::ErrorKind::NotFound))
				} else {
					Ok(ExitStatus::from_raw(1 << 8))
				}
			},
		);
		assert_eq!(
			result.err().map(|error| error.to_string()),
			Some("cannot enable Podman's API socket; run `systemctl --user enable --now podman.socket`".into()),
			"socket failure must print the exact systemctl repair"
		);
	}
}
