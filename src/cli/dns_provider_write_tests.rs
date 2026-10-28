//! The credential the configuration names has to reach the container.
//!
//! A host path is not visible inside the container unless the generated
//! compose file mounts it, so a `dns provider set --token-file` that only
//! rewrites `mail.toml` leaves a `mail` service that cannot build the
//! provider at all. The preview has to show the compose change too: a
//! preview that hides it is a preview of nothing.

use super::*;
use clap::Parser;
use std::os::unix::fs::PermissionsExt;

const TOKEN: &str = "/etc/epistle/secrets/dns.token";

/// A stack install whose generated compose file carries no token mount.
fn stack() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
	stack_with("hostname = 'mail.example.org'\ndata_dir = {data:?}\n", &[])
}

/// A stack install with the given configuration body and the given mounts in
/// the `mail` service of the generated compose file.
fn stack_with(
	body: &str,
	mounts: &[(&str, &str)],
) -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
	let dir = tempfile::tempdir().unwrap();
	let data = dir.path().join("data");
	std::fs::create_dir(&data).unwrap();
	let path = dir.path().join("mail.toml");
	std::fs::write(&path, body.replace("{data:?}", &format!("{data:?}"))).unwrap();
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
	let compose = crate::cli::init::compose_file_path(&data);
	std::fs::create_dir_all(compose.parent().unwrap()).unwrap();
	let volumes: Vec<serde_json::Value> = mounts
		.iter()
		.map(|(source, target)| {
			serde_json::json!({
				"type": "bind", "source": source, "target": target,
				"read_only": true, "bind": {"selinux": "Z"}
			})
		})
		.collect();
	let document = serde_json::json!({
		"services": {"mail": {"environment": {"TZ": "UTC"}, "volumes": volumes}}
	});
	std::fs::write(&compose, document.to_string()).unwrap();
	(dir, path, compose)
}

/// The `set` command with the given token flags, ready to run.
fn action(token_flags: &[&str]) -> DnsCli {
	let mut full = vec![
		"epistle",
		"dns",
		"provider",
		"set",
		"cloudflare",
		"--zone",
		"example.org",
	];
	full.extend_from_slice(token_flags);
	let crate::cli::Command::Dns { action, .. } =
		crate::cli::Cli::try_parse_from(full).unwrap().command
	else {
		unreachable!("dns arguments must select the dns command")
	};
	action
}

/// The mounts of the `mail` service, as the container engine reads them.
fn mail_mounts(compose: &std::path::Path) -> Vec<serde_json::Value> {
	let document: serde_json::Value =
		serde_json::from_str(&std::fs::read_to_string(compose).unwrap()).unwrap();
	document["services"]["mail"]["volumes"]
		.as_array()
		.cloned()
		.unwrap_or_default()
}

/// Whether the token file is mounted read-only at its own path.
fn mounted(compose: &std::path::Path, path: &str) -> bool {
	mail_mounts(compose).iter().any(|mount| {
		mount["source"] == path && mount["target"] == path && mount["read_only"] == true
	})
}

/// The token file the configuration names has to be mounted into `mail`, or
/// the container reads a path that does not exist inside it.
#[test]
fn a_token_file_is_mounted_into_the_mail_container() {
	let (_dir, path, compose) = stack();
	let (mut out, mut status) = (Vec::new(), Vec::new());
	let mut reached = None;
	let result = execute_with(
		&path,
		action(&["--token-file", TOKEN]),
		false,
		false,
		&mut out,
		&mut status,
		|_, action| {
			reached = Some(action);
			ExitCode::SUCCESS
		},
	);
	assert_eq!(result.unwrap(), ExitCode::SUCCESS);
	let config = Config::load(&path).unwrap();
	assert_eq!(
		config.dns.unwrap().token_file.as_ref(),
		Some(&std::path::PathBuf::from(TOKEN)),
		"the configuration has to name the token file"
	);
	assert!(
		mounted(&compose, TOKEN),
		"the token file has to be mounted read-only into mail: {}",
		std::fs::read_to_string(&compose).unwrap()
	);
	assert!(
		matches!(reached, Some(StackAction::Recreate { service }) if service == "mail"),
		"the container has to be recreated, or it keeps the mount it had"
	);
}

/// The preview has to show the compose change: a dry run that prints nothing
/// hides the change the command is about to make.
#[test]
fn the_dry_run_shows_the_compose_mount_and_writes_nothing() {
	let (_dir, path, compose) = stack();
	let before = std::fs::read_to_string(&compose).unwrap();
	let (mut out, mut status) = (Vec::new(), Vec::new());
	let result = execute_with(
		&path,
		action(&["--token-file", TOKEN]),
		true,
		false,
		&mut out,
		&mut status,
		|_, _| panic!("a dry run must not reach the stack"),
	);
	assert_eq!(result.unwrap(), ExitCode::SUCCESS);
	let printed = String::from_utf8(out).unwrap();
	assert!(
		printed.contains(TOKEN),
		"the preview has to name the token file it would mount: {printed}"
	);
	assert!(
		printed.contains("compose.yaml"),
		"the preview has to name the file it would change: {printed}"
	);
	assert_eq!(
		std::fs::read_to_string(&compose).unwrap(),
		before,
		"a dry run must not write the compose file"
	);
	assert!(
		status.is_empty(),
		"a dry run must not report a saved provider: {}",
		String::from_utf8_lossy(&status)
	);
}

/// The case the issue names: the configuration already points at the file, so
/// the configuration diff is empty, and the generated compose file still lacks
/// the mount. The preview has to show the compose change anyway, or it
/// previews nothing.
#[test]
fn the_dry_run_shows_the_compose_change_when_the_configuration_does_not_change() {
	let (_dir, path, _compose) = stack_with(
		&format!(
			"hostname = 'mail.example.org'\ndata_dir = {{data:?}}\n[dns]\nprovider = 'cloudflare'\nzone = 'example.org'\ntoken_file = '{TOKEN}'\n"
		),
		&[],
	);
	let before = std::fs::read_to_string(&path).unwrap();
	let (mut out, mut status) = (Vec::new(), Vec::new());
	let result = execute_with(
		&path,
		action(&["--token-file", TOKEN]),
		true,
		false,
		&mut out,
		&mut status,
		|_, _| panic!("a dry run must not reach the stack"),
	);
	assert_eq!(result.unwrap(), ExitCode::SUCCESS);
	let printed = String::from_utf8(out).unwrap();
	assert!(
		printed.contains("compose.yaml") && printed.contains(TOKEN),
		"the preview has to show the compose change: {printed}"
	);
	assert_eq!(
		std::fs::read_to_string(&path).unwrap(),
		before,
		"a dry run must not write the configuration"
	);
	assert!(
		status.is_empty(),
		"a dry run must not report a saved provider: {}",
		String::from_utf8_lossy(&status)
	);
}

/// The mount of the credential the configuration carried before leaves the
/// container with it: a container that keeps the old token mounted still
/// exposes it.
#[test]
fn the_mount_of_the_previous_token_file_is_removed() {
	let previous = "/etc/epistle/secrets/old.token";
	let (_dir, path, compose) = stack_with(
		&format!(
			"hostname = 'mail.example.org'\ndata_dir = {{data:?}}\n[dns]\nprovider = 'cloudflare'\nzone = 'example.org'\ntoken_file = '{previous}'\n"
		),
		&[(previous, previous)],
	);
	let (mut out, mut status) = (Vec::new(), Vec::new());
	let result = execute_with(
		&path,
		action(&["--token-file", TOKEN]),
		false,
		false,
		&mut out,
		&mut status,
		|_, _| ExitCode::SUCCESS,
	);
	assert_eq!(result.unwrap(), ExitCode::SUCCESS);
	assert!(
		!mounted(&compose, previous),
		"the old token file must not stay mounted: {}",
		std::fs::read_to_string(&compose).unwrap()
	);
	assert!(mounted(&compose, TOKEN));
}

/// A token the environment holds is forwarded to the container as `${NAME}`,
/// which is the only way the container reads it.
#[test]
fn a_token_environment_variable_is_forwarded_to_the_container() {
	let (_dir, path, compose) = stack();
	let (mut out, mut status) = (Vec::new(), Vec::new());
	let result = execute_with(
		&path,
		action(&["--token-env", "EPI_DNS_TOKEN"]),
		false,
		false,
		&mut out,
		&mut status,
		|_, _| ExitCode::SUCCESS,
	);
	assert_eq!(result.unwrap(), ExitCode::SUCCESS);
	let document: serde_json::Value =
		serde_json::from_str(&std::fs::read_to_string(&compose).unwrap()).unwrap();
	assert_eq!(
		document["services"]["mail"]["environment"]["EPI_DNS_TOKEN"], "${EPI_DNS_TOKEN}",
		"the token variable has to reach the container"
	);
	assert!(
		mail_mounts(&compose).is_empty(),
		"a token in the environment is not a file to mount"
	);
}
