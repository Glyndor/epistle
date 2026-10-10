//! The `mail` service inside the rendered compose file: pasta
//! network mode, the keep-id mapping that lets epistle stay
//! mapped to the unprivileged mail uid, the `serve --config`
//! command, the bind-mount pair shape, the on/off depending_on
//! behaviour tied to `services.database`, the top-level
//! `services.mail` invariants (`networks` key absent, no
//! `x-podman-pod`), the image pinning for both the default
//! `ghcr.io/glyndor/epistle:<MAJOR.MINOR>` and an operator
//! override.

use super::render;
use super::*;

#[test]
fn name_is_epistle() {
	let value = render(&minimal_answers(), false);
	assert_eq!(value["name"], "epistle");
}

#[test]
fn mail_uses_pasta_and_keep_id() {
	let value = render(&minimal_answers(), false);
	let mail = &value["services"]["mail"];
	assert_eq!(mail["network_mode"], "pasta");
	assert_eq!(mail["userns_mode"], "keep-id:uid=65532,gid=65532");
	assert_eq!(mail["user"], "65532:65532");
}

#[test]
fn mail_lowers_unprivileged_port_start_inside_its_netns() {
	// The mail user is uid 65532, non-root inside the container's
	// network namespace, where the kernel default
	// `net.ipv4.ip_unprivileged_port_start` is 1024. The mail
	// service binds SMTP (25) and several IANA-reserved listeners
	// (465, 587, 143, 993, 4190, ...). Without lowering the sysctl,
	// the listener would fail with `Permission denied (os error 13)`
	// at startup. The setting is namespaced to the container's netns
	// and does not change anything on the host.
	let value = render(&minimal_answers(), false);
	let sysctls = &value["services"]["mail"]["sysctls"];
	assert_eq!(
		sysctls["net.ipv4.ip_unprivileged_port_start"], "0",
		"the mail service must lower ip_unprivileged_port_start inside its netns; got {sysctls}"
	);
}

#[test]
fn mail_command_uses_serve_and_config_path() {
	let value = render(&minimal_answers(), false);
	let command = value["services"]["mail"]["command"]
		.as_array()
		.expect("command is an array");
	assert_eq!(command.len(), 3);
	assert_eq!(command[0], "serve");
	assert_eq!(command[1], "--config");
	let path_str = command[2].as_str().expect("config path is a string");
	assert!(path_str.ends_with("mail.toml"), "got {path_str}");
	assert!(path_str.starts_with("/etc/epistle/"), "got {path_str}");
}

#[test]
fn mail_bind_volumes_have_identical_source_and_target_paths() {
	let value = render(&minimal_answers(), false);
	for mount in value["services"]["mail"]["volumes"].as_array().unwrap() {
		if mount["type"] == "bind" {
			assert_eq!(mount["source"], mount["target"]);
		}
	}
}

#[test]
fn mail_depends_on_db_when_database_is_on() {
	let value = render(&stack_answers(), true);
	let mail = &value["services"]["mail"];
	let depends_on = &mail["depends_on"];
	assert_eq!(depends_on["db"]["condition"], "service_healthy");
}

#[test]
fn mail_depends_only_on_clamav_when_database_is_off() {
	let value = render(&minimal_answers(), false);
	assert_eq!(
		value["services"]["mail"]["depends_on"]["clamav"]["condition"],
		"service_healthy"
	);
	assert!(value["services"]["mail"]["depends_on"].get("db").is_none());
}

#[test]
fn no_service_has_a_networks_key() {
	let value = render(&stack_answers(), true);
	for (name, service) in value["services"].as_object().unwrap() {
		assert!(
			service.get("networks").is_none(),
			"service {name} must not declare networks; podup will create one otherwise"
		);
	}
}

#[test]
fn no_x_podman_pod_anywhere() {
	let value = render(&stack_answers(), true);
	assert!(
		value.get("x-podman-pod").is_none(),
		"the compose file must not declare an x-podman-pod"
	);
}

#[test]
fn every_image_is_pinned() {
	let value = render(&stack_answers(), true);
	for (name, service) in value["services"].as_object().unwrap() {
		let image = service["image"]
			.as_str()
			.unwrap_or_else(|| panic!("service {name} has no image"));
		// A digest pin (`@sha256:...`) is the strongest form. A
		// tag other than `latest` is acceptable for the `mail`
		// service (the release workflow tags `0.8`, `0.8.0`); a
		// floating `:latest` would silently change what `init`
		// brings up. An untagged reference (no `@sha256:`, no
		// `:tag` at all) would default to `:latest` on the
		// daemon, which is exactly what the validator catches
		// for operator overrides. The previous shape
		// (`image.contains('@') || !image.ends_with(":latest")`)
		// accepted untagged references: a value like
		// `docker.io/library/postgres` has no `@` and does not
		// end in `:latest`, so the assertion passed while the
		// reference was still untagged. The new shape requires
		// either a digest or a `:` followed by a non-empty
		// non-`latest` tag.
		let (path, suffix) = image
			.rsplit_once('@')
			.or_else(|| image.rsplit_once(':'))
			.unwrap_or((image, ""));
		let pinned = !suffix.is_empty() && (image.contains("@sha256:") || suffix != "latest");
		assert!(
			pinned,
			"service {name} image {image:?} must be pinned (digest or non-latest tag); \
			 the part after the last `@` or `:` is {suffix:?}, the path part is {path:?}"
		);
	}
}

#[test]
fn mail_image_uses_cargo_pkg_version_by_default() {
	let value = render(&minimal_answers(), false);
	let image = value["services"]["mail"]["image"]
		.as_str()
		.expect("image is a string");
	let expected = default_image();
	assert_eq!(image, expected);
}

#[test]
fn mail_image_override_takes_precedence() {
	let value = render(&local_image_answers(), true);
	let image = value["services"]["mail"]["image"]
		.as_str()
		.expect("image is a string");
	assert_eq!(image, "localhost/epistle:dev");
}
