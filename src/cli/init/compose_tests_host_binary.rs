//! Tests for the host-binary mode of the generated compose
//! file: the default answers (no `image`) produce a `mail`
//! service that runs the host's statically linked
//! `/usr/bin/epistle` bind-mounted read-only on the
//! digest-pinned `gcr.io/distroless/static-debian12:nonroot`
//! base, while an explicit `image` answer preserves the old
//! shape. Both shapes share volumes, network mode, the
//! `serve --config ...` command and the keep-id mapping.

use super::render;
use super::*;

const DISTROLESS_BASE: &str = "gcr.io/distroless/static-debian12:nonroot@sha256:52dcfbabb7457ea47c82f6e13af8c8a4a1d9f7b0145142b3ecab20f2b888411d";

#[test]
fn default_mode_image_is_the_pinned_distroless_base() {
	let value = render(&minimal_answers(), false);
	let image = value["services"]["mail"]["image"]
		.as_str()
		.expect("default mail image is a string");
	assert_eq!(
		image, DISTROLESS_BASE,
		"the default mail image must be the distroless base pinned by the Containerfile digest; got {image:?}"
	);
}

#[test]
fn default_mode_binds_host_binary_read_only_without_selinux_relabel() {
	// The bind mount for `/usr/bin/epistle` must use the long
	// syntax (so `read_only` is honoured) and must NOT carry the
	// `Z` (private SELinux relabel) option: the path is a system
	// file owned by root after the .deb install, and relabelling it
	// would silently change its on-disk label.
	let value = render(&minimal_answers(), false);
	let mut found = false;
	for mount in value["services"]["mail"]["volumes"].as_array().unwrap() {
		if mount.get("type").and_then(|t| t.as_str()) != Some("bind") {
			continue;
		}
		let source = mount["source"].as_str().unwrap_or("");
		let target = mount["target"].as_str().unwrap_or("");
		if source == "/usr/bin/epistle" && target == "/usr/bin/epistle" {
			found = true;
			assert_eq!(
				mount["read_only"], true,
				"the host-binary mount must be read_only"
			);
			assert!(
				mount.get("bind").is_none(),
				"the host-binary mount must not carry a bind.selinux option; got {mount:?}"
			);
		}
	}
	assert!(
		found,
		"default mode must bind-mount the host binary read-only; volumes: {:?}",
		value["services"]["mail"]["volumes"]
	);
}

#[test]
fn default_mode_entrypoint_is_the_host_binary() {
	let value = render(&minimal_answers(), false);
	let entrypoint = value["services"]["mail"]["entrypoint"]
		.as_array()
		.expect("entrypoint is an array");
	assert_eq!(entrypoint.len(), 1);
	assert_eq!(entrypoint[0], "/usr/bin/epistle");
}

#[test]
fn default_mode_keeps_the_serve_command_with_config_path() {
	// The default compose shape must carry the same
	// `serve --config <path>` command today uses; only the
	// image and the binary mount change between modes.
	let value = render(&minimal_answers(), false);
	let command = value["services"]["mail"]["command"]
		.as_array()
		.expect("command is an array");
	assert_eq!(command[0], "serve");
	assert_eq!(command[1], "--config");
	assert!(
		command[2]
			.as_str()
			.expect("config path is a string")
			.ends_with("mail.toml")
	);
}

#[test]
fn custom_image_mode_does_not_mount_the_host_binary() {
	let value = render(&local_image_answers(), true);
	for mount in value["services"]["mail"]["volumes"].as_array().unwrap() {
		if let (Some(source), Some(target)) = (
			mount.get("source").and_then(|s| s.as_str()),
			mount.get("target").and_then(|s| s.as_str()),
		) {
			assert!(
				!(source == "/usr/bin/epistle" && target == "/usr/bin/epistle"),
				"the custom image mode must NOT bind-mount the host binary; got mount {mount:?}"
			);
		}
	}
}

#[test]
fn custom_image_mode_uses_the_operator_image() {
	let value = render(&local_image_answers(), true);
	assert_eq!(
		value["services"]["mail"]["image"], "localhost/epistle:dev",
		"the custom image mode must render the operator's image"
	);
}

#[test]
fn custom_image_mode_has_no_entrypoint_override() {
	let value = render(&local_image_answers(), true);
	// Custom image mode relies on the image's own ENTRYPOINT and
	// does not override it. Anything the image author baked in
	// takes over (the project-default `ghcr.io/glyndor/epistle`
	// image sets ENTRYPOINT ["/usr/bin/epistle"] and CMD
	// ["serve", "--config", ...]; the custom image mode relies
	// on the same shape).
	assert!(
		value["services"]["mail"].get("entrypoint").is_none(),
		"custom image mode must not declare an entrypoint override"
	);
}

#[test]
fn default_mode_record_managed_shape_in_top_level_marker() {
	// The stack update path needs to know whether the file came
	// from the default (host binary) shape or the operator
	// image: a `stack update` on a default file must restart
	// the mail service rather than pull a different image.
	// The marker is `x-epistle-managed-image` set to true when
	// the answers leave `image` unset, false when the operator
	// pinned an image of their own.
	for (image, expected) in [
		(None, true),
		(Some("localhost/epistle:dev".to_string()), false),
	] {
		let mut answers = stack_answers();
		answers.image = image;
		assert_eq!(
			render(&answers, true)["x-epistle-managed-image"],
			expected,
			"the top-level marker must reflect whether the answers set an image"
		);
	}
}
