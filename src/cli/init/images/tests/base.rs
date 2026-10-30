//! Tests for the image manifest and for the compose file using it.

use super::{MANIFEST, clamav, mail_base, major, parse, postgres};

fn pinned(reference: &str) -> bool {
	let Some((name, digest)) = reference.split_once("@sha256:") else {
		return false;
	};
	let tagged = name
		.rsplit_once(':')
		.is_some_and(|(_, tag)| !tag.contains('/'));
	tagged && digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit())
}

#[test]
fn the_manifest_names_the_three_images_pinned_by_tag_and_digest() {
	let images = parse(MANIFEST).expect("deploy/images/Dockerfile parses");
	assert_eq!(
		images.keys().map(String::as_str).collect::<Vec<_>>(),
		["clamav", "mail", "postgres"]
	);
	for (name, reference) in &images {
		assert!(pinned(reference), "{name}: {reference} is not tag@sha256");
	}
}

#[test]
fn the_rendered_compose_uses_exactly_the_manifest_images() {
	let text = super::super::super::compose::render_for(
		&super::super::super::compose::stack_answers(),
		true,
	)
	.expect("render");
	let value: serde_json::Value = serde_json::from_str(&text).expect("json");
	let services = &value["services"];
	assert_eq!(services["db"]["image"], postgres());
	assert_eq!(services["clamav"]["image"], clamav());
	assert_eq!(services["freshclam"]["image"], clamav());
	assert_eq!(services["mail"]["image"], mail_base());
	assert!(postgres().starts_with("docker.io/library/postgres:18@sha256:"));
	assert!(clamav().starts_with("docker.io/clamav/clamav:1.5@sha256:"));
}

#[test]
fn the_container_image_runs_on_the_same_base_as_the_stack() {
	let containerfile = include_str!("../../../../../Containerfile");
	let runtime = containerfile
		.lines()
		.filter_map(|line| line.strip_prefix("FROM "))
		.next_back()
		.expect("a runtime stage");
	assert_eq!(runtime.trim(), mail_base());
}

#[test]
fn a_reference_without_a_digest_or_a_stage_name_is_refused() {
	for text in [
		"FROM docker.io/clamav/clamav:1.4 AS clamav\n",
		"FROM docker.io/clamav/clamav@sha256:b5b910ce43d595bf8a2fe401e34db56434602b2c755b7c2b07f00c917d04d469 AS clamav\n",
		"FROM docker.io/clamav/clamav:1.4@sha256:b5b9 AS clamav\n",
		"FROM docker.io/clamav/clamav:1.4@sha256:b5b910ce43d595bf8a2fe401e34db56434602b2c755b7c2b07f00c917d04d469\n",
		"RUN true\n",
	] {
		assert!(parse(text).is_err(), "{text:?} must be refused");
	}
	assert!(parse("# only a comment\n\n").is_ok());
}
#[test]
fn the_major_is_the_leading_number_of_the_tag() {
	assert_eq!(major(postgres()), Some(18));
	assert_eq!(major("docker.io/library/postgres:18.6-alpine"), Some(18));
	assert_eq!(major("docker.io/library/postgres:19@sha256:00"), Some(19));
	assert_eq!(major("localhost:5000/postgres"), None);
	assert_eq!(major("postgres:latest"), None);
}
