//! Tests for the images a verified update leaves unused.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::json;

use super::{Change, Engine, change, discard, references};

const OLD_CLAMAV: &str = "docker.io/clamav/clamav:1.5@sha256:old";
const NEW_CLAMAV: &str = "docker.io/clamav/clamav:1.5@sha256:new";
const LEGACY_MAIL: &str = "ghcr.io/glyndor/epistle:0.12.5";
const BASE_MAIL: &str = "gcr.io/distroless/static-debian13:nonroot@sha256:base";
const DATABASE: &str = "docker.io/library/postgres:18@sha256:pg";

/// A storage with named images and the containers made from them.
#[derive(Default)]
struct Storage {
	/// Reference -> image id.
	images: BTreeMap<String, String>,
	/// Ids a container was created from.
	used: BTreeSet<String>,
	/// Ids `remove` refuses, with the reason.
	refused: BTreeMap<String, String>,
	/// `used_image_ids` fails.
	blind: bool,
	/// The ids `remove` was asked for.
	removed: Vec<String>,
}

impl Storage {
	fn with(mut self, reference: &str, id: &str) -> Self {
		self.images.insert(reference.to_string(), id.repeat(64));
		self
	}
	fn used(mut self, id: &str) -> Self {
		self.used.insert(id.repeat(64));
		self
	}
}

impl Engine for Storage {
	fn image_id(&mut self, reference: &str) -> Result<Option<String>, String> {
		Ok(self.images.get(reference).cloned())
	}
	fn used_image_ids(&mut self) -> Result<BTreeSet<String>, String> {
		if self.blind {
			return Err("cannot list the containers".to_string());
		}
		Ok(self.used.clone())
	}
	fn remove(&mut self, id: &str) -> Result<(), String> {
		self.removed.push(id.to_string());
		if let Some(reason) = self.refused.get(id) {
			return Err(reason.clone());
		}
		self.images.retain(|_, held| held != id);
		Ok(())
	}
}

fn compose(images: &[(&str, &str)]) -> serde_json::Value {
	let services: serde_json::Map<String, serde_json::Value> = images
		.iter()
		.map(|(name, image)| (name.to_string(), json!({ "image": image })))
		.collect();
	json!({ "services": services })
}

fn moved() -> Change {
	Change {
		retired: vec![LEGACY_MAIL.to_string(), OLD_CLAMAV.to_string()],
		current: vec![
			BASE_MAIL.to_string(),
			DATABASE.to_string(),
			NEW_CLAMAV.to_string(),
		],
	}
}

fn storage() -> Storage {
	Storage::default()
		.with(LEGACY_MAIL, "a")
		.with(OLD_CLAMAV, "b")
		.with(BASE_MAIL, "c")
		.with(DATABASE, "d")
		.with(NEW_CLAMAV, "e")
		.used("c")
		.used("d")
		.used("e")
}

#[test]
fn the_references_are_the_image_of_every_service() {
	let found = references(&compose(&[
		("mail", LEGACY_MAIL),
		("clamav", OLD_CLAMAV),
		("freshclam", OLD_CLAMAV),
	]));
	assert_eq!(
		found.into_iter().collect::<Vec<_>>(),
		[OLD_CLAMAV, LEGACY_MAIL]
	);
}

#[test]
fn a_reference_that_cannot_be_one_argument_is_not_listed() {
	let found = references(&compose(&[
		("a", "--all"),
		("b", "two words"),
		("c", ""),
		("d", "line\nbreak"),
		("e", DATABASE),
	]));
	assert_eq!(found.into_iter().collect::<Vec<_>>(), [DATABASE]);
}

#[test]
fn only_what_the_new_compose_file_stopped_naming_is_retired() {
	let before = compose(&[
		("mail", LEGACY_MAIL),
		("db", DATABASE),
		("clamav", OLD_CLAMAV),
		("freshclam", OLD_CLAMAV),
	]);
	let after = compose(&[
		("mail", BASE_MAIL),
		("db", DATABASE),
		("clamav", NEW_CLAMAV),
		("freshclam", NEW_CLAMAV),
	]);
	let result = change(&before, &after);
	assert_eq!(result.retired, [OLD_CLAMAV, LEGACY_MAIL]);
	assert_eq!(
		result.current,
		[NEW_CLAMAV, DATABASE, BASE_MAIL]
			.map(String::from)
			.iter()
			.cloned()
			.collect::<BTreeSet<_>>()
			.into_iter()
			.collect::<Vec<_>>()
	);
	assert!(!result.retired.iter().any(|reference| reference == DATABASE));
}

#[test]
fn an_update_that_moves_nothing_retires_nothing() {
	let same = compose(&[("mail", BASE_MAIL), ("db", DATABASE)]);
	assert!(change(&same, &same).retired.is_empty());
}

#[test]
fn the_images_the_stack_left_behind_are_removed() {
	let mut engine = storage();
	let outcome = discard(&mut engine, &moved()).unwrap();
	assert_eq!(outcome.removed, [LEGACY_MAIL, OLD_CLAMAV]);
	assert!(outcome.kept.is_empty(), "{:?}", outcome.kept);
	assert_eq!(engine.removed, ["a".repeat(64), "b".repeat(64)]);
}

#[test]
fn the_image_the_new_compose_file_runs_is_never_removed() {
	// The old and the new reference are two names of one image, which is how
	// a re-tag looks from the storage.
	let mut engine = storage().with(OLD_CLAMAV, "e");
	let outcome = discard(&mut engine, &moved()).unwrap();
	assert_eq!(outcome.removed, [LEGACY_MAIL]);
	assert_eq!(
		outcome.kept,
		[format!(
			"{OLD_CLAMAV}: the new compose file runs this image"
		)]
	);
	assert!(!engine.removed.contains(&"e".repeat(64)));
}

#[test]
fn an_image_a_container_still_uses_stays() {
	for kind in ["a", "b"] {
		let mut engine = storage().used(kind);
		let outcome = discard(&mut engine, &moved()).unwrap();
		assert_eq!(outcome.removed.len(), 1, "{kind}: {outcome:?}");
		assert_eq!(outcome.kept.len(), 1, "{kind}: {outcome:?}");
		assert!(outcome.kept[0].ends_with("a container still uses it"));
		assert!(!engine.removed.contains(&kind.repeat(64)), "{kind}");
	}
}

#[test]
fn nothing_outside_the_retired_references_is_touched() {
	let mut engine = storage()
		.with("docker.io/library/redis:8", "f")
		.with("docker.io/clamav/clamav:1.4@sha256:other", "9");
	discard(&mut engine, &moved()).unwrap();
	assert_eq!(engine.removed, ["a".repeat(64), "b".repeat(64)]);
	assert!(engine.images.contains_key("docker.io/library/redis:8"));
	assert!(
		engine
			.images
			.contains_key("docker.io/clamav/clamav:1.4@sha256:other")
	);
}

#[test]
fn an_image_that_is_already_gone_is_not_an_error() {
	let mut engine = storage();
	engine.images.remove(LEGACY_MAIL);
	let outcome = discard(&mut engine, &moved()).unwrap();
	assert_eq!(outcome.removed, [OLD_CLAMAV]);
	assert!(outcome.kept.is_empty());
}

#[test]
fn an_image_the_engine_refuses_to_remove_stays_with_the_reason() {
	let mut engine = storage();
	engine.refused.insert(
		"a".repeat(64),
		"image has dependent child images".to_string(),
	);
	let outcome = discard(&mut engine, &moved()).unwrap();
	assert_eq!(outcome.removed, [OLD_CLAMAV]);
	assert_eq!(
		outcome.kept,
		[format!("{LEGACY_MAIL}: image has dependent child images")]
	);
}

#[test]
fn when_the_containers_cannot_be_listed_nothing_is_removed() {
	let mut engine = storage();
	engine.blind = true;
	let error = discard(&mut engine, &moved()).expect_err("cannot prove anything unused");
	assert!(error.contains("cannot list the containers"), "{error}");
	assert!(engine.removed.is_empty());
}

#[test]
fn a_change_with_nothing_retired_asks_the_engine_nothing() {
	let mut engine = storage();
	engine.blind = true;
	let outcome = discard(&mut engine, &Change::default()).unwrap();
	assert!(outcome.removed.is_empty() && outcome.kept.is_empty());
}
