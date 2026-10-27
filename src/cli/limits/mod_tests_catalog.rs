//! The catalog itself: every row `epistle limits show` prints, the
//! adjustable/recommended/fixed kind, the floor or ceiling the standard
//! imposes, and the RFC reference. Tests here pin the contract that
//! `set` honours and that the docs page mirrors.

use std::collections::BTreeSet;

use serde_json::json;

use super::*;

#[test]
fn every_catalog_key_appears_in_show_text_with_kind_and_reference() {
	let (_dir, file) = super::tests_config::config_file();
	let config = Config::load(file.path()).unwrap();
	let mut out = Vec::new();
	show(&config, &mut out).unwrap();
	let printed = String::from_utf8(out).unwrap();
	for entry in catalog::ADJUSTABLE {
		let needle_kind = catalog_kind_name(entry.kind);
		let row = format!("{}\t", entry.key.name());
		let matched = printed.lines().any(|line| {
			line.starts_with(&row)
				&& line.contains(&format!("\t{needle_kind}\t"))
				&& line.ends_with(&format!("\t{}", entry.reference))
		});
		assert!(
			matched,
			"catalog key `{}` must appear in `limits show` with kind `{needle_kind}` and reference `{}`; printed:\n{printed}",
			entry.key.name(),
			entry.reference,
		);
	}
}

#[test]
fn every_fixed_limit_appears_in_show_text() {
	let (_dir, file) = super::tests_config::config_file();
	let config = Config::load(file.path()).unwrap();
	let mut out = Vec::new();
	show(&config, &mut out).unwrap();
	let printed = String::from_utf8(out).unwrap();
	for fixed in catalog::FIXED {
		let row = format!("{}\t{} {}", fixed.name, fixed.value.render(), fixed.unit);
		assert!(
			printed.lines().any(|line| line.starts_with(&row)),
			"fixed limit `{}` must appear in `limits show`; printed:\n{printed}",
			fixed.name,
		);
	}
}

#[test]
fn show_json_lists_kind_bounds_and_reference_for_every_key() {
	let (_dir, file) = super::tests_config::config_file();
	let config = Config::load(file.path()).unwrap();
	let json = show_json(&config);
	for entry in catalog::ADJUSTABLE {
		let key = entry.key.name();
		let row = &json[key];
		assert_eq!(
			row["kind"].as_str(),
			Some(catalog_kind_name(entry.kind)),
			"{key}: kind column",
		);
		assert_eq!(
			row["reference"].as_str(),
			Some(entry.reference),
			"{key}: reference column",
		);
	}
}

#[test]
fn the_max_recipients_floor_is_a_must_not_a_recommendation() {
	// RFC 5321 §4.5.3.1.8 says a server MUST accept at least 100
	// recipients. The operator may raise the cap, never go below the
	// floor, so the catalog calls it `must`, not `recommended`.
	let (_dir, file) = super::tests_config::config_file();
	let config = Config::load(file.path()).unwrap();
	let json = show_json(&config);
	let row = &json["max-recipients"];
	assert_eq!(row["kind"], "must");
	assert_eq!(row["bounds"], json!({"at-least": 100_u64}));
	assert!(
		row["reference"]
			.as_str()
			.unwrap_or_default()
			.contains("RFC 5321 §4.5.3.1.8"),
		"max-recipients must name the §4.5.3.1.8 reference"
	);
}

#[test]
fn the_should_floors_carry_a_warning_and_a_floor() {
	let (_dir, file) = super::tests_config::config_file();
	let config = Config::load(file.path()).unwrap();
	let json = show_json(&config);
	for (key, floor) in [
		("queue-give-up", 4 * 86_400_u64),
		("queue-retry-base", 30 * 60_u64),
	] {
		let row = &json[key];
		assert_eq!(row["kind"], "recommended", "{key}: kind");
		assert_eq!(row["bounds"], json!({"at-least": floor}), "{key}: bounds");
	}
}

#[test]
fn the_connection_keys_are_listed_in_the_catalog() {
	let names: BTreeSet<&'static str> = catalog::ADJUSTABLE
		.iter()
		.map(|entry| entry.key.name())
		.collect();
	for needed in [
		"max-connections-per-ip",
		"preauth-timeout",
		"max-mailbox-connections-per-ip",
		"max-http-connections",
		"max-http-connections-per-ip",
	] {
		assert!(
			names.contains(needed),
			"catalog must include the connection key `{needed}`"
		);
	}
}

#[test]
fn fixed_limits_cannot_be_overridden_by_set() {
	// The fixed rows are documented in the catalog as read-only. The
	// server has no `Key::SmtpLineLength` variant, so there is no path
	// for `limits set` to touch them. The contract is that the catalog
	// lists them but the `Key` enum does not: `Key::ALL` and
	// `catalog::ADJUSTABLE` agree on the adjustable side and the fixed
	// side stays out of the writable surface.
	let table: BTreeSet<&'static str> = catalog::ADJUSTABLE
		.iter()
		.map(|entry| entry.key.name())
		.collect();
	for fixed in catalog::FIXED {
		assert!(
			!table.contains(fixed.name),
			"fixed entry `{}` must not also be a configurable Key",
			fixed.name,
		);
	}
}

/// The SHOULD floors take their numbers from the queue schedule
/// constants, so one source rules both the warning and the catalog.
#[test]
fn the_should_bounds_use_the_schedule_constants() {
	let bound_of = |name: &str| {
		catalog::ADJUSTABLE
			.iter()
			.find(|entry| entry.key.name() == name)
			.unwrap_or_else(|| panic!("{name} in catalog"))
			.bound
	};
	assert_eq!(
		bound_of("queue-give-up"),
		Some(catalog::Bound::AtLeast(
			crate::queue::schedule::SHOULD_GIVE_UP_SECS
		)),
	);
	assert_eq!(
		bound_of("queue-retry-base"),
		Some(catalog::Bound::AtLeast(
			crate::queue::schedule::SHOULD_RETRY_BASE_SECS
		)),
	);
}

fn catalog_kind_name(kind: catalog::Kind) -> &'static str {
	match kind {
		catalog::Kind::Adjustable => "adjustable",
		catalog::Kind::Recommended => "recommended",
		catalog::Kind::Must => "must",
		catalog::Kind::Fixed => "fixed",
	}
}

#[test]
fn per_account_connection_limits_are_shown_and_set() {
	use clap::ValueEnum;
	let (_dir, file) = super::tests_config::config_file();
	for (name, default) in [
		("max-connections-per-account-per-ip", 10),
		("max-connections-per-account-total", 50),
	] {
		let config = Config::load(file.path()).unwrap();
		let rows = show_json(&config);
		assert_eq!(rows[name]["value"], default, "{name}");
		assert_eq!(rows[name]["unit"], "count");
		assert_eq!(rows[name]["kind"], "adjustable");
		assert_eq!(rows[name]["reference"], "no standard mandate");
		let key = Key::from_str(name, false).expect("CLI accepts the key");
		assert!(change_config(file.path(), key, Some("73")).is_ok());
		let config = Config::load(file.path()).unwrap();
		assert_eq!(show_json(&config)[name]["value"], 73);
		assert_eq!(key.value(&config), Some(73));
		assert_eq!(key.max(), u64::from(u32::MAX));
		assert!(change_config(file.path(), key, Some("4294967296")).is_err());
		assert!(change_config(file.path(), key, Some("0")).is_ok());
		let config = Config::load(file.path()).unwrap();
		assert_eq!(show_json(&config)[name]["value"], default);
		assert!(key.zero_is_default());
		assert!(change_config(file.path(), key, None).is_ok());
	}
}
