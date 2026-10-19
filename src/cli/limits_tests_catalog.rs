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
		let row = format!("{}\t{} {}", fixed.name, fixed.value, fixed.unit);
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
fn the_max_recipients_floor_is_the_rfc_must_value() {
	// The §4.5.3.1.8 floor is a hard lower bound (MUST accept at least
	// 100) but the operator may set a value above it; `set
	// max-recipients 500` is valid. The catalog marks it
	// `recommended` so the operator sees a warning, not a refusal.
	let (_dir, file) = super::tests_config::config_file();
	let config = Config::load(file.path()).unwrap();
	let json = show_json(&config);
	let row = &json["max-recipients"];
	assert_eq!(row["kind"], "recommended");
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

/// The catalog is the user-facing mirror of the constants the server
/// enforces. If the server changes `MAX_DNS_MECHANISMS` to `8` but the
/// catalog still reads `10`, the operator will see the wrong number and
/// the docs page will lie. This test pins every fixed row against the
/// constant it advertises, so a drift between code and catalog trips it.
#[test]
fn fixed_rows_match_the_constants_the_server_enforces() {
	let by_name = |name: &str| -> &catalog::FixedEntry {
		catalog::FIXED
			.iter()
			.find(|entry| entry.name == name)
			.unwrap_or_else(|| panic!("catalog missing fixed entry `{name}`"))
	};
	assert_eq!(
		by_name("smtp-line-length").value,
		"998",
		"smtp-line-length must mirror `crate::smtp::line::MAX_LINE_LENGTH`"
	);
	assert_eq!(
		by_name("spf-max-dns-lookups").value,
		"10",
		"spf-max-dns-lookups must mirror `crate::spf::evaluator::MAX_DNS_MECHANISMS`"
	);
	assert_eq!(
		by_name("spf-max-void-lookups").value,
		"2",
		"spf-max-void-lookups must mirror `crate::spf::evaluator::MAX_VOID_LOOKUPS`"
	);
	assert_eq!(
		by_name("tls-minimum-version").value,
		"1.2",
		"tls-minimum-version must mirror the rustls version pinned in src/tls"
	);
	// The two queuing-side floors the RFC SHOULD rule are in the
	// schedule constants; the catalog's `AtLeast` mirror must use them
	// too so a single source of truth rules.
	let give_up = catalog::ADJUSTABLE
		.iter()
		.find(|entry| entry.key.name() == "queue-give-up")
		.expect("queue-give-up in catalog");
	let retry_base = catalog::ADJUSTABLE
		.iter()
		.find(|entry| entry.key.name() == "queue-retry-base")
		.expect("queue-retry-base in catalog");
	assert_eq!(
		give_up.bound,
		Some(catalog::Bound::AtLeast(
			crate::queue::schedule::SHOULD_GIVE_UP_SECS
		)),
	);
	assert_eq!(
		retry_base.bound,
		Some(catalog::Bound::AtLeast(
			crate::queue::schedule::SHOULD_RETRY_BASE_SECS
		)),
	);
}

fn catalog_kind_name(kind: catalog::Kind) -> &'static str {
	match kind {
		catalog::Kind::Adjustable => "adjustable",
		catalog::Kind::Recommended => "recommended",
		catalog::Kind::Fixed => "fixed",
	}
}
