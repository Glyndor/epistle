//! The protocol limits in the catalog against the code that enforces them.
//! A limit the code defines with no row in the catalog fails here, so a new
//! one cannot be added unlisted; a MUST stays at the number the RFC gives;
//! and the class of every row agrees with how `set` treats it.

use std::collections::BTreeSet;

use clap::ValueEnum;

use super::*;
use catalog::{Class, FixedValue, Kind};

/// The files that hold the limits a client can run into, with the module
/// path the catalog names them by.
const SCANNED: &[(&str, &str)] = &[
	("smtp::command", include_str!("../smtp/command.rs")),
	("smtp::line", include_str!("../smtp/line.rs")),
	("smtp::session", include_str!("../smtp/session/mod.rs")),
	("smtp::trace", include_str!("../smtp/trace.rs")),
	("smtp::server::run", include_str!("../smtp/server/run.rs")),
	("pop3::command", include_str!("../pop3/command.rs")),
	("pop3::server", include_str!("../pop3/server.rs")),
	("imap::command", include_str!("../imap/command/mod.rs")),
	("imap::keyword", include_str!("../imap/keyword.rs")),
	("imap::server", include_str!("../imap/server.rs")),
	(
		"managesieve::store",
		include_str!("../managesieve/store.rs"),
	),
	(
		"managesieve::session",
		include_str!("../managesieve/session.rs"),
	),
	("sieve::interp", include_str!("../sieve/interp.rs")),
	("sieve::parser", include_str!("../sieve/parser.rs")),
	("api::jmap::limits", include_str!("../api/jmap/limits.rs")),
	(
		"util::validation",
		include_str!("../util/validation/mod.rs"),
	),
	(
		"util::mailbox_path",
		include_str!("../util/mailbox_path.rs"),
	),
	("spf::evaluator", include_str!("../spf/evaluator.rs")),
];

/// The catalog sources a limit constant has to be named in.
const CATALOG_SOURCES: &[&str] = &[
	include_str!("limits_protocol.rs"),
	include_str!("limits_catalog.rs"),
	include_str!("limits_keys.rs"),
];

/// Limit constants in the scanned files that are not a row of their own,
/// each with the reason.
const NOT_A_ROW: &[(&str, &str)] = &[
	(
		"pop3::server::MAX_CONNECTIONS",
		"the protocol default of max-connections-per-listener",
	),
	(
		"imap::server::MAX_CONNECTIONS",
		"the protocol default of max-connections-per-listener",
	),
	(
		"spf::evaluator::MAX_DEPTH",
		"bounded by spf-max-dns-lookups, every include costs one lookup",
	),
];

/// Whether `text` names `path` as a whole identifier path.
fn names(text: &str, path: &str) -> bool {
	text.match_indices(path).any(|(start, _)| {
		let before = text[..start].chars().next_back();
		let after = text[start + path.len()..].chars().next();
		let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
		!before.is_some_and(word) && !after.is_some_and(word)
	})
}

/// The `const NAME: <integer>` declarations of a file whose name reads as a
/// limit.
fn limit_constants(source: &str) -> Vec<&str> {
	source
		.lines()
		.filter_map(|line| {
			let line = line.trim_start();
			let line = ["pub(crate) ", "pub(super) ", "pub "]
				.iter()
				.find_map(|prefix| line.strip_prefix(prefix))
				.unwrap_or(line);
			let rest = line.strip_prefix("const ")?;
			let (name, ty) = rest.split_once(": ")?;
			let integer = ["usize", "u8", "u16", "u32", "u64"]
				.iter()
				.any(|t| ty.starts_with(&format!("{t} ")));
			let limit =
				name.starts_with("MAX_") || name.starts_with("MIN_") || name.ends_with("_LIMIT");
			(integer && limit).then_some(name)
		})
		.collect()
}

#[test]
fn every_limit_constant_in_the_protocol_files_has_a_row() {
	let mut unlisted = Vec::new();
	let mut seen = 0;
	for (module, source) in SCANNED {
		for name in limit_constants(source) {
			seen += 1;
			let path = format!("{module}::{name}");
			let listed = CATALOG_SOURCES.iter().any(|text| names(text, &path));
			let excused = NOT_A_ROW.iter().any(|(excused, _)| *excused == path);
			if !listed && !excused {
				unlisted.push(path);
			}
		}
	}
	assert!(seen > 30, "the scan found only {seen} limit constants");
	assert!(
		unlisted.is_empty(),
		"limits with no row in src/cli/limits_protocol.rs (add one, or name it in NOT_A_ROW with the reason): {unlisted:?}"
	);
}

#[test]
fn every_excused_constant_still_exists_and_is_not_also_a_row() {
	for (path, reason) in NOT_A_ROW {
		assert!(!reason.is_empty(), "{path}: say why it is not a row");
		let found = SCANNED.iter().any(|(module, source)| {
			limit_constants(source)
				.iter()
				.any(|name| format!("{module}::{name}") == *path)
		});
		assert!(
			found,
			"`{path}` is excused but no scanned file defines it any more"
		);
		assert!(
			!CATALOG_SOURCES.iter().any(|text| names(text, path)),
			"`{path}` is excused but the catalog names it: drop the excuse"
		);
	}
}

/// The numbers the RFCs give for the MUST rows; the server may not drift
/// from them in either direction.
#[test]
fn the_must_rows_hold_the_number_the_rfc_gives() {
	let rfc: &[(&str, &str)] = &[
		("smtp-line-length", "998"),
		("smtp-command-line", "512"),
		("smtp-command-minimum-timeout", "300"),
		("smtp-never-bounce-a-bounce", "true"),
		("smtp-address-length", "254"),
		("smtp-local-part-length", "64"),
		("smtp-domain-length", "253"),
		("smtp-domain-label-length", "63"),
		("spf-max-dns-lookups", "10"),
		("spf-max-void-lookups", "2"),
		("tls-minimum-version", "1.2"),
	];
	let musts: BTreeSet<&str> = catalog::FIXED
		.iter()
		.filter(|entry| entry.class == Class::Must)
		.map(|entry| entry.name)
		.collect();
	let pinned: BTreeSet<&str> = rfc.iter().map(|(name, _)| *name).collect();
	assert_eq!(musts, pinned, "every MUST row needs its RFC number pinned");
	for (name, number) in rfc {
		let entry = catalog::FIXED.iter().find(|e| e.name == *name).unwrap();
		assert_eq!(&entry.value.render(), number, "{name}");
	}
}

/// The JMAP limits are the least RFC 8620 §2 recommends a server to
/// advertise; a client may rely on them.
#[test]
fn the_jmap_rows_are_not_below_what_rfc_8620_recommends() {
	let least: &[(&str, u64)] = &[
		("jmap-max-size-request", 10_000_000),
		("jmap-max-calls-in-request", 16),
		("jmap-max-concurrent-requests", 4),
		("jmap-max-concurrent-upload", 4),
		("jmap-max-objects-in-get", 500),
		("jmap-max-objects-in-set", 500),
	];
	let jmap: BTreeSet<&str> = catalog::FIXED
		.iter()
		.filter(|entry| entry.name.starts_with("jmap-"))
		.map(|entry| entry.name)
		.collect();
	assert_eq!(jmap, least.iter().map(|(name, _)| *name).collect());
	for (name, floor) in least {
		let entry = catalog::FIXED.iter().find(|e| e.name == *name).unwrap();
		let FixedValue::Number(value) = entry.value else {
			panic!("{name} is not a number")
		};
		assert!(value >= *floor, "{name}: {value} is below {floor}");
		assert_eq!(entry.class, Class::Should, "{name}");
	}
}

#[test]
fn fixed_rows_are_unique_and_not_settable() {
	let mut names = BTreeSet::new();
	for fixed in catalog::FIXED {
		assert!(names.insert(fixed.name), "duplicate row `{}`", fixed.name);
		assert!(
			Key::from_str(fixed.name, false).is_err(),
			"`{}` is a fixed row and also a settable key",
			fixed.name,
		);
	}
}

#[test]
fn the_kind_of_every_adjustable_row_matches_how_set_treats_it() {
	for entry in catalog::ADJUSTABLE {
		let key = entry.key;
		let floor = |bound: Option<(u64, &str)>| bound.map(|(value, _)| value);
		match entry.kind {
			Kind::Must => {
				assert_eq!(
					entry.bound,
					floor(key.must_floor()).map(catalog::Bound::AtLeast),
					"{}: a MUST row refuses below its bound",
					key.name(),
				);
				assert!(key.should_floor().is_none(), "{}", key.name());
			}
			Kind::Recommended => {
				assert_eq!(
					entry.bound,
					floor(key.should_floor()).map(catalog::Bound::AtLeast),
					"{}: a SHOULD row warns below its bound",
					key.name(),
				);
				assert!(key.must_floor().is_none(), "{}", key.name());
			}
			Kind::Adjustable => {
				assert!(entry.bound.is_none(), "{}", key.name());
				assert!(key.must_floor().is_none(), "{}", key.name());
				assert!(key.should_floor().is_none(), "{}", key.name());
			}
			Kind::Fixed => panic!("{}: a fixed row is not settable", key.name()),
		}
	}
}

#[test]
fn show_json_gives_every_fixed_row_its_class() {
	let (_dir, file) = super::tests_config::config_file();
	let config = Config::load(file.path()).unwrap();
	let json = show_json(&config);
	for fixed in catalog::FIXED {
		assert_eq!(
			json[fixed.name]["class"],
			fixed.class.label(),
			"{}",
			fixed.name
		);
		assert_eq!(json[fixed.name]["kind"], "fixed", "{}", fixed.name);
	}
}
