//! The protocol limits in the catalog against the code that enforces them.
//! A limit the code defines with no row in the catalog fails here, so a new
//! one cannot be added unlisted; a MUST stays at the number the RFC gives;
//! and the class of every row agrees with how `set` treats it.

use std::collections::BTreeSet;

use clap::ValueEnum;

use super::*;
use catalog::{Class, FixedValue, Kind};

/// What the RFC says of a row: the exact value, or the least the server may
/// hold.
enum Pin {
	Exactly(&'static str),
	AtLeast(u64),
}

/// The class and the number the RFCs give for every row a standard ties. A
/// row of class `must` or `should` with no entry here fails, so the class of
/// each one was read from the RFC and written down, not left to the code.
const RFC: &[(&str, Class, Pin)] = &[
	("smtp-line-length", Class::Must, Pin::Exactly("998")),
	("smtp-command-line", Class::Must, Pin::AtLeast(512)),
	(
		"smtp-command-minimum-timeout",
		Class::Should,
		Pin::AtLeast(300),
	),
	(
		"smtp-never-bounce-a-bounce",
		Class::Must,
		Pin::Exactly("true"),
	),
	("smtp-address-length", Class::Must, Pin::Exactly("254")),
	("smtp-local-part-length", Class::Must, Pin::Exactly("64")),
	("smtp-domain-length", Class::Must, Pin::Exactly("253")),
	("smtp-domain-label-length", Class::Must, Pin::Exactly("63")),
	("smtp-received-hop-limit", Class::Should, Pin::AtLeast(100)),
	("pop3-command-line", Class::Must, Pin::AtLeast(255)),
	("pop3-idle-timeout", Class::Must, Pin::AtLeast(600)),
	("imap-idle-timeout", Class::Must, Pin::AtLeast(1800)),
	(
		"managesieve-script-name-length",
		Class::Must,
		Pin::AtLeast(128),
	),
	(
		"managesieve-script-name-bytes",
		Class::Must,
		Pin::AtLeast(512),
	),
	(
		"jmap-max-size-request",
		Class::Should,
		Pin::AtLeast(10_000_000),
	),
	("jmap-max-calls-in-request", Class::Should, Pin::AtLeast(16)),
	(
		"jmap-max-concurrent-requests",
		Class::Should,
		Pin::AtLeast(4),
	),
	("jmap-max-concurrent-upload", Class::Should, Pin::AtLeast(4)),
	("jmap-max-objects-in-get", Class::Should, Pin::AtLeast(500)),
	("jmap-max-objects-in-set", Class::Should, Pin::AtLeast(500)),
	("spf-max-dns-lookups", Class::Must, Pin::Exactly("10")),
	("spf-max-void-lookups", Class::Should, Pin::Exactly("2")),
	("tls-minimum-version", Class::Must, Pin::Exactly("1.2")),
];

#[test]
fn the_rows_a_standard_ties_hold_the_class_and_number_the_rfc_gives() {
	let tied: BTreeSet<&str> = catalog::FIXED
		.iter()
		.filter(|entry| entry.class != Class::Own)
		.map(|entry| entry.name)
		.collect();
	let pinned: BTreeSet<&str> = RFC.iter().map(|(name, _, _)| *name).collect();
	assert_eq!(tied, pinned, "every MUST or SHOULD row needs its RFC pin");
	for (name, class, pin) in RFC {
		let entry = catalog::FIXED.iter().find(|e| e.name == *name).unwrap();
		assert_eq!(entry.class, *class, "{name}: class");
		match pin {
			Pin::Exactly(text) => assert_eq!(&entry.value.render(), text, "{name}"),
			Pin::AtLeast(floor) => {
				let FixedValue::Number(value) = entry.value else {
					panic!("{name} is not a number")
				};
				assert!(value >= *floor, "{name}: {value} is below {floor}");
			}
		}
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
fn show_json_gives_every_row_its_class() {
	let (_dir, file) = super::config::config_file();
	let config = Config::load(file.path()).unwrap();
	let json = show_json(&config);
	for entry in catalog::ADJUSTABLE {
		assert_eq!(
			json[entry.key.name()]["class"],
			entry.kind.class().label(),
			"{}",
			entry.key.name()
		);
	}
	for fixed in catalog::FIXED {
		assert_eq!(
			json[fixed.name]["class"],
			fixed.class.label(),
			"{}",
			fixed.name
		);
		assert_eq!(json[fixed.name]["kind"], "fixed", "{}", fixed.name);
	}
	assert_eq!(json["max-recipients"]["class"], "must");
	assert_eq!(json["max-message-size"]["class"], "must");
	assert_eq!(json["queue-give-up"]["class"], "should");
}

#[allow(unused_imports)]
use super::super::catalog;
