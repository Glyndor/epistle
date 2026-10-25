//! The protocol limits in the catalog against the code that enforces them.
//! A limit the code defines with no row in the catalog fails here, so a new
//! one cannot be added unlisted; a MUST stays at the number the RFC gives;
//! and the class of every row agrees with how `set` treats it.

use std::collections::BTreeSet;
use std::path::Path;

use clap::ValueEnum;

use super::*;
use catalog::{Class, FixedValue, Kind};

/// The directories of the protocol modules, under `src/`. Every file in
/// them is read, so a new file is scanned without being listed here.
const SCANNED_DIRS: &[&str] = &[
	"smtp",
	"pop3",
	"imap",
	"managesieve",
	"sieve",
	"api/jmap",
	"spf",
];

/// Single files outside those directories that hold limits a client meets:
/// the address and header rules, and the mailbox name rules.
const SCANNED_FILES: &[&str] = &[
	"util/validation/mod.rs",
	"util/mailbox_path.rs",
	"util/header.rs",
];

/// Constants that are not a row of their own, each with the reason. The
/// first group backs an adjustable key (its default or its ceiling), which
/// the key's own row already shows.
const NOT_A_ROW: &[(&str, &str)] = &[
	(
		"smtp::session::MAX_MESSAGE_SIZE",
		"the default of the adjustable max-message-size",
	),
	(
		"smtp::session::MIN_MESSAGE_SIZE",
		"the MUST floor of the adjustable max-message-size",
	),
	(
		"smtp::session::MIN_MAX_RECIPIENTS",
		"the MUST floor of the adjustable max-recipients",
	),
	(
		"smtp::session::MAX_MAX_RECIPIENTS",
		"the ceiling of the adjustable max-recipients",
	),
	(
		"smtp::server::MAX_CONNECTIONS",
		"the protocol default of max-connections-per-listener",
	),
	(
		"smtp::server::MAX_CONNECTIONS_PER_IP",
		"the default of the adjustable max-connections-per-ip",
	),
	(
		"pop3::server::MAX_CONNECTIONS",
		"the protocol default of max-connections-per-listener",
	),
	(
		"imap::server::MAX_CONNECTIONS",
		"the protocol default of max-connections-per-listener",
	),
	(
		"managesieve::server::MAX_CONNECTIONS",
		"the protocol default of max-connections-per-listener",
	),
	(
		"spf::evaluator::MAX_DEPTH",
		"bounded by spf-max-dns-lookups, every include costs one lookup",
	),
	(
		"smtp::memory_fit::LIMIT_DIVISOR",
		"internal: how the derived memory budget is worked out",
	),
	(
		"smtp::memory_fit::MAX_DERIVED_BUDGET",
		"internal: the ceiling of the memory budget derived from the container limit",
	),
	(
		"smtp::memory_fit::FALLBACK_LIMIT",
		"internal: the memory assumed when no container limit is found",
	),
	(
		"smtp::memory_fit::MAX_FILE_BYTES",
		"internal: the most read from a cgroup file",
	),
	(
		"smtp::memory_fit::MAX_CGROUP_DEPTH",
		"internal: how deep the cgroup tree is followed",
	),
	(
		"smtp::server::DEFAULT_MAX_CONNECTIONS_PER_IP",
		"the default of the adjustable max-connections-per-ip",
	),
	(
		"smtp::server::data_rate::DEFAULT_MIN_DATA_RATE",
		"the default of the adjustable min-data-rate",
	),
	(
		"smtp::server::session_time::DEFAULT_MAX_SESSION_TIME_SECS",
		"the default of the adjustable max-session-time",
	),
	(
		"smtp::session::DEFAULT_MAX_RECIPIENTS",
		"the default of the adjustable max-recipients",
	),
	(
		"smtp::session::SHOULD_COMMAND_TIMEOUT_SECS",
		"the SHOULD floor of the adjustable preauth-timeout",
	),
	(
		"smtp::session::junk::DEFAULT_JUNK_COMMAND_LIMIT",
		"the default of the adjustable junk-command-limit",
	),
	(
		"smtp::ratelimit::MAX_ENTRIES",
		"internal: the size of the rate limiter's table",
	),
	(
		"imap::fetch::MAX_DEPTH",
		"internal: how deep a message structure is walked",
	),
	(
		"imap::changelog::MAX_JOURNAL_BYTES",
		"internal: the largest change journal read",
	),
	(
		"imap::session::base_subject::MAX_SUBJECT",
		"internal: the subject length SORT and THREAD compare",
	),
	(
		"imap::session::thread_references::msgid::MAX_REFERENCES",
		"internal: the references THREAD follows",
	),
	(
		"imap::session::thread_references::msgid::MAX_MSGID_LEN",
		"internal: the message id length THREAD compares",
	),
	(
		"imap::command::parse::DEFAULT_APPEND_LIMIT",
		"internal: the APPENDLIMIT it advertises is the message size cap (max-message-size)",
	),
	(
		"managesieve::server::DEFAULT_MAX_LITERAL",
		"the same number as managesieve-script-size",
	),
	(
		"managesieve::store_index::MAX_INDEX_BYTES",
		"internal: the largest script index file read",
	),
	(
		"managesieve::store_names::MAX_SIDECAR_BYTES",
		"internal: the largest name file read",
	),
	(
		"sieve::key_set::MIN_KEYS",
		"internal: when a test with many keys is indexed",
	),
	(
		"sieve::key_set::MAX_KEY_BYTES",
		"internal: the memory one indexed test may take",
	),
	(
		"sieve::vacation::MAX_REFERENCES",
		"internal: the references a vacation reply carries",
	),
	(
		"api::jmap::mime::MAX_MIME_DEPTH",
		"internal: how deep a stored message is parsed",
	),
	(
		"api::jmap::uploads::MAX_BLOBS",
		"internal: the blob ids read ahead for one request",
	),
	(
		"api::jmap::uploads::MAX_WASTED_READS",
		"internal: reads without progress before an upload is dropped",
	),
	(
		"api::jmap::uploads::MAX_DEPTH",
		"internal: how deep a blob reference is followed",
	),
	(
		"api::jmap::sieve_script_query::MAX_COMPARATORS",
		"internal: the comparators a script query inspects",
	),
	(
		"api::jmap::email_build_parts::MAX_DEPTH",
		"internal: how deep a built message nests",
	),
	(
		"util::header::MAX_HEADER_VALUE_LEN",
		"internal: caps a sanitised header value so one input cannot inflate a line",
	),
];

/// The module path of a source file under `src/`, as `a::b`; a `mod.rs`
/// is the module of its directory.
fn module_of(relative: &Path) -> String {
	let mut parts: Vec<String> = relative
		.iter()
		.map(|part| part.to_string_lossy().into_owned())
		.collect();
	if let Some(last) = parts.last_mut() {
		*last = last.trim_end_matches(".rs").to_string();
	}
	if parts.last().is_some_and(|last| last == "mod") {
		parts.pop();
	}
	parts.join("::")
}

/// Every non-test source file under `dir`, with its module path.
fn sources_under(dir: &Path, src: &Path, found: &mut Vec<(String, String)>) {
	let Ok(entries) = std::fs::read_dir(dir) else {
		return;
	};
	for entry in entries.flatten() {
		let path = entry.path();
		let name = entry.file_name().to_string_lossy().into_owned();
		if path.is_dir() {
			if !name.contains("test") {
				sources_under(&path, src, found);
			}
		} else if name.ends_with(".rs") && !name.contains("test") {
			let text = std::fs::read_to_string(&path).expect("read source");
			// What follows `#[cfg(test)]` is test code.
			let code = text.split("#[cfg(test)]").next().unwrap_or("").to_string();
			let relative = path.strip_prefix(src).expect("under src");
			found.push((module_of(relative), code));
		}
	}
}

fn protocol_sources() -> Vec<(String, String)> {
	let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
	let mut found = Vec::new();
	for dir in SCANNED_DIRS {
		sources_under(&src.join(dir), &src, &mut found);
	}
	for file in SCANNED_FILES {
		let text = std::fs::read_to_string(src.join(file)).expect("read source");
		found.push((module_of(Path::new(file)), text));
	}
	found
}

/// The lines of `text` that are not comments.
fn code_lines(text: &str) -> String {
	text.lines()
		.filter(|line| !line.trim_start().starts_with("//"))
		.collect::<Vec<_>>()
		.join("\n")
}

/// The `const NAME: <integer or Duration>` declarations of a file whose
/// name reads as a limit.
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
			let ty = ty.split(" =").next().unwrap_or(ty);
			let typed =
				["usize", "u8", "u16", "u32", "u64"].contains(&ty) || ty.ends_with("Duration");
			let limit = ["MAX_", "MIN_", "LIMIT", "TIMEOUT"]
				.iter()
				.any(|word| name.contains(word));
			(typed && limit).then_some(name)
		})
		.collect()
}

/// The paths the rows read their values from, without `crate::`.
fn row_sources() -> BTreeSet<String> {
	catalog::FIXED
		.iter()
		.map(|row| row.source.trim_start_matches("crate::").to_string())
		.collect()
}

#[test]
fn every_limit_constant_in_the_protocol_modules_has_a_row() {
	let sources = row_sources();
	let mut unlisted = Vec::new();
	let mut seen = 0;
	for (module, code) in protocol_sources() {
		// A row may name a constant through the module that re-exports it.
		let parent = module
			.rsplit_once("::")
			.map(|(parent, _)| parent.to_string());
		for name in limit_constants(&code) {
			seen += 1;
			let listed = std::iter::once(&module)
				.chain(parent.as_ref())
				.any(|label| sources.contains(&format!("{label}::{name}")));
			let path = format!("{module}::{name}");
			let excused = NOT_A_ROW.iter().any(|(excused, _)| *excused == path);
			if !listed && !excused {
				unlisted.push(path);
			}
		}
	}
	assert!(seen > 50, "the scan found only {seen} limit constants");
	assert!(
		unlisted.is_empty(),
		"limits with no row in src/cli/limits_protocol.rs (add one, or name it in NOT_A_ROW with the reason): {unlisted:#?}"
	);
}

#[test]
fn every_row_names_a_constant_the_scan_finds() {
	let found: BTreeSet<String> = protocol_sources()
		.into_iter()
		.flat_map(|(module, code)| {
			let parent = module
				.rsplit_once("::")
				.map(|(parent, _)| parent.to_string());
			limit_constants(&code)
				.into_iter()
				.flat_map(|name| {
					std::iter::once(format!("{module}::{name}"))
						.chain(parent.iter().map(|parent| format!("{parent}::{name}")))
						.collect::<Vec<_>>()
				})
				.collect::<Vec<_>>()
		})
		.collect();
	for row in catalog::FIXED {
		if row.source.is_empty() || row.source.starts_with("tls::") {
			continue;
		}
		let source = row.source.trim_start_matches("crate::");
		assert!(
			found.contains(source),
			"row `{}` reads `{source}`, which no protocol module defines as a limit constant",
			row.name,
		);
	}
}

#[test]
fn every_excused_constant_still_exists_and_is_not_also_a_row() {
	let sources = protocol_sources();
	let rows = row_sources();
	let keys = code_lines(&format!(
		"{}{}{}",
		include_str!("limits.rs"),
		include_str!("limits_keys.rs"),
		include_str!("limits_catalog.rs")
	));
	for (path, reason) in NOT_A_ROW {
		assert!(!reason.is_empty(), "{path}: say why it is not a row");
		let found = sources.iter().any(|(module, code)| {
			limit_constants(code)
				.iter()
				.any(|name| format!("{module}::{name}") == *path)
		});
		assert!(
			found,
			"`{path}` is excused but no protocol module defines it any more"
		);
		assert!(!rows.contains(*path), "`{path}` is a row: drop the excuse");
		if reason.contains("adjustable") {
			let name = path.rsplit("::").next().unwrap();
			assert!(
				keys.contains(name),
				"`{path}` is said to back an adjustable key, but the key code never names it"
			);
		}
	}
}

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
	let (_dir, file) = super::tests_config::config_file();
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
