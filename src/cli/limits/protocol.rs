//! The limits the server hard-codes and a client can run into: line and
//! address lengths, idle timers, the JMAP request limits the Session
//! advertises, the script limits of ManageSieve, the abuse guards of each
//! protocol.
//!
//! A number is read from the constant the code enforces, never copied, and
//! the row remembers the path of that constant. A test walks the source of
//! the protocol modules and fails on a limit constant that is neither a row
//! here nor excused with a reason, so a new one cannot slip in unlisted.
//! `class` says how strongly a standard ties the limit: a MUST (below it the
//! server is broken), a SHOULD (the usual minimum, which a client may rely
//! on), or a bound of epistle's own.

use super::catalog::{Class, FixedEntry, FixedValue};

/// A row whose value is the integer constant at `$source`.
macro_rules! number {
	($name:literal, $source:path, $unit:literal, $class:ident, $reference:literal) => {
		FixedEntry {
			name: $name,
			value: FixedValue::Number($source as u64),
			unit: $unit,
			class: Class::$class,
			reference: $reference,
			source: stringify!($source),
		}
	};
}

/// A row of epistle's own with no standard behind it, in one line.
macro_rules! own {
	($name:literal, $source:path, $unit:literal) => {
		number!($name, $source, $unit, Own, "no standard mandate")
	};
}

/// A row whose value is the `Duration` constant at `$source`, in seconds.
macro_rules! seconds {
	($name:literal, $source:path, $unit:literal, $class:ident, $reference:literal) => {
		FixedEntry {
			name: $name,
			value: FixedValue::Number($source.as_secs()),
			unit: $unit,
			class: Class::$class,
			reference: $reference,
			source: stringify!($source),
		}
	};
}

/// Every hard-coded limit, in the order `show` prints them after the
/// adjustable keys. `limits set` has no path to change any of them.
pub(super) const FIXED: &[FixedEntry] = &[
	number!(
		"smtp-line-length",
		crate::smtp::line::MAX_LINE_LENGTH,
		"octets",
		Must,
		"RFC 5321 §4.5.3.1.6 (998 octets excl. CRLF; 1000 incl. CRLF)"
	),
	number!(
		"smtp-command-line",
		crate::smtp::command::MAX_COMMAND_LINE,
		"octets",
		Must,
		"RFC 5321 §4.5.3.1.4 (at least 512 octets incl. CRLF; 512 are accepted excl. CRLF)"
	),
	seconds!(
		"smtp-command-minimum-timeout",
		crate::smtp::server::COMMAND_TIMEOUT,
		"seconds",
		Should,
		"RFC 5321 §4.5.3.2.7 (a timeout of at least 5 minutes)"
	),
	FixedEntry {
		name: "smtp-never-bounce-a-bounce",
		value: FixedValue::Text("true"),
		unit: "boolean",
		class: Class::Must,
		reference: "RFC 5321 §3.6.3 (no notification about a notification)",
		source: "",
	},
	number!(
		"smtp-address-length",
		crate::util::validation::MAX_ADDRESS,
		"octets",
		Must,
		"RFC 5321 §4.5.3.1.3 (path of 256 octets with the angle brackets)"
	),
	number!(
		"smtp-local-part-length",
		crate::util::validation::MAX_LOCAL_PART,
		"octets",
		Must,
		"RFC 5321 §4.5.3.1.1 (local part of 64 octets)"
	),
	number!(
		"smtp-domain-length",
		crate::util::validation::MAX_DOMAIN,
		"octets",
		Must,
		"RFC 5321 §4.5.3.1.2 and RFC 1035 §2.3.4 (255 octets on the wire, 253 as written)"
	),
	number!(
		"smtp-domain-label-length",
		crate::util::validation::MAX_LABEL,
		"octets",
		Must,
		"RFC 1035 §2.3.4 (labels of 63 octets)"
	),
	number!(
		"smtp-received-hop-limit",
		crate::smtp::trace::RECEIVED_HOP_LIMIT,
		"count",
		Should,
		"RFC 5321 §6.3 (a Received count near 100 is a loop)"
	),
	number!(
		"smtp-header-fields",
		crate::smtp::trace::MAX_HEADER_FIELDS,
		"count",
		Own,
		"no standard mandate"
	),
	number!(
		"smtp-error-streak",
		crate::smtp::server::MAX_ERROR_STREAK,
		"count",
		Own,
		"no standard mandate (consecutive error replies before the connection is dropped)"
	),
	number!(
		"pop3-command-line",
		crate::pop3::command::MAX_COMMAND_LINE,
		"octets",
		Must,
		"RFC 2449 §4 (commands of at least 255 octets)"
	),
	seconds!(
		"pop3-idle-timeout",
		crate::pop3::server::TIMEOUT,
		"seconds",
		Must,
		"RFC 1939 §3 (an inactivity timer of at least 10 minutes; before sign-in preauth-timeout bounds the session)"
	),
	number!(
		"pop3-error-streak",
		crate::pop3::server::MAX_ERROR_STREAK,
		"count",
		Own,
		"no standard mandate (consecutive -ERR replies the client earns by its own errors before the connection is dropped; a [SYS/...] reply is not counted, and the acceptance of a USER does not clear the streak because the password that follows can still be refused)"
	),
	number!(
		"pop3-unavailable-streak",
		crate::pop3::server::MAX_UNAVAILABLE_STREAK,
		"count",
		Own,
		"no standard mandate (consecutive replies for a message that cannot be read before the connection is dropped)"
	),
	number!(
		"pop3-messages-per-session",
		crate::pop3::bounds::MAX_SESSION_MESSAGES,
		"count",
		Own,
		"no standard mandate (messages a session lists; the newest when the inbox holds more)"
	),
	number!(
		"pop3-message-octets",
		crate::pop3::bounds::MAX_MESSAGE_OCTETS,
		"octets",
		Own,
		"no standard mandate (largest message a session lists and retrieves)"
	),
	number!(
		"imap-command-line",
		crate::imap::command::MAX_COMMAND_LINE,
		"octets",
		Own,
		"no standard mandate"
	),
	seconds!(
		"imap-idle-timeout",
		crate::imap::server::DEFAULT_READ_TIMEOUT,
		"seconds",
		Must,
		"RFC 3501 §5.4 (an autologout timer of at least 30 minutes; before sign-in preauth-timeout bounds the session)"
	),
	number!(
		"imap-error-streak",
		crate::imap::server::MAX_ERROR_STREAK,
		"count",
		Own,
		"no standard mandate (consecutive BAD replies before the connection is dropped)"
	),
	number!(
		"imap-keywords-per-message",
		crate::imap::keyword::MAX_KEYWORDS_PER_MESSAGE,
		"count",
		Own,
		"no standard mandate"
	),
	number!(
		"imap-keyword-length",
		crate::imap::keyword::MAX_KEYWORD_BYTES,
		"octets",
		Own,
		"no standard mandate"
	),
	number!(
		"imap-mailbox-depth",
		crate::util::mailbox_path::MAX_DEPTH,
		"count",
		Own,
		"no standard mandate"
	),
	number!(
		"imap-mailbox-name-length",
		crate::util::mailbox_path::MAX_DISK_NAME_LEN,
		"octets",
		Own,
		"no standard mandate (NAME_MAX of the common filesystems)"
	),
	number!(
		"imap-search-depth",
		crate::imap::command::MAX_SEARCH_DEPTH,
		"count",
		Own,
		"no standard mandate"
	),
	number!(
		"managesieve-script-size",
		crate::managesieve::store::MAX_SCRIPT_BYTES,
		"octets",
		Own,
		"no standard mandate"
	),
	number!(
		"managesieve-scripts-per-account",
		crate::managesieve::store::MAX_SCRIPTS,
		"count",
		Own,
		"RFC 9661 (maxNumberScripts capability)"
	),
	number!(
		"managesieve-script-name-length",
		crate::managesieve::store::MAX_NAME_CHARS,
		"characters",
		Must,
		"RFC 5804 §1.6 (names of up to 128 characters)"
	),
	number!(
		"managesieve-script-name-bytes",
		crate::managesieve::store::MAX_NAME_BYTES,
		"octets",
		Must,
		"RFC 5804 §1.6 (128 characters take up to 512 octets)"
	),
	number!(
		"managesieve-auth-failures",
		crate::managesieve::session::MAX_AUTH_FAILURES,
		"count",
		Own,
		"no standard mandate (failed AUTHENTICATE attempts before the connection is dropped)"
	),
	seconds!(
		"managesieve-idle-timeout",
		crate::managesieve::server::TIMEOUT,
		"seconds",
		Own,
		"no standard mandate"
	),
	number!(
		"sieve-redirects",
		crate::sieve::interp::MAX_REDIRECTS,
		"count",
		Own,
		"RFC 9661 (maxNumberRedirects capability)"
	),
	number!(
		"sieve-fileinto",
		crate::sieve::interp::MAX_FILEINTO,
		"count",
		Own,
		"no standard mandate"
	),
	own!("sieve-flags", crate::sieve::interp::MAX_FLAGS, "count"),
	number!(
		"sieve-flag-length",
		crate::sieve::interp::MAX_FLAG_BYTES,
		"octets",
		Own,
		"no standard mandate (the IMAP keyword limit)"
	),
	number!(
		"sieve-nesting-depth",
		crate::sieve::parser::MAX_NESTING_DEPTH,
		"count",
		Own,
		"no standard mandate"
	),
	number!(
		"sieve-variable-length",
		crate::sieve::MAX_VAR_BYTES,
		"octets",
		Own,
		"RFC 5229 §4.1 (a server may keep as little as 4000 octets)"
	),
	number!(
		"sieve-variables-total-bytes",
		crate::sieve::MAX_VARS_TOTAL_BYTES,
		"octets",
		Own,
		"no standard mandate"
	),
	own!("sieve-variables", crate::sieve::MAX_VARS, "count"),
	own!(
		"caldav-freebusy-window",
		crate::webdav::caldav_busy::MAX_WINDOW_SECS,
		"seconds"
	),
	own!(
		"caldav-freebusy-items",
		crate::webdav::caldav_busy::MAX_ITEMS,
		"count"
	),
	own!(
		"caldav-freebusy-file-size",
		crate::webdav::caldav_busy::MAX_FILE_BYTES,
		"octets"
	),
	own!(
		"caldav-freebusy-periods",
		crate::webdav::caldav_busy::MAX_PERIODS,
		"count"
	),
	own!(
		"webdav-entry-bytes",
		crate::webdav::quota::MIN_ENTRY_BYTES,
		"octets"
	),
	own!(
		"webdav-collection-members",
		crate::webdav::bounds::MAX_MEMBERS,
		"count"
	),
	own!("webdav-depth", crate::webdav::bounds::MAX_DEPTH, "count"),
	number!(
		"sieve-variable-name-length",
		crate::sieve::MAX_VAR_NAME,
		"octets",
		Own,
		"no standard mandate"
	),
	own!("sieve-steps", crate::sieve::MAX_STEPS, "count"),
	own!("sieve-work", crate::sieve::MAX_WORK, "octets"),
	own!("sieve-headers", crate::sieve::MAX_HEADERS, "count"),
	number!(
		"sieve-header-name-length",
		crate::sieve::message::MAX_NAME,
		"octets",
		Own,
		"RFC 5322 §2.1.1 (lines of 998 octets)"
	),
	own!("sieve-body-window", crate::sieve::BODY_WINDOW, "octets"),
	number!(
		"sieve-header-name-values",
		crate::sieve::HEADER_NAME_VALUES,
		"count",
		Own,
		"no standard mandate"
	),
	number!(
		"sieve-header-name-window",
		crate::sieve::HEADER_NAME_WINDOW,
		"octets",
		Own,
		"no standard mandate"
	),
	number!(
		"sieve-header-names-per-lookup",
		crate::sieve::HEADER_NAMES_PER_LOOKUP,
		"count",
		Own,
		"no standard mandate"
	),
	number!(
		"sieve-pattern-length",
		crate::sieve::MAX_PATTERN_CHARS,
		"characters",
		Own,
		"no standard mandate"
	),
	own!("sieve-wildcards", crate::sieve::MAX_WILDCARDS, "count"),
	number!(
		"jmap-max-size-request",
		crate::api::jmap::limits::MAX_SIZE_REQUEST,
		"octets",
		Should,
		"RFC 8620 §2 (maxSizeRequest, at least 10000000 recommended)"
	),
	number!(
		"jmap-max-calls-in-request",
		crate::api::jmap::limits::MAX_CALLS_IN_REQUEST,
		"count",
		Should,
		"RFC 8620 §2 (maxCallsInRequest, at least 16 recommended)"
	),
	number!(
		"jmap-max-concurrent-requests",
		crate::api::jmap::limits::MAX_CONCURRENT_REQUESTS,
		"count",
		Should,
		"RFC 8620 §2 (maxConcurrentRequests, at least 4 recommended)"
	),
	number!(
		"jmap-max-concurrent-upload",
		crate::api::jmap::limits::MAX_CONCURRENT_UPLOAD,
		"count",
		Should,
		"RFC 8620 §2 (maxConcurrentUpload, at least 4 recommended)"
	),
	number!(
		"jmap-max-objects-in-get",
		crate::api::jmap::limits::MAX_OBJECTS_IN_GET,
		"count",
		Should,
		"RFC 8620 §2 (maxObjectsInGet, at least 500 recommended)"
	),
	number!(
		"jmap-max-objects-in-set",
		crate::api::jmap::limits::MAX_OBJECTS_IN_SET,
		"count",
		Should,
		"RFC 8620 §2 (maxObjectsInSet, at least 500 recommended)"
	),
	number!(
		"jmap-event-source-min-ping",
		crate::api::jmap::event_source::MIN_PING,
		"seconds",
		Own,
		"RFC 8620 §7.3 (ping interval)"
	),
	number!(
		"jmap-event-source-max-ping",
		crate::api::jmap::event_source::MAX_PING,
		"seconds",
		Own,
		"RFC 8620 §7.3 (ping interval)"
	),
	number!(
		"jmap-event-streams-per-caller",
		crate::api::jmap::event_source::MAX_STREAMS_PER_CALLER,
		"count",
		Own,
		"no standard mandate"
	),
	number!(
		"jmap-push-subscriptions-per-caller",
		crate::api::jmap::push_subscription::MAX_PER_CALLER,
		"count",
		Own,
		"no standard mandate"
	),
	number!(
		"spf-max-dns-lookups",
		crate::spf::MAX_DNS_MECHANISMS,
		"count",
		Must,
		"RFC 7208 §4.6.4 (max 10 DNS-querying terms)"
	),
	number!(
		"spf-max-void-lookups",
		crate::spf::MAX_VOID_LOOKUPS,
		"count",
		Should,
		"RFC 7208 §4.6.4 (void lookups limited to 2)"
	),
	FixedEntry {
		name: "tls-minimum-version",
		value: FixedValue::TlsMinimum,
		unit: "version",
		class: Class::Must,
		reference: "RFC 8996 (TLS 1.0/1.1 prohibited)",
		source: "tls::PROTOCOL_VERSIONS",
	},
];
