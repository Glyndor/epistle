//! The rest of the hard-coded limits: the WebDAV query and free-busy bounds,
//! the ban-strike guards and the TLS floor. They continue the list in
//! `super::CORE` and are printed after it.

use crate::cli::limits::catalog::{Class, FixedEntry, FixedValue};

/// Rows that follow `super::CORE`, in print order.
pub(in crate::cli::limits) const MORE: &[FixedEntry] = &[
	own!(
		"caldav-query-work",
		crate::webdav::caldav_filter::MAX_QUERY_WORK,
		"count"
	),
	own!(
		"caldav-query-request-work",
		crate::webdav::caldav_filter::MAX_REQUEST_WORK,
		"count"
	),
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
	own!(
		"jmap-websockets-per-caller",
		crate::api::jmap::websocket::bounds::MAX_SOCKETS_PER_CALLER,
		"count"
	),
	seconds!(
		"jmap-websocket-idle-timeout",
		crate::api::jmap::websocket::bounds::IDLE_TIMEOUT,
		"seconds",
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
	own!(
		"ban-strike-line",
		crate::smtp::directory::strike_locks::MAX_WAITING,
		"count"
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
