//! The resources check never suggests less memory than a service needs:
//! `mail` must hold five messages of `max_message_size` and its own base.

use super::{Level, evaluate};
use crate::cli::status::test_support::ctx;

/// The `name` finding for a config with `extra`, a compose file with
/// `limits` and a host of `kib` KiB.
fn finding(extra: &str, limits: &[(&str, &str)], kib: u64, name: &str) -> (Level, String) {
	let dir = tempfile::tempdir().expect("tempdir");
	let ctx = ctx(dir.path(), extra);
	let meminfo = dir.path().join("meminfo-fake");
	std::fs::write(&meminfo, format!("MemTotal: {kib} kB\n")).expect("meminfo");
	let services: serde_json::Map<String, serde_json::Value> = limits
		.iter()
		.map(|(service, memory)| {
			(
				(*service).to_string(),
				serde_json::json!({ "mem_limit": memory }),
			)
		})
		.collect();
	let compose = dir.path().join("compose.yaml");
	std::fs::write(
		&compose,
		serde_json::json!({ "services": services }).to_string(),
	)
	.expect("compose");
	let report = evaluate(ctx.config.as_ref().expect("config"), &compose, &meminfo);
	let item = report
		.items
		.iter()
		.find(|item| item.name == name)
		.unwrap_or_else(|| panic!("no {name} finding in {:?}", report.items));
	(item.status, item.detail.clone())
}

const FOUR_GIB: u64 = 4 * 1024 * 1024;

#[test]
fn lowering_mail_stops_where_its_largest_messages_need() {
	// 500 MiB messages: 5 x 500 + 256 = 2756 MiB, 2816m in 256 MiB steps.
	assert_eq!(
		finding(
			"max_message_size = 524288000",
			&[("mail", "3g"), ("db", "1g")],
			FOUR_GIB,
			"containers"
		),
		(
			Level::Warn,
			"the containers may use 4.0 GiB of the host's 4.0 GiB (100%), more than 85%; the \
			 largest are mail (3g) and db (1g); lower them with `epistle stack resources \
			 set mail --memory 2816m` and `epistle stack resources set db --memory 512m`"
				.to_string()
		)
	);
}

#[test]
fn when_mail_cannot_go_lower_the_next_largest_is_named() {
	// 600 MiB messages need 3256 MiB, more than mail's 3g: db goes down to
	// the least any tier gives it.
	assert_eq!(
		finding(
			"max_message_size = 629145600",
			&[("mail", "3g"), ("db", "1g")],
			FOUR_GIB,
			"containers"
		),
		(
			Level::Warn,
			"the containers may use 4.0 GiB of the host's 4.0 GiB (100%), more than 85%; the \
			 largest are mail (3g) and db (1g); lower one with `epistle stack resources set db \
			 --memory 384m`"
				.to_string()
		)
	);
}

#[test]
fn when_nothing_can_go_lower_the_host_needs_more_memory() {
	assert_eq!(
		finding(
			"max_message_size = 629145600",
			&[("mail", "3g"), ("db", "384m")],
			3 * 1024 * 1024,
			"containers"
		),
		(
			Level::Warn,
			"the containers may use 3.4 GiB of the host's 3.0 GiB (112%), more than 85%; the \
			 largest are mail (3g) and db (384m); none can be lowered under what it needs, so \
			 the host needs more memory"
				.to_string()
		)
	);
}

#[test]
fn the_suggested_mail_limit_holds_the_largest_messages() {
	// A host under 4 GiB gets mail 1g, too little for 300 MiB messages.
	assert_eq!(
		finding(
			"max_message_size = 314572800",
			&[("mail", "1g")],
			3_900_000,
			"suggested"
		),
		(
			Level::Warn,
			"a new install on this host (3.7 GiB) would get mail 1792m (now 1g); adopt it \
			 with `epistle stack resources set mail --memory 1792m`, then `epistle stack \
			 update`"
				.to_string()
		)
	);
}
