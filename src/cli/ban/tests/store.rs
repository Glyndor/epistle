//! `epistle ban` against a ban store in memory: what each action prints, as
//! text and as JSON, and what a refusal says. The routes of the API are held
//! to the same store in `api_parity`.

use std::process::ExitCode;

use super::super::*;
use crate::antispam::bans::operator::tests::fake::FakeAdmin;

const NOW: u64 = 1_700_000_000;

async fn run_on(store: &FakeAdmin, action: BanCli, json: bool) -> (ExitCode, String, String) {
	let (mut out, mut err) = (Vec::new(), Vec::new());
	let code = match execute(store, action, json, NOW, &mut out, &mut err).await {
		Ok(code) => code,
		Err(error) => {
			crate::cli::style::error_to(&mut err, error);
			ExitCode::FAILURE
		}
	};
	(
		code,
		String::from_utf8(out).expect("utf8"),
		String::from_utf8(err).expect("utf8"),
	)
}

fn target(spec: &str) -> BanTarget {
	BanTarget::parse(spec).expect("target")
}

#[tokio::test]
async fn a_ban_is_said_in_a_line_and_in_one_json_object() {
	let store = FakeAdmin::default();
	let (code, out, err) = run_on(
		&store,
		BanCli::Add {
			target: target("203.0.113.9"),
			duration: Some(3600),
		},
		false,
	)
	.await;
	assert_eq!(code, ExitCode::SUCCESS, "{err}");
	assert_eq!(out, "banned 203.0.113.9 until 2023-11-14T23:13:20Z\n");
	let (_, out, _) = run_on(
		&store,
		BanCli::Add {
			target: target("203.0.113.0/24"),
			duration: None,
		},
		true,
	)
	.await;
	let object: serde_json::Value = serde_json::from_str(&out).expect("one JSON object");
	assert_eq!(object["result"], "saved");
	assert_eq!(object["action"], "add");
	assert_eq!(object["target"], "203.0.113.0/24");
	assert_eq!(object["until"], NOW + 86_400);
}

#[tokio::test]
async fn the_listing_prints_what_the_store_holds_as_text_and_as_json() {
	let store = FakeAdmin::with(
		&[
			("ip:203.0.113.9", "manual ban", NOW + 60),
			("account:alice@example.org", "too many failures", NOW + 120),
			("ip:198.51.100.1", "ended", NOW - 1),
		],
		&[],
	);
	let (_, out, _) = run_on(&store, BanCli::List { json: false }, false).await;
	assert!(out.ends_with("2 banned\n"), "{out}");
	assert!(
		out.contains("account:alice@example.org\tuntil=2023-11-14T22:15:20Z\ttoo many failures"),
		"{out}"
	);
	let (_, out, _) = run_on(&store, BanCli::List { json: true }, false).await;
	let rows: serde_json::Value = serde_json::from_str(&out).expect("JSON");
	assert_eq!(rows.as_array().expect("rows").len(), 2);
	assert_eq!(rows[1]["subject"], "ip:203.0.113.9");
	assert_eq!(rows[1]["until"], NOW + 60);
}

#[tokio::test]
async fn a_refusal_is_said_on_stderr_with_a_failure_and_nothing_is_written() {
	let store = FakeAdmin::default();
	store.allow_entries(["203.0.113.0/24".to_string()]);
	let (code, out, err) = run_on(
		&store,
		BanCli::Add {
			target: target("203.0.113.9"),
			duration: None,
		},
		false,
	)
	.await;
	assert_eq!(code, ExitCode::FAILURE);
	assert!(out.is_empty(), "{out}");
	assert!(
		err.contains(
			"203.0.113.9 is on the allow list, which overrides every ban; remove it there first"
		),
		"{err}"
	);
	let (code, _, err) = run_on(
		&store,
		BanCli::Remove {
			target: Some(UnbanTarget::parse("198.51.100.7").expect("target")),
			account: None,
			ip: None,
		},
		false,
	)
	.await;
	assert_eq!(code, ExitCode::FAILURE);
	assert!(
		err.contains("198.51.100.7 has no ban or failure record"),
		"{err}"
	);
	assert!(store.writes().is_empty(), "{:?}", store.writes());
}

#[tokio::test]
async fn lifting_a_ban_says_how_much_it_cleared() {
	let store = FakeAdmin::with(
		&[("pair:alice@example.org|203.0.113.9", "x", NOW + 60)],
		&[("pair:alice@example.org|203.0.113.9", 4)],
	);
	let (code, out, _) = run_on(
		&store,
		BanCli::Remove {
			target: None,
			account: Some("Alice@Example.org".to_string()),
			ip: Some("203.0.113.9".parse().expect("ip")),
		},
		false,
	)
	.await;
	assert_eq!(code, ExitCode::SUCCESS);
	assert_eq!(
		out,
		"unbanned pair:alice@example.org|203.0.113.9 (1 bans, 1 failures cleared)\n"
	);
}

#[tokio::test]
async fn the_allow_list_is_added_to_listed_and_removed_from() {
	let store = FakeAdmin::default();
	let cidr = parse_allow("10.0.0.0/8").expect("block");
	let (_, out, _) = run_on(
		&store,
		BanCli::Allow {
			action: AllowCli::Add { cidr },
		},
		false,
	)
	.await;
	assert_eq!(out, "allowed 10.0.0.0/8\n");
	let (_, out, _) = run_on(
		&store,
		BanCli::Allow {
			action: AllowCli::Add { cidr },
		},
		true,
	)
	.await;
	let object: serde_json::Value = serde_json::from_str(&out).expect("JSON");
	assert_eq!(object["result"], "unchanged");
	let (_, out, _) = run_on(
		&store,
		BanCli::Allow {
			action: AllowCli::List { json: false },
		},
		false,
	)
	.await;
	assert_eq!(out, "10.0.0.0/8\n1 allowed\n");
	let (_, out, _) = run_on(
		&store,
		BanCli::Allow {
			action: AllowCli::Remove { cidr },
		},
		false,
	)
	.await;
	assert_eq!(out, "removed 10.0.0.0/8 from the allow list\n");
	let (code, _, err) = run_on(
		&store,
		BanCli::Allow {
			action: AllowCli::Remove { cidr },
		},
		false,
	)
	.await;
	assert_eq!(code, ExitCode::FAILURE);
	assert!(err.contains("10.0.0.0/8 is not on the allow list"), "{err}");
}

#[tokio::test]
async fn a_store_that_fails_is_a_failure_that_names_the_database() {
	let store = FakeAdmin::default();
	store.break_down();
	let (code, out, err) = run_on(&store, BanCli::List { json: false }, false).await;
	assert_eq!(code, ExitCode::FAILURE);
	assert!(out.is_empty());
	assert!(err.contains("database: connection refused"), "{err}");
}
