//! Every leaf command is run with `--json` against a seeded temporary
//! setup, and its stdout must be exactly one JSON document when it
//! succeeds and empty when it is refused. This is what makes "takes
//! `--json`" mean "honours `--json`": a command that declares the flag and
//! prints text, or prints two documents, fails here.
//!
//! The leaves are found by walking `--help`, and each must be in `CASES`,
//! in `SKIPPED` with its reason, or in `EXEMPT`, so a new command cannot be
//! added without choosing.

use std::collections::BTreeSet;

use crate::harness::{PASSWORD, add_account, env, epistle};

/// Leaves that read no configuration file and so take no `--config`.
const NO_CONFIG: &[&str] = &[
	"dkim-keygen",
	"storage-keygen",
	"oauth-keygen",
	"token-hash",
];

/// What a case must do.
#[derive(Clone, Copy, Debug)]
enum Expect {
	/// Exit 0 and one JSON document on stdout.
	Done,
	/// Refused with this exit code and nothing on stdout.
	Refused(i32),
}
use Expect::{Done, Refused};

/// Leaves whose stdout is the product, or that never return. They take no
/// `--json`; `src/cli/cli_json_everywhere_tests.rs` holds the reasons.
const EXEMPT: &[&str] = &[
	"serve",
	"local",
	"mta-sts-serve",
	"stack logs",
	"completions",
	"export",
	"backup",
	"report-abuse",
	"mobileconfig",
	"autoconfig",
	"autodiscover",
];

/// Leaves not run here, each with the test that covers it or the reason it
/// cannot run on a bare temporary setup.
const SKIPPED: &[(&str, &str)] = &[
	("ban list", "needs PostgreSQL; tests/cli_json/ban.rs"),
	("ban add", "needs PostgreSQL; tests/cli_json/ban.rs"),
	("ban remove", "needs PostgreSQL; tests/cli_json/ban.rs"),
	("ban allow list", "needs PostgreSQL; tests/cli_json/ban.rs"),
	("ban allow add", "needs PostgreSQL; tests/cli_json/ban.rs"),
	(
		"ban allow remove",
		"needs PostgreSQL; tests/cli_json/ban.rs",
	),
	("dns provider test", "calls the DNS provider"),
	("webhook test", "posts to the endpoint"),
	("relay test", "connects to the smarthost"),
	("probe", "connects to the server's listeners"),
	("check", "looks up DNS and probes services"),
	("status", "looks up DNS and probes services"),
	("verify-dns", "looks up DNS"),
	("dns-records", "builds records from live DKIM and DNS state"),
	("dns lockdown", "reads the zone through the DNS provider"),
	("dkim show", "checks the published records through DNS"),
	("dkim rotate", "tests/cli_json/dkim.rs"),
	("dkim cleanup", "src/cli/dkim_cli_cleanup_tests.rs"),
	("tls renew", "src/cli/tls_cli_tests.rs"),
	("db upgrade", "needs the stack and the database"),
	("stack update", "needs the stack; tests/cli_json/stack.rs"),
	("stack up", "tests/cli_json/stack.rs"),
	("stack down", "tests/cli_json/stack.rs"),
	("stack ps", "needs podup output; tests/cli_json/stack.rs"),
	("stack restart", "tests/cli_json/stack.rs"),
	("stack stop", "tests/cli_json/stack.rs"),
	("stack start", "tests/cli_json/stack.rs"),
	("stack rollback", "replaces the installed binary, as root"),
	("init", "tests/cli_json/init.rs"),
	(
		"restore",
		"reads an archive on stdin; src/cli/dispatch_restore_tests.rs",
	),
	(
		"import",
		"reads a mailbox stream; tests/cli_json/top_level.rs",
	),
	("migrate imap", "needs a remote IMAP server"),
	("migrate mox", "needs a Mox installation"),
	("migrate stalwart", "needs a Stalwart installation"),
];

const ID: &str = "01a142e5-edcf-7490-9152-8a1a76b72933";

/// The cases, in the order they run on one shared setup (account `bob`
/// exists, `srs_secret` is set and the delivery log is on).
#[rustfmt::skip]
const CASES: &[(&str, &[&str], Expect)] = &[
	("config-check", &[], Done),
	("dkim-keygen", &["--out", "@TMP/sweep-dkim.pem"], Done),
	("storage-keygen", &[], Done),
	("oauth-keygen", &["--out", "@TMP/sweep-oauth.toml"], Done),
	("verify", &[], Done),
	("srv-records", &[], Done),
	("token-hash", &[], Done),
	("reports", &[], Done),
	("suppression list", &[], Done),
	("suppression add", &["gone@example.net"], Done),
	("suppression remove", &["gone@example.net"], Done),
	("account list", &[], Done),
	(
		"account add",
		&["alice", "--address", "alice@example.org"],
		Done,
	),
	("account show", &["alice"], Done),
	("account set-name", &["alice", "Alice A"], Done),
	("account password", &["alice"], Done),
	("account disable", &["alice"], Done),
	("account enable", &["alice"], Done),
	("account address add", &["alice", "a2@example.org"], Done),
	("account address remove", &["alice", "a2@example.org"], Done),
	("account quota", &["alice", "1G"], Done),
	("account protocols", &["alice", "imap,smtp"], Done),
	("account save-sent", &["alice", "off"], Done),
	("account find-log-id", &["acct-000000000000"], Refused(2)),
	("account 2fa show", &["alice"], Done),
	("account 2fa disable", &["alice", "--yes"], Done),
	("account forward list", &["alice"], Done),
	("account forward add", &["alice", "out@example.com"], Done),
	(
		"account forward remove",
		&["alice", "out@example.com"],
		Done,
	),
	("account catch-all list", &["alice"], Done),
	("account catch-all add", &["alice", "example.org"], Done),
	("account catch-all remove", &["alice", "example.org"], Done),
	("queue list", &[], Done),
	("queue show", &[ID], Refused(2)),
	("queue retry", &["--all"], Done),
	("queue hold", &["--all"], Done),
	("queue release", &["--all"], Done),
	("queue destinations", &[], Done),
	("queue release-destination", &["--all"], Done),
	("queue remove", &[ID, "--yes"], Refused(2)),
	("warmup status", &[], Done),
	("warmup plan", &["--all"], Done),
	("warmup start", &["--all", "--yes"], Done),
	("warmup enable", &["--yes"], Done),
	("warmup pause", &[], Done),
	("warmup resume", &[], Done),
	("warmup set", &["gmail", "--next", "--yes"], Done),
	("warmup reset", &["gmail", "--yes"], Done),
	("warmup disable", &["--yes"], Done),
	("delivery list", &[], Done),
	("masked list", &["bob"], Done),
	("masked add", &["bob", "--label", "shop"], Done),
	("masked remove", &["bob", "nobody@example.org"], Refused(2)),
	("masked enable", &["bob", "nobody@example.org"], Refused(2)),
	("masked disable", &["bob", "nobody@example.org"], Refused(2)),
	("app-password list", &[], Done),
	("app-password create", &["bob", "phone"], Done),
	("app-password revoke", &["bob", "phone", "--yes"], Done),
	("archive list", &["bob"], Done),
	("archive restore", &["bob", ID], Refused(1)),
	("archive purge", &["bob", "--yes"], Done),
	("domain list", &[], Done),
	("domain show", &["example.org"], Done),
	("domain add", &["example.net"], Done),
	(
		"domain alias add",
		&["alias.example.net", "example.net"],
		Done,
	),
	("domain alias remove", &["alias.example.net", "--yes"], Done),
	("domain remove", &["example.net", "--yes"], Done),
	("suppression", &[], Done),
	("delivery", &[], Done),
	("queue", &[], Done),
	("limits set", &["quota", "2G", "--dry-run"], Done),
	("limits unset", &["quota", "--dry-run"], Done),
	("limits show", &[], Done),
	("limits set", &["quota", "2G"], Done),
	("limits unset", &["quota"], Done),
	("dns provider show", &[], Done),
	(
		"dns provider set",
		&["manual", "--zone", "example.org"],
		Done,
	),
	("dns provider unset", &[], Done),
	("storage blobs show", &[], Done),
	("storage blobs set fs", &[], Done),
	("storage blobs set s3", &["--endpoint", "https://s3.example.net", "--bucket", "mail", "--region", "us-east-1", "--access-key-id", "AKIAEXAMPLE", "--secret-env", "EPISTLE_SWEEP_S3", "--force"], Done),
	("webhook show", &[], Done),
	("webhook set", &["https://hooks.example.net/in"], Done),
	("alert list", &[], Done),
	("alert add", &["spool", "--metric", "accepted", "--op", ">", "--threshold", "100", "--window", "5m", "--webhook"], Done),
	("alert remove", &["spool"], Done),
	("webhook unset", &[], Done),
	("relay list", &[], Done),
	("relay show", &[], Refused(2)),
	(
		"relay add",
		&["--domain", "example.net", "--host", "relay.example.net"],
		Done,
	),
	("relay remove", &["--domain", "example.net"], Done),
	("service list", &[], Done),
	("service enable", &["webdav"], Done),
	("service disable", &["webdav"], Done),
	("antispam show", &[], Done),
	("antispam set", &["greylist-delay", "5m"], Done),
	("antispam add", &["dnsbl-zones", "zen.spamhaus.org"], Done),
	(
		"antispam remove",
		&["dnsbl-zones", "zen.spamhaus.org"],
		Done,
	),
	("antispam unset", &["greylist-delay"], Done),
	("attachments policy show", &[], Done),
	("attachments policy set", &["mode", "quarantine"], Done),
	("attachments policy unset", &["mode"], Done),
	("attachments check", &["@TMP/sweep.eml"], Done),
	("alias list", &[], Done),
	("alias add", &["team@example.org", "bob@example.org"], Done),
	("alias show", &["team@example.org"], Done),
	(
		"alias member add",
		&["team@example.org", "alice@example.org"],
		Done,
	),
	(
		"alias member remove",
		&["team@example.org", "alice@example.org"],
		Done,
	),
	(
		"alias sender add",
		&["team@example.org", "alice@example.org"],
		Done,
	),
	(
		"alias sender remove",
		&["team@example.org", "alice@example.org"],
		Done,
	),
	("alias disable", &["team@example.org"], Done),
	("alias enable", &["team@example.org"], Done),
	("alias remove", &["team@example.org", "--yes"], Done),
	("tls show", &[], Refused(1)),
	("api-key list", &[], Done),
	("api-key create", &["ci", "--scope", "read"], Done),
	("api-key rotate", &["ci"], Done),
	("api-key revoke", &["ci", "--yes"], Done),
	("account remove", &["alice", "--queue", "drain", "--yes"], Done),
	("stack resources", &[], Done),
	("stack resources set", &["clamav", "--memory", "2g"], Done),
];

/// `--help` of `path`, and the leaves below it.
fn leaves(path: &[&str], found: &mut BTreeSet<String>) {
	let mut args = path.to_vec();
	args.push("--help");
	let help = String::from_utf8_lossy(&epistle(&args, b"").stdout).into_owned();
	let commands: Vec<&str> = help
		.split("Commands:\n")
		.nth(1)
		.map(|rest| rest.split("\n\n").next().unwrap_or(rest))
		.into_iter()
		.flat_map(str::lines)
		.filter_map(|line| line.strip_prefix("  "))
		.filter_map(|line| line.split_whitespace().next())
		.filter(|name| *name != "help")
		.collect();
	if commands.is_empty() {
		found.insert(path.join(" "));
		return;
	}
	for name in commands {
		let mut child = path.to_vec();
		child.push(name);
		leaves(&child, found);
	}
}

#[test]
fn every_leaf_is_run_here_skipped_with_a_reason_or_exempt() {
	let mut found = BTreeSet::new();
	leaves(&[], &mut found);
	assert!(
		found.len() > 100,
		"the walk found only {} leaves",
		found.len()
	);
	let known: BTreeSet<String> = CASES
		.iter()
		.map(|(path, _, _)| (*path).to_string())
		.chain(SKIPPED.iter().map(|(path, _)| (*path).to_string()))
		.chain(EXEMPT.iter().map(|path| (*path).to_string()))
		.collect();
	let unplaced: Vec<&String> = found.difference(&known).collect();
	assert!(
		unplaced.is_empty(),
		"leaves that are neither run, skipped nor exempt: {unplaced:?}"
	);
	// A name that is a command with an action of its own (`queue`,
	// `delivery`) is the form without the action, not a missing command.
	let gone: Vec<&String> = known
		.difference(&found)
		.filter(|name| {
			!found
				.iter()
				.any(|leaf| leaf.starts_with(&format!("{name} ")))
		})
		.collect();
	assert!(gone.is_empty(), "named here but not a command: {gone:?}");
}

fn write_compose(env: &crate::harness::Env) {
	let compose = env.data_dir().join("compose/compose.yaml");
	std::fs::create_dir_all(compose.parent().expect("parent")).expect("compose dir");
	std::fs::write(
		&compose,
		r#"{"services":{"mail":{"mem_limit":"1g","pids_limit":1024},"db":{"mem_limit":"1g","pids_limit":256},"clamav":{"mem_limit":"3g","pids_limit":128},"freshclam":{"mem_limit":"2g","pids_limit":32}}}"#,
	)
	.expect("write compose");
}

#[test]
fn every_leaf_honours_json() {
	let env = env(
		"srs_secret = \"0123456789abcdef0123456789abcdef\"\n[storage]\ndelivery_log_days = 7\n",
	);
	add_account(&env, "bob");
	let tmp = env.dir.path().to_string_lossy().into_owned();
	let mut problems = Vec::new();
	for (path, args, expect) in CASES {
		// The limits live in the compose file, which only these cases need:
		// with it present a configuration edit would try to restart the stack.
		if path.starts_with("stack resources") {
			write_compose(&env);
		}
		if *path == "attachments check" {
			std::fs::write(
				env.dir.path().join("sweep.eml"),
				"From: x@example.net\r\nSubject: hi\r\n\r\nhello\r\n",
			)
			.expect("write sweep.eml");
		}
		let mut full: Vec<String> = path.split(' ').map(str::to_string).collect();
		full.extend(args.iter().map(|arg| arg.replace("@TMP", &tmp)));
		if !NO_CONFIG.contains(path) {
			full.extend(["--config".into(), env.config.clone()]);
		}
		full.push("--json".into());
		let refs: Vec<&str> = full.iter().map(String::as_str).collect();
		let output = epistle(&refs, PASSWORD);
		let code = output.status.code().unwrap_or(-1);
		let stdout = String::from_utf8_lossy(&output.stdout);
		let documents = serde_json::Deserializer::from_str(&stdout)
			.into_iter::<serde_json::Value>()
			.collect::<Result<Vec<_>, _>>();
		let stderr = String::from_utf8_lossy(&output.stderr);
		let verdict = match (expect, &documents) {
			(Expect::Done, Ok(docs)) if code == 0 && docs.len() == 1 => None,
			(Expect::Refused(want), _) if code == *want && stdout.is_empty() => None,
			(_, Ok(docs)) => Some(format!("exit {code}, {} documents", docs.len())),
			(_, Err(error)) => Some(format!("exit {code}, stdout is not JSON: {error}")),
		};
		if let Some(verdict) = verdict {
			problems.push(format!(
				"{path} {args:?} wanted {expect:?}: {verdict}; stderr: {}",
				stderr.lines().next().unwrap_or("")
			));
		}
	}
	assert!(problems.is_empty(), "{}", problems.join("\n"));
}
