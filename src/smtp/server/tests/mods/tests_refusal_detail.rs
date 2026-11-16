//! `[smtp] reject_detail` and `[smtp] reject_reference`: the same refusal at
//! each level changes its text and nothing else, and a final refusal carries
//! a reference the log line of the same refusal repeats. Only example data.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing_subscriber::layer::SubscriberExt;

use super::tests_refusal_text::{Dns, Setup, refusal_with};
use super::*;
use crate::config::RefusalDetail::{self, Standard, Terse, Verbose};
use crate::smtp::ratelimit::{InboundLimit, SendLimiter};
use crate::smtp::server::refusal::Site;
use crate::smtp::sink::MemorySink;

const LEVELS: [RefusalDetail; 3] = [Terse, Standard, Verbose];

fn setup(detail: RefusalDetail) -> Setup {
	Setup {
		detail,
		reference: false,
	}
}

/// The refusal of one message at each level, in the order of [`LEVELS`].
async fn at_each_level(
	dns: impl Fn() -> Dns,
	dnsbl: impl Fn() -> crate::dnsbl::Dnsbl,
	from: &str,
	body: &str,
) -> Vec<String> {
	let mut lines = Vec::new();
	for detail in LEVELS {
		lines.push(refusal_with(setup(detail), dns(), dnsbl(), from, body).await);
	}
	lines
}

/// The reply code and the enhanced status code: what no level may change.
fn class(line: &str) -> (&str, &str) {
	let mut words = line.split(' ');
	(words.next().unwrap_or(""), words.next().unwrap_or(""))
}

fn same_class(lines: &[String]) {
	for line in lines {
		assert_eq!(class(line), class(&lines[0]), "{lines:?}");
	}
}

fn spf_fail() -> Dns {
	Dns {
		txt: vec![("sender.example", "v=spf1 -all")],
		..Dns::default()
	}
}

#[tokio::test]
async fn an_spf_failure_says_each_level_and_keeps_its_code() {
	let lines = at_each_level(
		spf_fail,
		crate::dnsbl::Dnsbl::default,
		"eve@sender.example",
		"hi",
	)
	.await;
	same_class(&lines);
	assert_eq!(lines[0], "550 5.7.23 message refused");
	assert_eq!(
		lines[1],
		"550 5.7.23 SPF validation failed for 192.0.2.7 as sender of sender.example (result: fail)"
	);
	assert_eq!(
		lines[2],
		"550 5.7.23 SPF validation failed for 192.0.2.7 as sender of sender.example (result: fail); \
		 add 192.0.2.7 to the SPF record of sender.example or send through a host it lists"
	);
}

#[tokio::test]
async fn a_terse_refusal_names_no_check_no_address_and_no_list() {
	let spf = at_each_level(
		spf_fail,
		crate::dnsbl::Dnsbl::default,
		"eve@sender.example",
		"hi",
	)
	.await;
	let listed = || Dns {
		listed: vec!["7.2.0.192.bl.example"],
		..Dns::default()
	};
	let dnsbl = || crate::dnsbl::Dnsbl::new(["bl.example".to_string()]);
	let list = at_each_level(listed, dnsbl, "eve@sender.example", "hi").await;
	for line in [&spf[0], &list[0]] {
		for word in [
			"SPF",
			"DMARC",
			"blocklist",
			"bl.example",
			"192.0.2.7",
			"sender",
		] {
			assert!(!line.contains(word), "{line} names {word}");
		}
	}
}

#[tokio::test]
async fn a_temporary_spf_error_stays_451_and_4_7_24_at_every_level() {
	let broken = || Dns {
		broken: vec!["sender.example"],
		..Dns::default()
	};
	let lines = at_each_level(
		broken,
		crate::dnsbl::Dnsbl::default,
		"eve@sender.example",
		"hi",
	)
	.await;
	same_class(&lines);
	assert_eq!(class(&lines[0]), ("451", "4.7.24"));
	assert_eq!(lines[0], "451 4.7.24 try again later");
	assert!(lines[1].ends_with("(result: temperror)"), "{}", lines[1]);
	assert!(
		lines[2].ends_with("; the DNS of sender.example did not answer, retry later"),
		"{}",
		lines[2]
	);
}

#[tokio::test]
async fn a_dmarc_refusal_says_each_level_and_keeps_its_code() {
	let dns = || Dns {
		txt: vec![
			("sender.example", "v=spf1 ip4:192.0.2.0/24 -all"),
			("_dmarc.bank.example", "v=DMARC1; p=reject"),
		],
		..Dns::default()
	};
	let lines = at_each_level(dns, crate::dnsbl::Dnsbl::default, "ceo@bank.example", "hi").await;
	same_class(&lines);
	assert_eq!(lines[0], "550 5.7.1 message refused");
	assert_eq!(
		lines[1],
		"550 5.7.1 rejected by DMARC policy of bank.example (p=reject, result: fail)"
	);
	assert_eq!(
		lines[2],
		"550 5.7.1 rejected by DMARC policy of bank.example (p=reject, result: fail); \
		 make SPF or DKIM pass for a domain aligned with bank.example"
	);
}

#[tokio::test]
async fn a_temporary_dmarc_error_says_each_level_and_keeps_its_code() {
	let dns = || Dns {
		txt: vec![("sender.example", "v=spf1 ip4:192.0.2.0/24 -all")],
		broken: vec!["_dmarc.bank.example"],
		..Dns::default()
	};
	let lines = at_each_level(dns, crate::dnsbl::Dnsbl::default, "ceo@bank.example", "hi").await;
	same_class(&lines);
	assert_eq!(lines[0], "451 4.7.24 try again later");
	assert_eq!(
		lines[1],
		"451 4.7.24 DMARC check temporarily failed for bank.example (result: temperror)"
	);
	assert!(lines[2].starts_with(&lines[1]), "{}", lines[2]);
	assert!(
		lines[2].ends_with("; the DNS of bank.example did not answer, retry later"),
		"{}",
		lines[2]
	);
}

#[tokio::test]
async fn a_blocklist_refusal_says_each_level_and_keeps_its_code() {
	let client = || Dns {
		listed: vec!["7.2.0.192.bl.example"],
		..Dns::default()
	};
	let lines = at_each_level(
		client,
		|| crate::dnsbl::Dnsbl::new(["bl.example".to_string()]),
		"eve@sender.example",
		"hi",
	)
	.await;
	same_class(&lines);
	assert_eq!(lines[0], "554 5.7.1 message refused");
	assert_eq!(
		lines[1],
		"554 5.7.1 client host 192.0.2.7 blocked by DNS blocklist bl.example (result: listed)"
	);
	assert_eq!(
		lines[2],
		"554 5.7.1 client host 192.0.2.7 blocked by DNS blocklist bl.example (result: listed); \
		 ask DNS blocklist bl.example to delist 192.0.2.7"
	);

	let domain = || Dns {
		listed: vec!["sender.example.dbl.example"],
		..Dns::default()
	};
	let lines = at_each_level(
		domain,
		|| crate::dnsbl::Dnsbl::default().with_domain_zones(["dbl.example".to_string()]),
		"eve@sender.example",
		"hi",
	)
	.await;
	same_class(&lines);
	assert!(
		lines[2].ends_with("; ask DNS blocklist dbl.example to delist sender.example"),
		"{}",
		lines[2]
	);

	let url = || Dns {
		listed: vec!["spam.example.uri.example"],
		..Dns::default()
	};
	let lines = at_each_level(
		url,
		|| crate::dnsbl::Dnsbl::default().with_url_zones(["uri.example".to_string()]),
		"eve@sender.example",
		"see http://spam.example/x",
	)
	.await;
	same_class(&lines);
	assert!(
		lines[2].ends_with("; remove the links DNS blocklist uri.example lists"),
		"{}",
		lines[2]
	);
}

#[tokio::test]
async fn a_verbose_blocklist_refusal_never_quotes_the_key_in_the_zone() {
	let dns = Dns {
		listed: vec!["7.2.0.192.abcd1234efgh5678.zen.dq.spamhaus.net"],
		..Dns::default()
	};
	let dnsbl = crate::dnsbl::Dnsbl::new(["abcd1234efgh5678.zen.dq.spamhaus.net".to_string()]);
	let line = refusal_with(setup(Verbose), dns, dnsbl, "eve@sender.example", "hi").await;
	assert!(line.contains("ask DNS blocklist spamhaus.net"), "{line}");
	assert!(!line.contains("abcd1234efgh5678"), "{line}");
}

/// Everything the server writes for `script` sent from 192.0.2.7 to a
/// server built by `build`.
async fn conversation(build: impl FnOnce(Server) -> Server, script: &str) -> String {
	let sink = Arc::new(MemorySink::new());
	let server = build(
		Server::new("mail.example.org", sink as Arc<dyn MessageSink>).with_directory(
			DirectoryHandle::new(Directory::new(
				["example.org".to_string()],
				[("bob@example.org".to_string(), "bob".to_string())],
			)),
		),
	);
	let (client, server_stream) = tokio::io::duplex(64 * 1024);
	let peer = Some("192.0.2.7".parse().expect("ip"));
	let task = tokio::spawn(async move { server.handle(server_stream, peer).await });
	let (mut read, mut write) = tokio::io::split(client);
	write.write_all(script.as_bytes()).await.expect("write");
	write.shutdown().await.expect("shutdown");
	let mut output = Vec::new();
	read.read_to_end(&mut output).await.expect("read");
	task.await.expect("task").expect("server result");
	String::from_utf8(output).expect("ascii")
}

fn line_with<'a>(output: &'a str, code: &str) -> &'a str {
	output
		.lines()
		.find(|line| line.starts_with(code))
		.unwrap_or_else(|| panic!("no {code} in {output}"))
}

/// Two messages from one client against a limit of one a minute: the line
/// that refuses the second at `MAIL FROM`.
async fn limit_refusal(detail: RefusalDetail) -> String {
	let limit = InboundLimit {
		limiter: Arc::new(SendLimiter::new(60)),
		per_min: 1,
	};
	let output = conversation(
		|server| {
			server
				.with_refusal(detail, false)
				.with_inbound_ip_limit(limit)
		},
		"EHLO client.example.org\r\nMAIL FROM:<eve@sender.example>\r\nRSET\r\n\
		 MAIL FROM:<eve@sender.example>\r\nQUIT\r\n",
	)
	.await;
	line_with(&output, "450").to_string()
}

#[tokio::test]
async fn a_limit_says_each_level_and_keeps_its_code() {
	let before = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.expect("clock")
		.as_secs();
	let terse = limit_refusal(Terse).await;
	let standard = limit_refusal(Standard).await;
	let verbose = limit_refusal(Verbose).await;
	same_class(&[terse.clone(), standard.clone(), verbose.clone()]);
	assert_eq!(terse, "450 4.7.1 try again later");
	assert_eq!(
		standard,
		"450 4.7.1 too many messages from this client; retry later"
	);
	// The window began when the first message was counted, inside the span
	// the verbose refusal was drawn in, and ends a minute after.
	let figures = "450 4.7.1 too many messages from this client (max 1/min); retry after ";
	let clock = verbose.strip_prefix(figures).expect(&verbose);
	let now = || {
		std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.expect("clock")
			.as_secs()
	};
	let after = now();
	let candidates: Vec<String> = (before..=after)
		.map(|start| crate::smtp::retry_time::clock_at(start + 60))
		.collect();
	assert!(
		candidates.iter().any(|c| c == clock),
		"{verbose} {candidates:?}"
	);
}

#[tokio::test]
async fn the_retry_time_is_the_end_of_the_window_the_refusal_came_in() {
	let limiter = SendLimiter::new(60);
	assert!(limiter.check("192.0.2.7", 1, 1_000));
	assert!(!limiter.check("192.0.2.7", 1, 1_010));
	assert_eq!(limiter.retry_at("192.0.2.7", 1_010), 1_060);
	assert_eq!(limiter.retry_at("192.0.2.8", 1_010), 1_010);
	assert_eq!(limiter.retry_at("192.0.2.7", 1_060), 1_060);
}

/// A first attempt of a triplet with a greylist of 300 seconds: the line
/// that defers it at the end of DATA.
async fn greylist_refusal(detail: RefusalDetail) -> String {
	let output = conversation(
		|server| {
			server.with_refusal(detail, false).with_greylist(
				Arc::new(crate::antispam::greylist::MemoryGreylist::new()),
				300,
			)
		},
		"EHLO client.example.org\r\nMAIL FROM:<eve@sender.example>\r\n\
		 RCPT TO:<bob@example.org>\r\nDATA\r\nSubject: hi\r\n\r\nhi\r\n.\r\nQUIT\r\n",
	)
	.await;
	line_with(&output, "451").to_string()
}

#[tokio::test]
async fn a_greylist_deferral_says_each_level_and_keeps_its_code() {
	let terse = greylist_refusal(Terse).await;
	let standard = greylist_refusal(Standard).await;
	let verbose = greylist_refusal(Verbose).await;
	same_class(&[terse.clone(), standard.clone(), verbose.clone()]);
	assert_eq!(terse, "451 4.7.1 try again later");
	assert_eq!(standard, "451 4.7.1 greylisted, please retry shortly");
	let clock = verbose
		.strip_prefix("451 4.7.1 greylisted, please retry after ")
		.expect(&verbose);
	assert!(clock.len() == 9 && clock.ends_with(" UTC"), "{verbose}");
}

/// The reference at the end of `line`, when it ends with one.
fn reference_of(line: &str) -> Option<&str> {
	let tail = line.strip_suffix(')')?;
	let (_, reference) = tail.rsplit_once(" (ref ")?;
	let hex = reference.len() == 6
		&& reference
			.bytes()
			.all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
	hex.then_some(reference)
}

/// The refusal of an SPF failure with the reference on, the events logged
/// while it was sent, and the refusal with the reference off.
async fn spf_refusal_logged(
	reference: bool,
) -> (String, Vec<crate::cli::trace::capture::CapturedEvent>) {
	crate::cli::trace::capture::keep_callsites_live();
	let capture = crate::cli::trace::capture::Capture::default();
	let events = capture.events.clone();
	let _guard =
		tracing::subscriber::set_default(tracing_subscriber::registry().with(capture.clone()));
	let setup = Setup {
		detail: Standard,
		reference,
	};
	let line = refusal_with(
		setup,
		spf_fail(),
		crate::dnsbl::Dnsbl::default(),
		"eve@sender.example",
		"hi",
	)
	.await;
	let captured = std::mem::take(&mut *events.lock().expect("capture"));
	(line, captured)
}

#[tokio::test]
async fn a_final_refusal_carries_a_reference_and_the_log_line_repeats_it() {
	let (line, captured) = spf_refusal_logged(true).await;
	let reference = reference_of(&line).unwrap_or_else(|| panic!("no reference in {line}"));
	assert_eq!(
		line,
		format!(
			"550 5.7.23 SPF validation failed for 192.0.2.7 as sender of sender.example \
			 (result: fail) (ref {reference})"
		)
	);
	let logged: Vec<_> = captured
		.iter()
		.filter(|event| event.fields.contains_key("reference"))
		.collect();
	assert_eq!(logged.len(), 1, "one log line carries the reference");
	let event = logged[0];
	assert_eq!(event.fields["reference"], reference);
	assert_eq!(event.fields["code"], "550");
	assert_eq!(event.fields["ip"], "192.0.2.7");
	assert_eq!(event.level, tracing::Level::INFO);
	assert!(
		event.fields["reply"].starts_with("5.7.23 SPF validation failed"),
		"{:?}",
		event.fields
	);
}

#[tokio::test]
async fn with_the_reference_off_the_text_is_unchanged_and_nothing_is_logged_for_it() {
	let (line, captured) = spf_refusal_logged(false).await;
	assert_eq!(
		line,
		"550 5.7.23 SPF validation failed for 192.0.2.7 as sender of sender.example (result: fail)"
	);
	assert!(
		captured
			.iter()
			.all(|event| !event.fields.contains_key("reference")),
		"{captured:?}"
	);
}

#[tokio::test]
async fn the_reference_comes_from_no_counter_and_no_server_name() {
	let mut seen = std::collections::HashSet::new();
	for _ in 0..8 {
		let setup = Setup {
			detail: Standard,
			reference: true,
		};
		let line = refusal_with(
			setup,
			spf_fail(),
			crate::dnsbl::Dnsbl::default(),
			"eve@sender.example",
			"hi",
		)
		.await;
		let reference = reference_of(&line).expect("a reference").to_string();
		seen.insert(reference);
	}
	// Eight draws of 24 bits: a counter would give consecutive values, and
	// a value derived from the server or the client would give one.
	assert!(seen.len() >= 7, "{seen:?}");
}

#[tokio::test]
async fn a_four_hundred_after_data_carries_a_reference_and_one_at_a_command_does_not() {
	let limit = InboundLimit {
		limiter: Arc::new(SendLimiter::new(60)),
		per_min: 1,
	};
	let output = conversation(
		|server| {
			server
				.with_refusal(Standard, true)
				.with_inbound_ip_limit(limit)
				.with_greylist(
					Arc::new(crate::antispam::greylist::MemoryGreylist::new()),
					300,
				)
		},
		"EHLO client.example.org\r\nMAIL FROM:<eve@sender.example>\r\n\
		 RCPT TO:<bob@example.org>\r\nDATA\r\nSubject: hi\r\n\r\nhi\r\n.\r\n\
		 MAIL FROM:<eve@sender.example>\r\nQUIT\r\n",
	)
	.await;
	let deferred = line_with(&output, "451");
	assert!(reference_of(deferred).is_some(), "{deferred}");
	let limited = line_with(&output, "450");
	assert_eq!(
		limited,
		"450 4.7.1 too many messages from this client; retry later"
	);
	for ok in output.lines().filter(|line| line.starts_with('2')) {
		assert!(reference_of(ok).is_none(), "{ok}");
	}
}

#[tokio::test]
async fn a_permanent_refusal_at_a_command_carries_a_reference() {
	let output = conversation(
		|server| server.with_refusal(Standard, true),
		"EHLO client.example.org\r\nMAIL FROM:<eve@sender.example>\r\n\
		 RCPT TO:<nobody@example.org>\r\nFOO\r\nQUIT\r\n",
	)
	.await;
	let unknown = line_with(&output, "550");
	assert!(reference_of(unknown).is_some(), "{unknown}");
	let syntax = line_with(&output, "500");
	assert!(reference_of(syntax).is_none(), "{syntax}");
}

#[test]
fn the_site_of_a_line_decides_which_refusals_carry_a_reference() {
	assert_eq!(Site::of(false, b"MAIL FROM:<a@example.net>"), Site::Command);
	assert_eq!(Site::of(false, b"rcpt to:<a@example.net>"), Site::Command);
	assert_eq!(Site::of(false, b"DATA"), Site::Command);
	assert_eq!(Site::of(false, b"BDAT 10 LAST"), Site::AfterData);
	assert_eq!(Site::of(true, b"anything"), Site::AfterData);
	assert_eq!(Site::of(false, b"NOOP"), Site::Other);
	assert_eq!(Site::of(false, b""), Site::Other);
}
