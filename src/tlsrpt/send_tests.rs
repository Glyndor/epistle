//! The daily pass turns a day's journal into reports and then forgets it.

use std::collections::HashMap;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;

use base64::Engine;

use super::*;
use crate::queue::tls_outcome::TlsOutcome;
use crate::smtp::sink::MemorySink;
use crate::spf::DnsFailure;
use crate::tlsrpt::sessions::{Attempt, record};

/// 2024-01-01T12:00:00Z; the pass runs on 2024-01-02.
const NOW: u64 = 1_704_110_400;
const DAY_START: u64 = 1_704_067_200;
const TODAY: &str = "20240102";

#[derive(Default)]
struct Dns {
	txt: HashMap<String, Vec<String>>,
	down: bool,
}

type Lookup<'a, T> = Pin<Box<dyn Future<Output = Result<T, DnsFailure>> + Send + 'a>>;

impl DnsLookup for Dns {
	fn txt(&self, name: &str) -> Lookup<'_, Vec<String>> {
		let answer = match self.down {
			true => Err(DnsFailure::Temporary),
			false => Ok(self.txt.get(name).cloned().unwrap_or_default()),
		};
		Box::pin(async move { answer })
	}
	fn addresses(&self, _name: &str) -> Lookup<'_, Vec<IpAddr>> {
		Box::pin(async { Ok(Vec::new()) })
	}
	fn mx(&self, _name: &str) -> Lookup<'_, Vec<String>> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

fn dns(records: &[(&str, &str)]) -> Dns {
	let mut dns = Dns::default();
	for (domain, value) in records {
		dns.txt
			.entry(format!("_smtp._tls.{domain}"))
			.or_default()
			.push(value.to_string());
	}
	dns
}

/// Records each POST as (url, body).
#[derive(Default)]
struct Poster {
	posts: Mutex<Vec<(String, Vec<u8>)>>,
}

impl ReportPoster for Poster {
	fn post<'a>(&'a self, url: &'a str, body: &'a [u8]) -> Fut<'a, Result<(), String>> {
		self.posts
			.lock()
			.expect("posts")
			.push((url.to_string(), body.to_vec()));
		Box::pin(async { Ok(()) })
	}
}

fn journal(data_dir: &Path, domain: &str, outcomes: &[TlsOutcome]) {
	for outcome in outcomes {
		let attempt = Attempt {
			policy_domain: domain,
			mx_host: "mx.remote.example",
			sts: None,
			sts_invalid: false,
			sts_fetch_failed: false,
			dane: false,
			local_ip: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))),
			peer_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))),
		};
		record(data_dir, NOW, &attempt, *outcome);
	}
}

async fn pass(data_dir: &Path, dns: &Dns, sink: &MemorySink, poster: &Poster) {
	let sender = Sender {
		data_dir,
		hostname: "mail.sender.example",
		dns,
		sink,
		poster,
		auto_submitted: true,
	};
	send_pending(&sender, TODAY).await;
}

/// The report JSON inside a queued message's gzip attachment.
fn attached_report(data: &[u8]) -> serde_json::Value {
	let text = String::from_utf8_lossy(data);
	let start = text
		.find("Content-Disposition: attachment")
		.and_then(|at| text[at..].find("\r\n\r\n").map(|end| at + end + 4))
		.expect("attachment part");
	let encoded: String = text[start..]
		.lines()
		.take_while(|line| !line.is_empty())
		.collect();
	let gzip = base64::engine::general_purpose::STANDARD
		.decode(encoded)
		.expect("base64");
	let mut json = String::new();
	flate2::read::GzDecoder::new(gzip.as_slice())
		.read_to_string(&mut json)
		.expect("gzip");
	serde_json::from_str(&json).expect("json")
}

const FAILED: TlsOutcome = TlsOutcome::Failure("certificate-not-trusted");

#[tokio::test]
async fn mailto_rua_gets_one_report_with_the_days_counts() {
	let dir = tempfile::tempdir().expect("tempdir");
	journal(
		dir.path(),
		"remote.example",
		&[TlsOutcome::Success, TlsOutcome::Success, FAILED],
	);
	let dns = dns(&[(
		"remote.example",
		"v=TLSRPTv1; rua=mailto:tlsrpt@remote.example",
	)]);
	let sink = MemorySink::new();
	pass(dir.path(), &dns, &sink, &Poster::default()).await;

	let messages = sink.messages();
	assert_eq!(messages.len(), 1, "one message per mailto rua");
	assert_eq!(
		messages[0].recipients,
		vec!["tlsrpt@remote.example".to_string()]
	);
	assert_eq!(messages[0].reverse_path, "postmaster@mail.sender.example");
	let report = attached_report(&messages[0].data);
	assert_eq!(
		report["date-range"]["start-datetime"],
		crate::clock::rfc3339(DAY_START)
	);
	assert_eq!(
		report["date-range"]["end-datetime"],
		crate::clock::rfc3339(DAY_START + 86_400)
	);
	let policy = &report["policies"][0];
	assert_eq!(policy["policy"]["policy-domain"], "remote.example");
	assert_eq!(policy["summary"]["total-successful-session-count"], 2);
	assert_eq!(policy["summary"]["total-failure-session-count"], 1);
	assert_eq!(
		policy["failure-details"][0]["result-type"],
		"certificate-not-trusted"
	);
	assert_eq!(
		policy["failure-details"][0]["sending-mta-ip"],
		"203.0.113.5"
	);
}

#[tokio::test]
async fn sessions_are_removed_after_the_report_went_out() {
	let dir = tempfile::tempdir().expect("tempdir");
	journal(dir.path(), "remote.example", &[TlsOutcome::Success]);
	let dns = dns(&[(
		"remote.example",
		"v=TLSRPTv1; rua=mailto:tlsrpt@remote.example",
	)]);
	let sink = MemorySink::new();
	pass(dir.path(), &dns, &sink, &Poster::default()).await;
	assert!(
		!dir.path().join("reports/tlsrpt-outbound/20240101").exists(),
		"the reported day is still in the journal"
	);
	// A second pass has nothing left to send.
	pass(dir.path(), &dns, &sink, &Poster::default()).await;
	assert_eq!(sink.messages().len(), 1);
}

#[tokio::test]
async fn domain_without_a_record_gets_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	journal(dir.path(), "quiet.example", &[FAILED]);
	let sink = MemorySink::new();
	let poster = Poster::default();
	pass(dir.path(), &dns(&[]), &sink, &poster).await;
	assert_eq!(sink.messages().len(), 0);
	assert_eq!(poster.posts.lock().expect("posts").len(), 0);
	assert!(!dir.path().join("reports/tlsrpt-outbound/20240101").exists());
}

#[tokio::test]
async fn transient_dns_failure_keeps_the_day_for_the_next_pass() {
	let dir = tempfile::tempdir().expect("tempdir");
	journal(dir.path(), "remote.example", &[FAILED]);
	let down = Dns {
		down: true,
		..Dns::default()
	};
	let sink = MemorySink::new();
	pass(dir.path(), &down, &sink, &Poster::default()).await;
	assert_eq!(sink.messages().len(), 0);
	assert!(
		dir.path()
			.join("reports/tlsrpt-outbound/20240101/remote.example.jsonl")
			.exists()
	);
}

#[tokio::test]
async fn https_rua_gets_the_gzip_report_posted() {
	let dir = tempfile::tempdir().expect("tempdir");
	journal(dir.path(), "remote.example", &[FAILED]);
	let dns = dns(&[(
		"remote.example",
		"v=TLSRPTv1; rua=https://reports.remote.example/tlsrpt",
	)]);
	let sink = MemorySink::new();
	let poster = Poster::default();
	pass(dir.path(), &dns, &sink, &poster).await;
	assert_eq!(sink.messages().len(), 0);
	let posts = poster.posts.lock().expect("posts");
	assert_eq!(posts.len(), 1);
	assert_eq!(posts[0].0, "https://reports.remote.example/tlsrpt");
	let mut json = String::new();
	flate2::read::GzDecoder::new(posts[0].1.as_slice())
		.read_to_string(&mut json)
		.expect("gzip body");
	let report: serde_json::Value = serde_json::from_str(&json).expect("json");
	assert_eq!(
		report["policies"][0]["summary"]["total-failure-session-count"],
		1
	);
}

#[tokio::test]
async fn todays_sessions_wait_for_the_day_to_end() {
	let dir = tempfile::tempdir().expect("tempdir");
	journal(dir.path(), "remote.example", &[FAILED]);
	let dns = dns(&[(
		"remote.example",
		"v=TLSRPTv1; rua=mailto:tlsrpt@remote.example",
	)]);
	let sink = MemorySink::new();
	let sender = Sender {
		data_dir: dir.path(),
		hostname: "mail.sender.example",
		dns: &dns,
		sink: &sink,
		poster: &Poster::default(),
		auto_submitted: true,
	};
	send_pending(&sender, "20240101").await;
	assert_eq!(sink.messages().len(), 0);
}
