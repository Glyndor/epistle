//! RFC conformance cases using external vectors from the DKIM/ARC suite.
//! Run: cargo test --locked --test dkim_rfc_conformance

use epistle::arc::chain::{ChainError, ChainValidation};
use epistle::arc::{ams, chain, signature, validate};
use epistle::dkim::DkimOutcome::{Pass, PermError};
use epistle::dkim::{DkimOutcome, DkimResult, verify_message};
use epistle::spf::{DnsFailure, DnsLookup};
use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

// Exact wire bytes from test/hostile-dkim-arc-2; kept here so that suite
// can merge independently without adding its other cases to this target.
const ARC_AMS_SIMPLE_FOLDED: &str = concat!(
	"ARC-Seal: i=1; a=ed25519-sha256; d=example.test; s=seal; cv=none; b=bvUgK4xuTAuOSXPTxGVNFt9eIcpnNCyUQMfjo5sYsFxOI8hJ2RekNu5bDdhp7Wi8HAQOMXLMeMFaZaCyq5+BAg==\r\n",
	"ARC-Message-Signature: i=1; a=ed25519-sha256; c=simple/relaxed; d=example.test; s=ams; h=from:to:subject:from:subject; bh=VwbiVmSrr0pBRHQSPGZMHw50LJ8kfwr6TdTJgJSvhBY=; b=xrrAVCD58TgxnkppbSe8iHDsHQ6oo97HrVogtmCmmOtCP3wF9yUwWBRkwhiOqtPvEwHZ3WfFWjqt/y3oZHC0Cw==\r\n",
	"ARC-Authentication-Results: i=1; mx.example.test; dkim=pass header.d=example.test\r\n",
	"FrOm: Alice <alice@example.test>\r\n",
	"To: Bob <bob@example.net>\r\n",
	"SuBJeCt:  external\tvector\r\n",
	"\t folded  \r\n",
	"\r\n",
	"\t  indented\ttext \t\r\n",
	"\r\n",
	"line\t\t two\r\n",
	" \t\r\n",
	"\r\n",
);

const ARC_ED_1: &str = concat!(
	"ARC-Seal: i=1; a=ed25519-sha256; d=example.test; s=seal; cv=none; b=Myuo4T6C8XJVUlS2xzaH3MgHsQVVHRmEsgbLOf4KMC2XxSmj/gFB2L/0uupKX3oFE/TnftVzfTbnbUZVASw4AA==\r\n",
	"ARC-Message-Signature: i=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.test; s=ams; h=from:to:subject:from:subject; bh=VwbiVmSrr0pBRHQSPGZMHw50LJ8kfwr6TdTJgJSvhBY=; b=eq7djESs7BUChad+ClS6nrszoS/URuexXKxO0SG8H+jPDhJwXuuv830dmuTsWZwxe8E0aUoPsZK7Q4T6dvCzAQ==\r\n",
	"ARC-Authentication-Results: i=1; mx.example.test; dkim=pass header.d=example.test\r\n",
	"FrOm: Alice <alice@example.test>\r\n",
	"To: Bob <bob@example.net>\r\n",
	"SuBJeCt:  external\tvector\r\n",
	"\t folded  \r\n",
	"\r\n",
	"\t  indented\ttext \t\r\n",
	"\r\n",
	"line\t\t two\r\n",
	" \t\r\n",
	"\r\n",
);

const RFC6376_SIMPLE: &str = concat!(
	"DKIM-Signature: v=1; a=ed25519-sha256; c=simple/simple; d=example.test; s=external; h=from:a:b; bh=NOeivbQlDH9TmNKJUw7D53wZfsk8YMZ/hTuVVwTgi8s=; b=cwelnF3TuXqvLDYbRwPA+W5yo0GPHDfVE14uDx4O7pPMaTeQLQkpzmdvCVQa86UHAfIeJEyJ+b6SYibLofwJDA==\r\n",
	"From: alice@example.test\r\n",
	"A: X\r\n",
	"B : Y \t\r\n",
	"\t Z  \r\n",
	"\r\n",
	" C \r\n",
	"D \t E\r\n",
	"\r\n",
	"\r\n",
);

const SINGLE_FROM: &str = concat!(
	"DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.test; s=external; h=from:to:subject; bh=VwbiVmSrr0pBRHQSPGZMHw50LJ8kfwr6TdTJgJSvhBY=; b=SNwBXz4dbK17QK4EFmPg9cNx3WPuTc0z88z87z8Uff5rZ416esHJqxj/lQ3Y7f0dLbNf64DcwUVvt1Gx/+49Dg==\r\n",
	"FrOm: Alice <alice@example.test>\r\n",
	"To: Bob <bob@example.net>\r\n",
	"SuBJeCt:  external\tvector\r\n",
	"\t folded  \r\n",
	"\r\n",
	"\t  indented\ttext \t\r\n",
	"\r\n",
	"line\t\t two\r\n",
	" \t\r\n",
	"\r\n",
);

const KEY_RECORD: &str = "v=DKIM1; k=ed25519; p=3Bmop+ymZ0z/KKff4JzdyvLFAGeLCUOvVvc/fOWX5Vw=";

// Minimal DNS and deadline adapters from the DKIM/ARC harness.
struct Dns {
	records: HashMap<String, Vec<String>>,
	calls: AtomicUsize,
}

impl Dns {
	fn one(owner: &str, value: &str) -> Self {
		Self {
			records: HashMap::from([(owner.to_string(), vec![value.to_string()])]),
			calls: AtomicUsize::new(0),
		}
	}
}

impl DnsLookup for Dns {
	fn txt(
		&self,
		name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		self.calls.fetch_add(1, Ordering::SeqCst);
		let result = self.records.get(name).cloned().unwrap_or_default();
		Box::pin(async move { Ok(result) })
	}

	fn addresses(
		&self,
		_: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, DnsFailure>> + Send + '_>> {
		panic!("DKIM/ARC must only query TXT")
	}

	fn mx(
		&self,
		_: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		panic!("DKIM/ARC must only query TXT")
	}
}

fn bounded<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
	let (send, recv) = std::sync::mpsc::sync_channel(1);
	std::thread::spawn(move || {
		let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work));
		let _ = send.send(result);
	});
	match recv
		.recv_timeout(Duration::from_secs(15))
		.expect("verification exceeded 15s wall deadline")
	{
		Ok(result) => result,
		Err(panic) => std::panic::resume_unwind(panic),
	}
}

fn expect_dkim(raw: Vec<u8>, dns: Dns, outcome: DkimOutcome, domain: Option<&str>, queries: usize) {
	let (results, calls) = bounded(move || {
		let results = run(verify_message(&dns, &raw));
		(results, dns.calls.load(Ordering::SeqCst))
	});
	assert_eq!(
		results,
		vec![DkimResult {
			outcome,
			domain: domain.map(str::to_string)
		}]
	);
	assert_eq!(calls, queries, "wrong rejection stage");
}

fn replace(raw: &[u8], old: &str, new: &str) -> Vec<u8> {
	let raw = std::str::from_utf8(raw).expect("ASCII message");
	assert!(raw.contains(old), "replacement did not match");
	raw.replacen(old, new, 1).into_bytes()
}

fn message(name: &str) -> Vec<u8> {
	match name {
		"arc-ams-simple-folded" => ARC_AMS_SIMPLE_FOLDED,
		"arc-ed-1" => ARC_ED_1,
		"rfc6376-simple" => RFC6376_SIMPLE,
		"single-from" => SINGLE_FROM,
		_ => panic!("unknown vector"),
	}
	.as_bytes()
	.to_vec()
}

fn dkim_dns() -> Dns {
	Dns::one("external._domainkey.example.test", KEY_RECORD)
}

fn arc_dns() -> Dns {
	let mut dns = Dns::one("ams._domainkey.example.test", KEY_RECORD);
	dns.records.insert(
		"seal._domainkey.example.test".into(),
		vec![KEY_RECORD.into()],
	);
	dns
}

fn run<F: Future>(future: F) -> F::Output {
	tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.expect("runtime")
		.block_on(future)
}

fn ams_result(raw: Vec<u8>, dns: Dns) -> (epistle::dkim::DkimOutcome, usize) {
	bounded(move || {
		let instances = chain::extract(&raw)
			.expect("structural chain")
			.expect("ARC present");
		let newest = instances.last().expect("instance");
		let parsed =
			signature::parse_message_signature(&newest.message_signature).expect("AMS parses");
		let result = run(ams::verify(&dns, &parsed, &newest.message_signature, &raw));
		(result, dns.calls.load(Ordering::SeqCst))
	})
}

fn malformed(raw: Vec<u8>, expected: ChainError) {
	let inspected = raw.clone();
	assert_eq!(bounded(move || chain::extract(&inspected)), Err(expected));
	assert_eq!(
		bounded(move || {
			let dns = arc_dns();
			let result = run(validate::validate(&dns, &raw));
			(result, dns.calls.load(Ordering::SeqCst))
		}),
		(ChainValidation::Fail, 0)
	);
}

#[test]
fn simple_ams_preserves_folded_header_bytes() {
	assert_eq!(
		ams_result(message("arc-ams-simple-folded"), arc_dns()),
		(Pass, 1)
	);
	assert_eq!(ams_result(message("arc-ed-1"), arc_dns()), (Pass, 1));
}

#[test]
fn zero_instance_mixed_with_valid_instance_is_rejected_without_panic() {
	let raw = replace(&message("arc-ed-1"), "i=1;", "i=0;");
	malformed(raw, ChainError::BadInstance);
	let raw = ARC_ED_1.replace("i=1;", "i=2;").into_bytes();
	malformed(raw, ChainError::NonContiguous);
}

#[test]
fn rfc6376_simple_example() {
	expect_dkim(
		message("rfc6376-simple"),
		dkim_dns(),
		Pass,
		Some("example.test"),
		1,
	);
}

#[test]
fn duplicate_from_without_oversigning_is_rejected() {
	let mut raw = b"From: attacker@evil.test\r\n".to_vec();
	raw.extend_from_slice(&message("single-from"));
	expect_dkim(raw, dkim_dns(), PermError, Some("example.test"), 0);
}
