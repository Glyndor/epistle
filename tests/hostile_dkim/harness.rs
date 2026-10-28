//! No network DNS and a wall-clock deadline independent of executor progress.

use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use epistle::dkim::{DkimOutcome, DkimResult, verify_message};
use epistle::spf::{DnsFailure, DnsLookup};

pub fn path(name: &str) -> PathBuf {
	PathBuf::from(env!("CARGO_MANIFEST_DIR"))
		.join("tests/fixtures/dkim")
		.join(name)
}

pub fn bytes(name: &str) -> Vec<u8> {
	std::fs::read(path(name)).expect("external fixture")
}

pub fn text(name: &str) -> String {
	String::from_utf8(bytes(name)).expect("ASCII fixture")
}

pub fn message(name: &str) -> Vec<u8> {
	bytes(&format!("{name}.eml"))
}

pub fn record(name: &str) -> String {
	text(&format!("{name}.dns")).trim().to_string()
}

pub struct Dns {
	pub records: HashMap<String, Vec<String>>,
	pub calls: AtomicUsize,
	pub temporary: bool,
}

impl Dns {
	pub fn one(owner: &str, value: &str) -> Self {
		Self {
			records: HashMap::from([(owner.to_string(), vec![value.to_string()])]),
			calls: AtomicUsize::new(0),
			temporary: false,
		}
	}

	pub fn dkim(name: &str) -> Self {
		Self::one("external._domainkey.example.test", &record(name))
	}
}

impl DnsLookup for Dns {
	fn txt(
		&self,
		name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		self.calls.fetch_add(1, Ordering::SeqCst);
		let result = if self.temporary {
			Err(DnsFailure::Temporary)
		} else {
			Ok(self.records.get(name).cloned().unwrap_or_default())
		};
		Box::pin(async move { result })
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

/// A stuck synchronous verifier cannot prevent this receiver from timing out.
/// On timeout its worker remains detached until the test process exits.
pub fn bounded<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
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

fn run<F: Future>(future: F) -> F::Output {
	tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.expect("runtime")
		.block_on(future)
}

pub fn dkim(raw: Vec<u8>, dns: Dns) -> (Vec<DkimResult>, usize) {
	bounded(move || {
		let results = run(verify_message(&dns, &raw));
		(results, dns.calls.load(Ordering::SeqCst))
	})
}

pub fn expect_dkim(
	raw: Vec<u8>,
	dns: Dns,
	outcome: DkimOutcome,
	domain: Option<&str>,
	queries: usize,
) {
	let (results, calls) = dkim(raw, dns);
	assert_eq!(
		results,
		vec![DkimResult {
			outcome,
			domain: domain.map(str::to_string)
		}]
	);
	assert_eq!(calls, queries, "wrong rejection stage");
}

pub fn case(name: &str, outcome: DkimOutcome, queries: usize) {
	expect_dkim(
		message(name),
		Dns::dkim(name),
		outcome,
		Some("example.test"),
		queries,
	);
}
