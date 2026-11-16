//! Helpers of the `deliverability` tests: a check run over a data directory
//! whose delivery log holds mail answered by the given exchangers.

use std::path::Path;

use crate::cli::status::report::AreaReport;
use crate::cli::status::test_support::ctx;
use crate::storage::DeliveryLog;
use crate::storage::delivery_log::{DeliveryOutcome, DeliveryRecord};

/// One exchanger of each provider that has a sender panel.
pub(super) const EVERY_PROVIDER: [&str; 4] = [
	"gmail-smtp-in.l.google.com",
	"outlook-com.olc.protection.outlook.com",
	"mta5.am0.yahoodns.net",
	"mx01.mail.icloud.com",
];

/// Append one delivered record answered by `host` to the log under `data`.
pub(super) fn deliver(data: &Path, host: &str) {
	let record = DeliveryRecord {
		time: std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map_or(0, |elapsed| elapsed.as_secs()),
		spool_id: uuid::Uuid::new_v4(),
		account: None,
		from: "alice@example.org".to_string(),
		recipient: "bob@example.net".to_string(),
		outcome: DeliveryOutcome::Delivered,
		remote: Some(host.to_string()),
		reply: None,
		attempt: 1,
		extra: Default::default(),
		class: Default::default(),
	};
	DeliveryLog::open(data, 30).append(&record).expect("append");
}

/// The check over a configuration with `extra` appended, after mail was
/// delivered through each of `hosts`.
pub(super) fn report_after(extra: &str, hosts: &[&str]) -> AreaReport {
	let dir = tempfile::tempdir().expect("tempdir");
	let ctx = ctx(dir.path(), extra);
	for host in hosts {
		deliver(&dir.path().join("data"), host);
	}
	tokio::runtime::Runtime::new()
		.expect("runtime")
		.block_on(super::super::check(&ctx))
}
