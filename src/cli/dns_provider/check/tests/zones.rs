//! `dns provider check` with one credential per zone: every entry is
//! reported, each with the names of its own zone.

use std::sync::{Arc, Mutex};

use super::*;
use crate::config::Config;
use crate::dns::provider::{DnsProvider, DnsRecord, ListOp, Op};
use crate::dns::providers::check::{AccessReport, CheckOp, Finding};

type Calls = Arc<Mutex<Vec<(String, Vec<String>)>>>;

struct Recording(Calls);

impl DnsProvider for Recording {
	fn check_access<'a>(&'a self, zone: &'a str, names: &'a [String]) -> CheckOp<'a> {
		self.0
			.lock()
			.unwrap()
			.push((zone.to_string(), names.to_vec()));
		Box::pin(async {
			let mut report = AccessReport::unknown();
			report.record_read = Finding::verified("readable");
			report
		})
	}
	fn upsert(&self, _: &str, _: DnsRecord) -> Op<'_> {
		panic!("inspection must never write records")
	}
	fn delete(&self, _: &str, _: DnsRecord) -> Op<'_> {
		panic!("inspection must never delete records")
	}
	fn list(&self, _: &str) -> ListOp<'_> {
		panic!("the check asks check_access, not list")
	}
}

fn two_zones() -> Config {
	toml::from_str(
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n\
		 domains = [\"example.org\", \"example.net\"]\n\
		 [[dns]]\nprovider = \"cloudflare\"\nzone = \"example.org\"\n\
		 [[dns]]\nprovider = \"desec\"\nzone = \"example.net\"\n",
	)
	.expect("parses")
}

#[test]
fn every_entry_is_checked_with_the_names_of_its_own_zone() {
	let calls = Calls::default();
	let mut out = Vec::new();
	run_with(&two_zones(), true, &mut out, |_, _| {
		Some(Arc::new(Recording(calls.clone())) as Arc<dyn DnsProvider>)
	})
	.unwrap();
	let calls = calls.lock().unwrap().clone();
	assert_eq!(calls.len(), 2);
	for (zone, names) in &calls {
		assert!(!names.is_empty());
		for name in names {
			assert!(
				name == zone || name.ends_with(&format!(".{zone}")),
				"{name} was checked with the credential of {zone}"
			);
		}
	}
	let printed: serde_json::Value = serde_json::from_slice(&out).unwrap();
	let zones: Vec<&str> = printed
		.as_array()
		.expect("several entries print a list")
		.iter()
		.map(|entry| entry["zone"].as_str().unwrap())
		.collect();
	assert_eq!(zones, vec!["example.org", "example.net"]);
}

#[test]
fn one_credential_that_cannot_be_read_does_not_hide_the_others() {
	let calls = Calls::default();
	let mut out = Vec::new();
	run_with(&two_zones(), true, &mut out, |dns, _| {
		(dns.zone == "example.org")
			.then(|| Arc::new(Recording(calls.clone())) as Arc<dyn DnsProvider>)
	})
	.unwrap();
	let printed: serde_json::Value = serde_json::from_slice(&out).unwrap();
	let report = |index: usize| &printed[index]["report"];
	assert_eq!(report(0)["record_read"]["status"], "verified");
	assert_eq!(report(1)["token_status"]["status"], "failure");
	assert_eq!(calls.lock().unwrap().len(), 1);
}

#[test]
fn text_lines_start_with_the_zone() {
	let mut out = Vec::new();
	run_with(&two_zones(), false, &mut out, |_, _| {
		Some(Arc::new(Recording(Calls::default())) as Arc<dyn DnsProvider>)
	})
	.unwrap();
	let text = String::from_utf8(out).unwrap();
	assert!(
		text.lines()
			.all(|line| line.starts_with("example.org\t") || line.starts_with("example.net\t")),
		"{text}"
	);
	assert!(text.contains("example.net\trecord_read\tverified"));
}
