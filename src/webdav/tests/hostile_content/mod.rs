//! Stored-content attacks for #1606, separate from hostile REPORT XML.

mod calendar;
mod card;
mod reports;

mod selector_overflow;

use crate::webdav::caldav_filter::{self, CalendarQueryFilter};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const MIB: usize = 1024 * 1024;

/// A process deadline also bounds synchronous parsers: Tokio's timeout cannot
/// interrupt a comparator that never yields. Never leave a runaway worker.
fn isolated(name: &str, work: impl FnOnce()) {
	isolated_with_deadline(name, Duration::from_secs(10), work);
}

// HTTP fixtures include credential hashing and async filesystem work. Their
// outer deadline allows setup under suite-wide load; comparator limits stay strict.
fn isolated_with_deadline(name: &str, deadline: Duration, work: impl FnOnce()) {
	if std::env::var("EPISTLE_CONTENT_CASE").as_deref() == Ok(name) {
		work();
		return;
	}
	let full = format!("webdav::tests::hostile_content::{name}");
	let log = tempfile::tempfile().expect("worker log");
	let mut child = Command::new(std::env::current_exe().expect("test executable"))
		.args(["--exact", &full, "--nocapture"])
		.env("EPISTLE_CONTENT_CASE", name)
		.stdout(Stdio::from(log.try_clone().expect("log clone")))
		.stderr(Stdio::from(log.try_clone().expect("log clone")))
		.spawn()
		.expect("worker");
	let started = Instant::now();
	let status = loop {
		if let Some(status) = child.try_wait().expect("worker status") {
			break Some(status);
		}
		if started.elapsed() > deadline {
			if let Ok(memory) = std::fs::read_to_string(format!("/proc/{}/status", child.id())) {
				for line in memory.lines().filter(|line| line.starts_with("VmHWM:")) {
					eprintln!("stalled worker {line}");
				}
			}
			child.kill().expect("kill stalled parser");
			child.wait().expect("reap stalled parser");
			break None;
		}
		std::thread::sleep(Duration::from_millis(20));
	};
	use std::io::{Read, Seek};
	let mut log = log;
	log.rewind().expect("rewind log");
	let mut output = String::new();
	log.read_to_string(&mut output).expect("read worker log");
	assert!(
		status.is_some_and(|s| s.success()) && output.contains("1 passed"),
		"{name}: {status:?}\n{output}"
	);
	print!("{output}");
}

fn calendar(events: &str) -> String {
	let text = format!("BEGIN:VCALENDAR\r\nVERSION:2.0\r\n{events}END:VCALENDAR\r\n");
	assert!(text.len() as u64 <= crate::webdav::report_bounds::MAX_RESOURCE_BYTES);
	text
}

fn event(rule: &str, extra: &str) -> String {
	format!("BEGIN:VEVENT\r\nDTSTART:20260101T000000Z\r\nRRULE:{rule}\r\n{extra}END:VEVENT\r\n")
}

fn query(from: &str, to: &str, extra: &str) -> String {
	format!(
		"<C:calendar-query xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\
		<D:prop><D:getetag/></D:prop><C:filter><C:comp-filter name=\"VCALENDAR\">\
		<C:comp-filter name=\"VEVENT\"><C:time-range start=\"{from}\" end=\"{to}\"/>\
		{extra}</C:comp-filter></C:comp-filter></C:filter></C:calendar-query>"
	)
}

fn filter(from: &str, to: &str, extra: &str) -> CalendarQueryFilter {
	caldav_filter::parse(&query(from, to, extra)).expect("supported filter")
}

fn measured<T>(work: impl FnOnce() -> T) -> T {
	let start = Instant::now();
	let (result, peak) = crate::sieve::test_peak_bytes(work);
	eprintln!("peak={peak} bytes elapsed={:?}", start.elapsed());
	assert!(peak < 64 * MIB, "comparator reserved {peak} bytes");
	assert!(
		start.elapsed() < Duration::from_secs(8),
		"comparator exceeded 8 seconds"
	);
	result
}
