//! `[queue] dmarc_reports = false` writes no journal and starts no sender.

use std::sync::Arc;

use super::base::parse;
use super::{dmarc_journal_dir, spawn_dmarc_flush};
use crate::smtp::sink::{MemorySink, MessageSink};

fn config(data_dir: &std::path::Path, queue: &str) -> crate::config::Config {
	parse(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\n[queue]\n{queue}",
		data_dir.display().to_string()
	))
}

/// A journal file of a day long past, which a flush pass drops.
fn stale_journal(data_dir: &std::path::Path) -> std::path::PathBuf {
	let day = data_dir.join("dmarc-reports").join("20000101");
	std::fs::create_dir_all(&day).expect("day directory");
	let file = day.join("example.org.jsonl");
	std::fs::write(&file, "{}\n").expect("journal file");
	file
}

fn start(config: &crate::config::Config) {
	spawn_dmarc_flush(
		config,
		Arc::new(crate::dkim::test_support::FailingDns),
		Arc::new(MemorySink::new()) as Arc<dyn MessageSink>,
	)
	.expect("spawn");
}

#[test]
fn the_journal_is_written_only_while_reports_are_on() {
	let dir = std::path::Path::new("/var/lib/mail");
	assert_eq!(
		dmarc_journal_dir(&config(dir, "")).as_deref(),
		Some(dir),
		"on by default"
	);
	assert_eq!(
		dmarc_journal_dir(&config(dir, "dmarc_reports = false")),
		None
	);
}

#[tokio::test]
async fn reports_off_start_no_sender() {
	let dir = tempfile::tempdir().expect("tempdir");
	let journal = stale_journal(dir.path());
	let tasks = tokio::runtime::Handle::current().metrics();
	let before = tasks.num_alive_tasks();
	start(&config(dir.path(), "dmarc_reports = false"));
	for _ in 0..16 {
		tokio::task::yield_now().await;
	}
	assert_eq!(tasks.num_alive_tasks(), before, "no task was spawned");
	assert!(journal.exists(), "no flush pass ran");
}

#[tokio::test]
async fn reports_on_start_the_sender() {
	let dir = tempfile::tempdir().expect("tempdir");
	let journal = stale_journal(dir.path());
	let tasks = tokio::runtime::Handle::current().metrics();
	let before = tasks.num_alive_tasks();
	start(&config(dir.path(), ""));
	assert_eq!(tasks.num_alive_tasks(), before + 1);
	// The first pass runs at once and drops the day that is past its cap.
	for _ in 0..500 {
		if !journal.exists() {
			return;
		}
		tokio::time::sleep(std::time::Duration::from_millis(10)).await;
	}
	panic!("the first flush pass did not run");
}
