use super::*;

fn log_len(dir: &Path) -> u64 {
	std::fs::metadata(state_file(dir, StateFile::Vanished).unwrap())
		.unwrap()
		.len()
}

#[test]
fn an_append_past_the_cap_drops_the_oldest_entries() {
	let dir = tempfile::tempdir().expect("tempdir");
	let uids: Vec<u32> = (1..=700_000).collect();
	record(dir.path(), &uids, 5).expect("record");
	assert!(
		log_len(dir.path()) <= MAX_LOG_OCTETS,
		"the log must be trimmed to the cap, it holds {} octets",
		log_len(dir.path())
	);
	record(dir.path(), &[700_001], 6).expect("record");
	let kept = since(dir.path(), 0);
	assert_eq!(kept.last(), Some(&700_001), "the newest entry is kept");
	assert!(kept.len() < 700_000, "the oldest entries are dropped");
	assert!(!kept.contains(&1), "the oldest entry is gone");
	assert_eq!(since(dir.path(), 5), vec![700_001]);
}

#[test]
fn a_read_looks_only_at_the_end_of_an_oversized_log() {
	let dir = tempfile::tempdir().expect("tempdir");
	// A log that grew before the cap existed.
	let mut text = String::new();
	for uid in 1..=800_000u32 {
		text.push_str(&format!("{uid} 3\n"));
	}
	std::fs::write(state_file(dir.path(), StateFile::Vanished).unwrap(), &text).unwrap();
	assert!(log_len(dir.path()) > MAX_LOG_OCTETS);
	let seen = since(dir.path(), 0);
	assert_eq!(seen.last(), Some(&800_000));
	assert!(
		(seen.len() as u64) * 8 < MAX_LOG_OCTETS,
		"a read must not parse more than the cap: {} entries",
		seen.len()
	);
	assert!(!seen.contains(&1), "a cut first line must not be parsed");
}
