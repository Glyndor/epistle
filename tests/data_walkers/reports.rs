use super::*;

#[test]
fn reports_skip_non_regular_jsonl_paths() {
	let root = tempfile::tempdir().unwrap();
	let data = root.path().join("data");
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap()
		.as_secs();
	let today = epistle::dmarc::aggregate::unix_to_day(now);
	let day_dir = data.join("reports/dmarc").join(today);
	std::fs::create_dir_all(&day_dir).unwrap();
	let outside = root.path().join("outside");
	std::fs::write(&outside, "{}\n").unwrap();
	let mut skipped = Vec::new();
	for kind in ["socket", "fifo", "symlink"] {
		let path = day_dir.join(format!("{kind}.jsonl"));
		special(&path, kind, &outside);
		skipped.push(path);
	}
	let config = config(root.path(), &data);
	let output = run(&["reports", "--config", config.to_str().unwrap()]);
	assert_eq!(output.as_ref().map(|out| String::from_utf8_lossy(&out.stdout).into_owned()),
        Some("DMARC aggregate reports (0 ingested):\n  (no reports yet)\nTLS-RPT reports (0 ingested):\n  (no reports yet)\n".to_string()),
        "report summaries must count zero records from non-regular paths");
	let output = output.unwrap();
	assert_eq!(
		output.status.code(),
		Some(0),
		"report summaries must succeed with special files present"
	);
	for path in skipped {
		assert_warning_once(&output, &path);
	}
}
