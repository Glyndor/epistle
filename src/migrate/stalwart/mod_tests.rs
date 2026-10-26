use super::*;
use crate::migrate::import::Algorithm;

#[test]
fn reads_the_memory_directory_and_signatures() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (file, _) = fixture::write(dir.path());
	let plan = read(&file).expect("plan");
	assert_eq!(plan.domains, ["example.org"]);
	let john = plan
		.accounts
		.iter()
		.find(|a| a.name == "john")
		.expect("john");
	assert_eq!(john.addresses, ["john@example.org", "j.doe@example.org"]);
	assert_eq!(john.display_name.as_deref(), Some("John Doe"));
	let jane = plan
		.accounts
		.iter()
		.find(|a| a.name == "jane")
		.expect("jane");
	assert_eq!(jane.catch_all, ["example.org"]);
	assert!(
		plan.manual
			.iter()
			.any(|m| m.contains("jane") && m.contains("administrator"))
	);
	assert!(plan.skipped.iter().any(|n| n.item == "account nobody"));
	let alias = |address: &str| {
		plan.aliases
			.iter()
			.find(|a| a.address == address)
			.expect(address)
	};
	assert_eq!(
		alias("sales@example.org").members,
		["john@example.org", "jane@example.org"]
	);
	assert_eq!(alias("support@example.org").members, ["john@example.org"]);
	let mut keys: Vec<(&str, Algorithm)> = plan
		.keys
		.iter()
		.map(|k| (k.selector.as_str(), k.algorithm))
		.collect();
	keys.sort_by_key(|k| k.0);
	assert_eq!(
		keys,
		[("202401e", Algorithm::Ed25519), ("202401r", Algorithm::Rsa)]
	);
	assert!(
		plan.skipped
			.iter()
			.any(|n| n.item.contains("from-env") && n.reason.contains("environment"))
	);
}

#[test]
fn another_directory_type_points_at_the_manual_route() {
	let dir = tempfile::tempdir().expect("tempdir");
	let file = fixture::write_internal(dir.path());
	let plan = read(&file).expect("plan");
	assert!(plan.accounts.is_empty());
	assert!(plan.aliases.is_empty());
	assert_eq!(plan.keys.len(), 2, "the signatures still come over");
	assert!(
		plan.manual
			.iter()
			.any(|m| m.contains("internal") && m.contains("epistle migrate imap")),
		"{:?}",
		plan.manual
	);
}

#[test]
fn a_016_bootstrap_file_is_refused_with_directions() {
	let dir = tempfile::tempdir().expect("tempdir");
	let file = dir.path().join("config.json");
	std::fs::write(&file, r#"{"@type":"RocksDb","path":"/var/lib/stalwart/"}"#).expect("write");
	let error = read(&file).expect_err("refused");
	assert!(matches!(error, ReadError::Database(_)));
	assert!(error.to_string().contains("migrate imap"));
}

#[test]
fn keys_and_secrets_never_appear_in_the_plan_output() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (file, written) = fixture::write(dir.path());
	let plan = read(&file).expect("plan");
	let shown = format!("{plan:?}\n{}", serde_json::to_string(&plan).expect("json"));
	for pem in [&written.rsa, &written.ed25519] {
		let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
		assert!(!shown.contains(&body[..40]));
	}
	assert!(!shown.contains("PRIVATE KEY"));
	assert!(!shown.contains("changeme-not-a-real-one"));
	assert!(!shown.contains("$6$"));
	assert!(
		plan.manual
			.iter()
			.chain(plan.skipped.iter().map(|n| &n.reason))
			.all(|line| !line.chars().any(char::is_control)),
		"output lines carry no tabs or control characters"
	);
}

#[test]
fn not_toml_is_an_error() {
	let dir = tempfile::tempdir().expect("tempdir");
	let file = dir.path().join("config.toml");
	std::fs::write(&file, "[unclosed").expect("write");
	assert!(matches!(read(&file), Err(ReadError::Parse(..))));
}

#[cfg(unix)]
#[test]
fn a_fifo_key_is_rejected_without_waiting_for_a_writer() {
	use std::os::unix::fs::OpenOptionsExt;
	use std::sync::mpsc;
	use std::time::Duration;
	let dir = tempfile::tempdir().expect("dir");
	let fifo = dir.path().join("key.pem");
	assert!(
		std::process::Command::new("mkfifo")
			.arg(&fifo)
			.status()
			.expect("mkfifo")
			.success()
	);
	let (send, receive) = mpsc::channel();
	let path = dir.path().to_path_buf();
	let worker = std::thread::spawn(move || {
		let result = private_key("%{file:key.pem}%", &path);
		send.send(result.map(|_| ())).expect("result");
	});
	let result = receive.recv_timeout(Duration::from_secs(1));
	// Release an old blocking reader before checking the result.
	let writer = std::fs::OpenOptions::new()
		.write(true)
		.custom_flags(libc::O_NONBLOCK)
		.open(&fifo);
	drop(writer);
	worker.join().expect("reader");
	assert!(
		matches!(result, Ok(Err(_))),
		"a special file must fail before waiting for data"
	);
}
