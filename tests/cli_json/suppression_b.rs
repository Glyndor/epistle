//! `suppression show`, `export` and `import`, and `add --reason`.

use serde_json::{Value, json};

use crate::harness::{Env, env, epistle, json};

fn run(env: &Env, args: &[&str]) -> (i32, Value) {
	let mut full = vec!["suppression", "--config", &env.config];
	full.extend_from_slice(args);
	full.push("--json");
	json(&epistle(&full, b""))
}

/// Exit code, stdout and stderr of a run without `--json`.
fn plain(env: &Env, args: &[&str]) -> (Option<i32>, String, String) {
	let mut full = vec!["suppression", "--config", &env.config];
	full.extend_from_slice(args);
	let output = epistle(&full, b"");
	(
		output.status.code(),
		String::from_utf8_lossy(&output.stdout).into_owned(),
		String::from_utf8_lossy(&output.stderr).into_owned(),
	)
}

fn write(env: &Env, name: &str, content: &[u8]) -> String {
	let path = env.dir.path().join(name);
	std::fs::write(&path, content).expect("write input");
	path.to_string_lossy().into_owned()
}

fn addresses(env: &Env, account: Option<&str>) -> Vec<String> {
	let mut args = vec!["list"];
	if let Some(account) = account {
		args.extend(["--account", account]);
	}
	let (_, list) = run(env, &args);
	list.as_array()
		.expect("array")
		.iter()
		.map(|row| row["address"].as_str().expect("address").to_string())
		.collect()
}

const STAMP: &str = "2026-01-02T03:04:05Z";

#[test]
fn add_records_the_reason_it_was_given() {
	let env = env("");
	let (code, added) = run(
		&env,
		&["add", "bad@example.net", "--reason", "complaint, ticket 42"],
	);
	assert_eq!(code, 0);
	assert_eq!(added["reason"], "complaint, ticket 42");
	let (_, list) = run(&env, &["list"]);
	assert_eq!(list[0]["reason"], "complaint, ticket 42");
	assert!(list[0]["since"].is_string());
}

#[test]
fn add_refuses_a_reason_that_cannot_be_stored_as_given() {
	let env = env("");
	for (reason, needle) in [
		("line one\nline two".to_string(), "control characters"),
		("\u{1b}[2Jgone".to_string(), "control characters"),
		("x".repeat(513), "at most 512 characters"),
	] {
		let (code, stdout, stderr) = plain(
			&env,
			&["add", "bad@example.net", "--reason", &reason, "--json"],
		);
		assert_eq!((code, stdout.as_str()), (Some(2), ""), "{needle}: {stderr}");
		assert!(stderr.contains(needle), "{stderr}");
	}
	assert!(addresses(&env, None).is_empty(), "a refused add wrote");
}

#[test]
fn add_reports_a_marker_that_could_not_be_written() {
	let env = env("");
	let (code, _) = run(&env, &["add", "bad@example.net"]);
	assert_eq!(code, 0);
	// Turn the marker into a directory: the write can no longer succeed,
	// whoever runs the test.
	let marker = std::fs::read_dir(env.data_dir().join("suppression"))
		.expect("dir")
		.flatten()
		.find(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
		.expect("marker")
		.path();
	std::fs::remove_file(&marker).expect("remove");
	std::fs::create_dir(&marker).expect("block the marker");
	let (code, stdout, stderr) = plain(&env, &["add", "bad@example.net", "--json"]);
	assert_eq!((code, stdout.as_str()), (Some(1), ""), "{stderr}");
	assert!(
		stderr.contains("cannot suppress bad@example.net"),
		"{stderr}"
	);
}

#[test]
fn show_prints_one_entry() {
	let env = env("");
	let file = write(
		&env,
		"in.csv",
		format!("bad@example.net,{STAMP},\"550 5.1.1, no such user\"\n").as_bytes(),
	);
	assert_eq!(run(&env, &["import", &file]).0, 0);
	assert_eq!(
		run(&env, &["show", "BAD@example.net"]),
		(
			0,
			json!({
				"address": "bad@example.net", "account": null, "suppressed": true,
				"since": STAMP, "reason": "550 5.1.1, no such user",
			})
		)
	);
	let (code, stdout, _) = plain(&env, &["show", "bad@example.net"]);
	assert_eq!(code, Some(0));
	assert_eq!(
		stdout,
		format!(
			"address\tbad@example.net\nscope\tglobal\nsince\t{STAMP}\nreason\t550 5.1.1, no such user\n"
		)
	);
}

#[test]
fn show_of_an_address_that_is_not_listed_is_refused() {
	let env = env("");
	let (code, stdout, stderr) = plain(&env, &["show", "nobody@example.net", "--json"]);
	assert_eq!((code, stdout.as_str()), (Some(2), ""));
	assert_eq!(
		stderr.trim_end(),
		"error: nobody@example.net is not suppressed"
	);
	let (code, stdout, stderr) = plain(&env, &["show", "not an address", "--json"]);
	assert_eq!((code, stdout.as_str()), (Some(2), ""));
	assert_eq!(
		stderr.trim_end(),
		"error: cannot show: spaces are not allowed"
	);
}

#[test]
fn show_and_list_escape_what_the_marker_holds() {
	let env = env("");
	assert_eq!(run(&env, &["add", "bad@example.net"]).0, 0);
	let marker = std::fs::read_dir(env.data_dir().join("suppression"))
		.expect("dir")
		.flatten()
		.find(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
		.expect("marker")
		.path();
	std::fs::write(&marker, "bad@example.net\n1767323045\tgone\u{1b}[2Jaway\n").expect("plant");
	for args in [vec!["show", "bad@example.net"], vec!["list"]] {
		let (_, stdout, _) = plain(&env, &args);
		assert!(
			!stdout.contains('\u{1b}'),
			"{args:?} let an escape reach the terminal: {stdout:?}"
		);
		assert!(
			stdout.contains("gone\\u{1b}[2Jaway"),
			"{args:?}: {stdout:?}"
		);
	}
}

#[test]
fn export_writes_csv_that_import_reads_back() {
	let source = env("");
	let file = write(
		&source,
		"in.csv",
		format!(
			"# bounced last week\nb@example.net,{STAMP},\"said \"\"no\"\", twice\"\na@example.net\nc@example.net,,=cmd|' /C calc'!A0\n"
		)
		.as_bytes(),
	);
	let (code, imported) = run(&source, &["import", &file]);
	assert_eq!(code, 0);
	assert_eq!(imported["added"], 3);

	let (code, csv, _) = plain(&source, &["export"]);
	assert_eq!(code, Some(0));
	let lines: Vec<&str> = csv.lines().collect();
	assert_eq!(lines[0], "address,since,reason");
	assert_eq!(
		lines[2],
		format!("b@example.net,{STAMP},\"said \"\"no\"\", twice\"")
	);
	assert!(lines[1].starts_with("a@example.net,2"), "{}", lines[1]);
	assert!(
		lines[3].ends_with(",'=cmd|' /C calc'!A0"),
		"a formula is exported with a leading apostrophe: {}",
		lines[3]
	);
	assert_eq!(lines.len(), 4);

	let target = env("");
	let copy = write(&target, "copy.csv", csv.as_bytes());
	assert_eq!(run(&target, &["import", &copy]).1["added"], 3);
	let (_, mine) = run(&source, &["list"]);
	let (_, theirs) = run(&target, &["list"]);
	assert_eq!(mine, theirs, "the entries differ after a round trip");
}

#[test]
fn export_as_json_is_the_listing() {
	let env = env("");
	let file = write(
		&env,
		"in.csv",
		format!("b@example.net,{STAMP},why\n").as_bytes(),
	);
	run(&env, &["import", &file]);
	assert_eq!(
		run(&env, &["export"]),
		(
			0,
			json!([{"address": "b@example.net", "since": STAMP, "reason": "why"}])
		)
	);
}

#[test]
fn import_counts_what_it_added_and_what_was_there() {
	let env = env("");
	let file = write(
		&env,
		"in.txt",
		b"\xEF\xBB\xBFone@example.net\r\n\r\n# comment\nTWO@example.net\none@example.net\n",
	);
	let (code, first) = run(
		&env,
		&["import", &file, "--reason", "list from the old server"],
	);
	assert_eq!(code, 0);
	assert_eq!(
		first,
		json!({
			"result": "saved", "action": "import", "account": null,
			"added": 2, "already": 0, "duplicates": 1,
		})
	);
	let (_, listed) = run(&env, &["list"]);
	assert_eq!(listed[0]["reason"], "list from the old server");
	let (code, second) = run(&env, &["import", &file]);
	assert_eq!(code, 0);
	assert_eq!(
		second,
		json!({
			"result": "unchanged", "action": "import", "account": null,
			"added": 0, "already": 2, "duplicates": 1,
		})
	);
	let (_, kept) = run(&env, &["list"]);
	assert_eq!(
		kept[0]["reason"], "list from the old server",
		"an entry already there is left alone"
	);
}

#[test]
fn import_into_an_account_list_stays_out_of_the_global_one() {
	let env = env("");
	let file = write(&env, "in.txt", b"one@example.net\n");
	let (code, done) = run(&env, &["import", &file, "--account", "bob"]);
	assert_eq!(
		(code, done["account"].as_str(), done["added"].as_u64()),
		(0, Some("bob"), Some(1))
	);
	assert_eq!(addresses(&env, Some("bob")), vec!["one@example.net"]);
	assert!(addresses(&env, None).is_empty());
	assert_eq!(
		run(&env, &["show", "one@example.net", "--account", "bob"]).0,
		0
	);
	assert_eq!(
		plain(&env, &["show", "one@example.net", "--json"]).0,
		Some(2)
	);
}

#[test]
fn a_dry_run_import_counts_and_writes_nothing() {
	let env = env("");
	let file = write(&env, "in.txt", b"one@example.net\ntwo@example.net\n");
	let (code, plan) = run(&env, &["import", &file, "--dry-run"]);
	assert_eq!(code, 0);
	assert_eq!(
		plan,
		json!({
			"result": "dry-run", "action": "import", "account": null,
			"added": 2, "already": 0, "duplicates": 0,
		})
	);
	assert!(addresses(&env, None).is_empty());
}

#[test]
fn a_bad_line_refuses_the_whole_file() {
	let env = env("");
	let file = write(
		&env,
		"in.csv",
		b"good@example.net\nnot an address\nalso@good.example\nx@y@z\nbad@example.net,yesterday,why\nok@example.net,,\"a\x1b[2Jb\"\n",
	);
	let (code, stdout, stderr) = plain(&env, &["import", &file, "--json"]);
	assert_eq!((code, stdout.as_str()), (Some(2), ""));
	for line in ["line 2:", "line 4:", "line 5:", "line 6:"] {
		assert!(stderr.contains(line), "{line} missing from: {stderr}");
	}
	assert!(
		!stderr.contains("line 1:") && !stderr.contains("line 3:"),
		"{stderr}"
	);
	assert!(
		!stderr.contains('\u{1b}'),
		"an escape reached stderr: {stderr:?}"
	);
	assert!(
		addresses(&env, None).is_empty(),
		"a refused import wrote entries"
	);
}

#[test]
fn a_file_over_the_row_limit_is_refused_before_anything_is_written() {
	let env = env("");
	let mut text = String::new();
	for n in 0..100_001 {
		text.push_str(&format!("u{n}@example.net\n"));
	}
	let file = write(&env, "big.txt", text.as_bytes());
	let (code, stdout, stderr) = plain(&env, &["import", &file, "--json"]);
	assert_eq!((code, stdout.as_str()), (Some(2), ""));
	assert!(stderr.contains("more than 100000 entries"), "{stderr}");
	assert!(addresses(&env, None).is_empty());
}

#[test]
fn a_file_over_the_size_limit_is_refused_without_reading_it_whole() {
	let env = env("");
	let path = env.dir.path().join("huge.txt");
	let file = std::fs::File::create(&path).expect("create");
	file.set_len(16 * 1024 * 1024 + 1).expect("sparse file");
	let (code, stdout, stderr) = plain(&env, &["import", &path.to_string_lossy(), "--json"]);
	assert_eq!((code, stdout.as_str()), (Some(2), ""));
	assert!(stderr.contains("larger than 16 MiB"), "{stderr}");
}

#[test]
fn a_file_that_is_not_a_readable_text_file_is_refused() {
	let env = env("");
	let binary = write(&env, "bin.txt", &[0xff, 0xfe, 0x00, 0x41]);
	let missing = env
		.dir
		.path()
		.join("missing.txt")
		.to_string_lossy()
		.into_owned();
	let directory = env.dir.path().to_string_lossy().into_owned();
	for (path, needle) in [
		(binary, "not UTF-8"),
		(missing, "cannot read"),
		(directory, "is not a regular file"),
	] {
		let (code, stdout, stderr) = plain(&env, &["import", &path, "--json"]);
		assert_eq!((code, stdout.as_str()), (Some(2), ""), "{needle}: {stderr}");
		assert!(stderr.contains(needle), "{needle} missing from: {stderr}");
	}
}
