//! `epistle verify --json`: the count of accounts and messages and the
//! problems found, with exit 1 when there is one.

use serde_json::json;

use crate::harness::{add_account, env, epistle, json};

const GOOD: &[u8] = b"Subject: hi\r\n\r\nbody\r\n";
const BAD: &[u8] = b"no header body separator here";
const GOOD_ID: &str = "11111111-2222-4333-8444-555555555555";
const BAD_ID: &str = "66666666-7777-4888-8999-aaaaaaaaaaaa";

#[test]
fn verify_lists_the_problems_it_found_and_exits_1() {
	let env = env("");
	add_account(&env, "bob");
	let inbox = env.data_dir().join("accounts/bob/new");
	std::fs::create_dir_all(&inbox).expect("inbox");
	std::fs::write(inbox.join(format!("{GOOD_ID}.eml")), GOOD).expect("good message");
	std::fs::write(inbox.join(format!("{BAD_ID}.eml")), BAD).expect("bad message");
	let (code, report) = json(&epistle(
		&["verify", "--config", &env.config, "--json"],
		b"",
	));
	assert_eq!(code, 1);
	assert_eq!(
		report,
		json!({
			"accounts": 1, "messages": 2,
			"problems": [format!("bob/INBOX/{BAD_ID}.eml: no header/body separator")],
		})
	);
}

#[test]
fn verify_of_a_sound_store_exits_0() {
	let env = env("");
	add_account(&env, "bob");
	let inbox = env.data_dir().join("accounts/bob/new");
	std::fs::create_dir_all(&inbox).expect("inbox");
	std::fs::write(inbox.join(format!("{GOOD_ID}.eml")), GOOD).expect("good message");
	assert_eq!(
		json(&epistle(
			&["verify", "--config", &env.config, "--json"],
			b""
		)),
		(0, json!({"accounts": 1, "messages": 1, "problems": []}))
	);
}
