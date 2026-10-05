use super::SubjectPass;

fn pass() -> SubjectPass {
	let generated = uuid::Uuid::now_v7().simple().to_string();
	SubjectPass::with_key(generated.as_bytes().try_into().unwrap())
}

#[test]
fn expired_tokens_never_revive_after_day_cycles() {
	let pass = pass();
	let sender = "alice@example.org";
	let recipient = "bob@example.org";
	let token = pass.issue(sender, recipient, 20_000);
	assert!(pass.verify(&token, sender, recipient, 20_000));
	assert!(pass.verify(&token, sender, recipient, 20_001));
	for day in [20_002, 21_024, 21_025, 22_048, 22_049] {
		assert!(
			!pass.verify(&token, sender, recipient, day),
			"expired token accepted on day {day}"
		);
	}
}

#[test]
fn punctuation_delimits_subject_tokens() {
	let pass = pass();
	let sender = "alice@example.org";
	let recipient = "bob@example.org";
	let token = pass.issue(sender, recipient, 20_000).to_ascii_lowercase();
	for (index, subject) in [
		format!("Re: hello [{token}]"),
		format!("hello ({token})"),
		format!("hello {token}!"),
		format!("Résumé: [{token}]"),
		format!("hello -{token}-"),
	]
	.iter()
	.enumerate()
	{
		assert!(
			pass.accepts(Some(subject), sender, recipient, 20_000),
			"punctuated token rejected in case {index}"
		);
	}
	for subject in [format!("A{token}"), format!("{token}2")] {
		assert!(
			!pass.accepts(Some(&subject), sender, recipient, 20_000),
			"token embedded in base32 text accepted"
		);
	}
}
