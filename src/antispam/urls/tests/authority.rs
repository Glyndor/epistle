use super::*;

#[test]
fn url_screen_normalizes_authority_spellings() {
	for spelling in [
		"HTTP://blocked.example/",
		"hTtPs://blocked.example/",
		"http://innocent.example@blocked.example/",
		"http://user:password@blocked.example:8080/",
		"http://user;name:pass,word@blocked.example/",
		"http://user(name)@blocked.example/",
		"http://o'connor@blocked.example/",
		"http://%62locked.example/",
		"http://blocked%2eexample/",
	] {
		assert_eq!(
			extract_hosts(spelling.as_bytes(), DEFAULT_HOST_CAP),
			vec!["blocked.example"],
			"URL screening must return the normalized authority host"
		);
	}
}

#[test]
fn url_screen_normalizes_unicode_and_percent_encoded_idna() {
	for spelling in [
		"http://bücher.example/",
		"http://b%C3%BCcher.example/",
		"http://xn--bcher-kva.example/",
	] {
		assert_eq!(
			extract_hosts(spelling.as_bytes(), DEFAULT_HOST_CAP),
			vec!["xn--bcher-kva.example"],
			"equivalent IDNA hosts must share one DNSBL lookup"
		);
	}
	let body = "http://bücher.example/ http://b%C3%BCcher.example/ http://xn--bcher-kva.example/";
	assert_eq!(
		extract_hosts(body.as_bytes(), DEFAULT_HOST_CAP),
		vec!["xn--bcher-kva.example"],
		"equivalent IDNA hosts must share one DNSBL lookup"
	);
}

#[test]
fn url_screen_rejects_malformed_authorities_without_partial_hosts() {
	let body = b"http://blocked.example%zz/ http://blocked.example%2f.evil/ http://[::1]/ http://127.1/ http://real.example/";
	assert_eq!(
		extract_hosts(body, DEFAULT_HOST_CAP),
		vec!["real.example"],
		"invalid authorities and IP literals must not yield partial DNSBL hosts"
	);
}

#[test]
fn url_screen_preserves_hosts_next_to_prose_punctuation() {
	let body = b"(http://blocked.example). http://blocked.example', http://blocked.example;";
	assert_eq!(
		extract_hosts(body, DEFAULT_HOST_CAP),
		vec!["blocked.example"],
		"prose punctuation must not become part of the DNSBL host"
	);
}
