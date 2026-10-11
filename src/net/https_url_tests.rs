use super::{HttpsUrl, HttpsUrlError};

#[test]
fn parse_refuses_every_scheme_but_https() {
	for text in [
		"http://dns.example/api",
		"ftp://dns.example/",
		"HTTP://dns.example/",
		"ws://dns.example/",
		"file:///etc/passwd",
	] {
		assert_eq!(
			HttpsUrl::parse(text),
			Err(HttpsUrlError::NotHttps),
			"scheme of {text}"
		);
	}
}

#[test]
fn parse_refuses_unusable_urls() {
	assert_eq!(HttpsUrl::parse("not a url"), Err(HttpsUrlError::Invalid));
	assert_eq!(HttpsUrl::parse("https://"), Err(HttpsUrlError::Invalid));
	assert_eq!(
		HttpsUrl::parse("https://user:pw@dns.example/"),
		Err(HttpsUrlError::EmbeddedCredentials)
	);
	assert_eq!(
		HttpsUrl::parse("https://user@dns.example/"),
		Err(HttpsUrlError::EmbeddedCredentials)
	);
}

#[test]
fn parse_accepts_https_and_keeps_the_text() {
	let url = HttpsUrl::parse("https://dns.example/api/v1").expect("https parses");
	assert_eq!(url.as_str(), "https://dns.example/api/v1");
	assert_eq!(url.host_str(), Some("dns.example"));
}

#[test]
fn loopback_http_accepts_only_loopback_hosts() {
	let ok = HttpsUrl::loopback_http("http://127.0.0.1:8080/v2").expect("loopback v4");
	assert_eq!(ok.as_str(), "http://127.0.0.1:8080/v2");
	assert!(HttpsUrl::loopback_http("http://[::1]:9/").is_ok());
	assert!(HttpsUrl::loopback_http("http://localhost:9/").is_ok());
	assert_eq!(
		HttpsUrl::loopback_http("http://203.0.113.9/"),
		Err(HttpsUrlError::NotHttps)
	);
	assert_eq!(
		HttpsUrl::loopback_http("http://dns.example/"),
		Err(HttpsUrlError::NotHttps)
	);
	assert_eq!(
		HttpsUrl::loopback_http("https://127.0.0.1/"),
		Err(HttpsUrlError::NotHttps)
	);
}

#[test]
fn segments_with_slash_and_query_characters_stay_one_segment() {
	let base = HttpsUrl::parse("https://dns.example/v2").expect("base");
	let url = base
		.with_segments(["acct/../9?x=1#f", "zones", "a b.example"])
		.expect("segments");
	assert_eq!(
		url.as_str(),
		"https://dns.example/v2/acct%2F..%2F9%3Fx=1%23f/zones/a%20b.example"
	);
	assert_eq!(url.as_url().query(), None);
	assert_eq!(url.as_url().fragment(), None);
}

#[test]
fn segments_do_not_double_the_trailing_slash_or_keep_the_query() {
	let base = HttpsUrl::parse("https://dns.example/v2/?old=1#frag").expect("base");
	let url = base.with_segments(["zones"]).expect("segments");
	assert_eq!(url.as_str(), "https://dns.example/v2/zones");
}

#[test]
fn segments_refuse_dot_segments() {
	let base = HttpsUrl::parse("https://dns.example/v2").expect("base");
	assert_eq!(base.with_segments([".."]), Err(HttpsUrlError::DotSegment));
	assert_eq!(
		base.with_segments(["a", "."]),
		Err(HttpsUrlError::DotSegment)
	);
}

#[test]
fn query_pairs_are_percent_encoded() {
	let base = HttpsUrl::parse("https://dns.example/zones").expect("base");
	let url = base.with_query("search", "a&b=c d");
	assert_eq!(url.as_str(), "https://dns.example/zones?search=a%26b%3Dc+d");
}
