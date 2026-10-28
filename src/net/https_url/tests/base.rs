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

#[test]
fn from_static_accepts_an_https_literal() {
	let url = HttpsUrl::from_static("https://desec.io/api/v1");
	assert_eq!(url.as_str(), "https://desec.io/api/v1");
}

#[test]
#[should_panic(expected = "is not a usable https URL: URL must use https://")]
fn from_static_panics_on_an_http_literal() {
	let _ = HttpsUrl::from_static("http://desec.io/api/v1");
}

#[test]
fn follow_accepts_same_origin_absolute_and_relative_links() {
	let base = HttpsUrl::parse("https://api.example/v2/domains").expect("base");
	assert_eq!(
		base.follow("https://api.example/v2/domains?page=2")
			.map(|u| u.to_string()),
		Ok("https://api.example/v2/domains?page=2".to_string())
	);
	assert_eq!(
		base.follow("/v2/other?page=3").map(|u| u.to_string()),
		Ok("https://api.example/v2/other?page=3".to_string())
	);
}

#[test]
fn follow_refuses_another_host_scheme_or_port() {
	let base = HttpsUrl::parse("https://api.example/v2").expect("base");
	for link in [
		"https://evil.example/v2",
		"http://api.example/v2",
		"https://api.example:8443/v2",
		"//evil.example/v2",
		"https://api.example.evil.example/v2",
	] {
		assert_eq!(base.follow(link), Err(HttpsUrlError::OffOrigin), "{link}");
	}
}

#[test]
fn follow_refuses_a_link_with_embedded_credentials() {
	let base = HttpsUrl::parse("https://api.example/v2").expect("base");
	assert_eq!(
		base.follow("https://user:pw@api.example/v2"),
		Err(HttpsUrlError::EmbeddedCredentials)
	);
}
