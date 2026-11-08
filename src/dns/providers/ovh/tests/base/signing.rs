use super::*;

#[test]
fn signature_matches_ovh_python_reference_vector() {
	// The vector is the same one python-ovh ships in
	// `python-ovh/tests/test_client.py::TestClient::test_call_signature`:
	// a GET against `https://eu.api.ovh.com/1.0/auth` at unix 1457018875
	// with the body empty produces this exact signature header.
	let provider = OvhProvider::new(
		"TDPKJdwZwAQPwKX2".into(),
		"9ufkBmLaTQ9nz5yMUlg79taH0GNnzDjk".into(),
		ScopedSecret::new("example.org", "5mBuy6SUQcRw2ZUxg0cG68BoDKpED4KY"),
	);
	let url = "https://eu.api.ovh.com/1.0/auth";
	let sig = provider.sign("GET", url, "", 1457018875);
	assert_eq!(sig, "$1$e9556054b6309771395efa467c22e627407461ad");
}

#[test]
fn sub_domain_strips_zone_and_uses_empty_for_apex() {
	assert_eq!(OvhProvider::sub_domain("example.org", "example.org"), "");
	assert_eq!(
		OvhProvider::sub_domain("example.org", "_dmarc.example.org"),
		"_dmarc"
	);
	assert_eq!(
		OvhProvider::sub_domain("example.org", "mail.example.org"),
		"mail"
	);
	assert_eq!(
		OvhProvider::sub_domain("example.org", "_dmarc.example.org."),
		"_dmarc"
	);
}

#[test]
fn endpoint_alias_resolves_to_regional_base() {
	let resolved = |endpoint| resolve_base(endpoint).map(|url| url.to_string());
	assert_eq!(resolved(None), Ok("https://eu.api.ovh.com/1.0".to_string()));
	assert_eq!(
		resolved(Some("ovh-eu")),
		Ok("https://eu.api.ovh.com/1.0".to_string())
	);
	assert_eq!(
		resolved(Some("ovh-ca")),
		Ok("https://ca.api.ovh.com/1.0".to_string())
	);
	assert_eq!(
		resolved(Some("ovh-us")),
		Ok("https://api.us.ovhcloud.com/1.0".to_string())
	);
	assert_eq!(
		resolved(Some("https://private.example.com/1.0")),
		Ok("https://private.example.com/1.0".to_string())
	);
	assert_eq!(
		resolved(Some("not-a-region")),
		Ok("https://eu.api.ovh.com/1.0".to_string())
	);
}

#[test]
fn a_cleartext_endpoint_is_refused() {
	assert_eq!(
		resolve_base(Some("http://private.example.com/1.0")),
		Err(crate::net::HttpsUrlError::NotHttps)
	);
}
