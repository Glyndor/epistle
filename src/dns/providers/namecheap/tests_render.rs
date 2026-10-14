//! Pure unit tests for the render-side helpers: `split_sld_tld`,
//! `host_label`, and the sandbox URL constant. No mock server required.

use super::NamecheapProvider;
use super::render;

#[test]
fn split_sld_tld_two_label() {
	let (sld, tld) = render::split_sld_tld("example.org");
	assert_eq!(sld, "example");
	assert_eq!(tld, "org");
}

#[test]
fn split_sld_tld_with_psl_subdomain() {
	let (sld, tld) = render::split_sld_tld("foo.example.org");
	assert_eq!(sld, "example");
	assert_eq!(tld, "org");
}

#[test]
fn split_sld_tld_with_psl_multi_label_tld() {
	let (sld, tld) = render::split_sld_tld("foo.example.co.uk");
	assert_eq!(sld, "example");
	assert_eq!(tld, "co.uk");
}

#[test]
fn host_label_apex_is_at() {
	let label = render::host_label("example.org", "example.org");
	assert_eq!(label, "@");
}

#[test]
fn host_label_subdomain_is_prefix() {
	let label = render::host_label("_dmarc.example.org", "example.org");
	assert_eq!(label, "_dmarc");
}

#[test]
fn host_label_strips_trailing_dot_on_input() {
	let label = render::host_label("_dmarc.example.org.", "example.org");
	assert_eq!(label, "_dmarc");
}

#[test]
fn sandbox_url_constant_is_sandbox_subdomain() {
	assert_eq!(
		NamecheapProvider::sandbox_url().host_str(),
		Some("api.sandbox.namecheap.com")
	);
}

/// The null MX (RFC 7505) keeps its root target instead of an empty one.
#[test]
fn the_null_mx_keeps_its_root_target() {
	let mx = crate::dns::provider::DnsRecord::new(
		"www.example.org",
		crate::dns::provider::RecordKind::Mx,
		"0 .",
		3600,
	);
	let host = render::host_from_record(&mx, "example.org").expect("host");
	assert_eq!(host.address, ".");
	assert_eq!(host.mx_pref, Some(0));
}
