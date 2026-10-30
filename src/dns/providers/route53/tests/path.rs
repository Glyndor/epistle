//! The hosted zone id is data in the request path: characters that mean
//! something in a URL must not change which resource the signed request
//! reaches.

use super::*;
use crate::dns::tests::uri_probe::probe;

#[test]
fn default_endpoint_is_the_signed_host_over_https() {
	let provider = Route53Provider::new("AKIA".into(), "secret".into(), "Z123".into());
	let url = provider.rrset_url().expect("url");
	assert_eq!(
		url.as_str(),
		"https://route53.amazonaws.com/2013-04-01/hostedzone/Z123/rrset"
	);
	assert_eq!(
		url.host_str(),
		Some(HOST),
		"the Host header and the URL agree"
	);
}

#[tokio::test]
async fn hosted_zone_id_is_one_escaped_path_segment() {
	let (base, seen) = probe(&["<ok/>"]).await;
	let provider =
		Route53Provider::new("AKIA".into(), "secret".into(), "Z1/../x?y".into()).with_base(base);
	provider
		.upsert(
			"example.org",
			DnsRecord {
				name: "a.example.org".to_string(),
				kind: RecordKind::A,
				value: "192.0.2.1".to_string(),
				ttl: 300,
				proxied: None,
			},
		)
		.await
		.expect("upsert");
	assert_eq!(
		*seen.lock().unwrap(),
		["POST /2013-04-01/hostedzone/Z1%2F..%2Fx%3Fy/rrset"]
	);
}
