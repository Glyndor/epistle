//! The request URLs the Google Cloud DNS provider builds: the production base
//! must not repeat its own version prefix, and identifiers are path data.

use super::test_support::test_key;
use super::*;

fn provider(project_id: &str) -> GcloudProvider {
	let account = ServiceAccount {
		client_email: "sa@example.iam.gserviceaccount.com".into(),
		private_key: test_key().pem.clone(),
		project_id: project_id.into(),
	};
	GcloudProvider::new(ScopedSecret::new("example.org", ""), account)
}

#[test]
fn production_urls_carry_the_version_prefix_once() {
	let provider = provider("proj");
	assert_eq!(
		provider.managed_zones_url(&[]).unwrap().as_str(),
		"https://dns.googleapis.com/dns/v1/projects/proj/managedZones"
	);
	assert_eq!(
		provider
			.managed_zones_url(&["zone-1", "rrsets"])
			.unwrap()
			.as_str(),
		"https://dns.googleapis.com/dns/v1/projects/proj/managedZones/zone-1/rrsets"
	);
}

#[test]
fn project_and_zone_identifiers_stay_single_path_segments() {
	let provider = provider("p/../q?x=1");
	let url = provider.managed_zones_url(&["z#1", "changes"]).unwrap();
	assert_eq!(
		url.as_str(),
		"https://dns.googleapis.com/dns/v1/projects/p%2F..%2Fq%3Fx=1/managedZones/z%231/changes"
	);
	assert_eq!(url.as_url().query(), None);
}

#[test]
fn token_endpoint_is_the_https_oauth_host() {
	let provider = provider("proj");
	assert_eq!(
		provider
			.token_base
			.with_segments(["token"])
			.unwrap()
			.as_str(),
		"https://oauth2.googleapis.com/token"
	);
}
