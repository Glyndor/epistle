//! Client configuration is not offered for a domain that is switched off.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use crate::config::Config;

fn config(extra: &str) -> Config {
	toml::from_str(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n\
		 domains = [\"example.org\", \"example.net\"]\n{extra}"
	))
	.expect("config")
}

async fn status(config: &Config, address: &str) -> StatusCode {
	let request = Request::get(format!("/mail/config-v1.1.xml?emailaddress={address}"))
		.body(Body::empty())
		.expect("request");
	super::router_for(config)
		.oneshot(request)
		.await
		.expect("response")
		.status()
}

#[tokio::test]
async fn a_disabled_domain_gets_no_autoconfig() {
	let config = config("disabled_domains = [\"example.net\"]");
	assert_eq!(status(&config, "a@example.org").await, StatusCode::OK);
	assert_eq!(
		status(&config, "a@example.net").await,
		StatusCode::NOT_FOUND
	);
	assert_eq!(
		status(&config, "A@Example.NET").await,
		StatusCode::NOT_FOUND
	);
}

#[tokio::test]
async fn with_nothing_disabled_both_domains_are_served() {
	let config = config("");
	assert_eq!(status(&config, "a@example.net").await, StatusCode::OK);
}

#[test]
fn enabled_domains_leave_out_the_disabled_ones() {
	let config = config("disabled_domains = [\"example.net\"]");
	assert_eq!(config.enabled_domains(), vec!["example.org".to_string()]);
}
