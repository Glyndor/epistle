//! A tenant's events go to the tenant's webhook and to no other, signed with
//! the tenant's secret; the server-wide webhook is the default for the rest.

use super::support::{Received, bodies, quiet, settle, signed_receiver, tenant_config};
use super::*;
use crate::test_fixtures::fresh_secret;

fn received_for(account: &str) -> WebhookEvent {
	WebhookEvent::MessageReceived {
		account: account.into(),
		from: "origin@elsewhere.example".into(),
		subject: Some("hello".into()),
		message_id: None,
	}
}

fn delivered(recipient: &str) -> WebhookEvent {
	WebhookEvent::Delivered {
		spool_id: Uuid::nil(),
		recipient: recipient.into(),
		message_id: None,
		remote: None,
		extra: BTreeMap::new(),
	}
}

fn signature_of(received: &Received, index: usize) -> (String, Option<String>) {
	received.lock().expect("lock")[index].clone()
}

struct Three {
	webhook: Webhook,
	default: Received,
	alpha: Received,
	beta: Received,
	secrets: (String, String, String),
}

/// A server-wide receiver and one per tenant, each with its own secret.
async fn three() -> Three {
	let (default_url, default) = signed_receiver().await;
	let (alpha_url, alpha) = signed_receiver().await;
	let (beta_url, beta) = signed_receiver().await;
	let secrets = (fresh_secret(), fresh_secret(), fresh_secret());
	let config = tenant_config(
		Some((&default_url, &secrets.0)),
		Some((&alpha_url, &secrets.1)),
		Some((&beta_url, &secrets.2)),
	);
	let webhook = from_config(&config).expect("a poster");
	Three {
		webhook,
		default,
		alpha,
		beta,
		secrets,
	}
}

#[tokio::test]
async fn an_event_of_one_tenant_reaches_only_that_tenant_signed_with_its_secret() {
	let t = three().await;
	t.webhook.notify(&received_for("alice@a.example")).await;
	settle(|| !bodies(&t.alpha).is_empty()).await;
	quiet().await;
	assert_eq!(bodies(&t.alpha).len(), 1, "alpha got its event");
	assert!(bodies(&t.beta).is_empty(), "beta saw alpha's event");
	assert!(
		bodies(&t.default).is_empty(),
		"the default saw alpha's event"
	);
	let (body, signature) = signature_of(&t.alpha, 0);
	assert_eq!(
		signature.as_deref(),
		Some(sign(&t.secrets.1, body.as_bytes()).as_str())
	);
	for foreign in [&t.secrets.0, &t.secrets.2] {
		assert_ne!(
			signature.as_deref(),
			Some(sign(foreign, body.as_bytes()).as_str()),
			"alpha's event was signed with another webhook's secret"
		);
	}
}

#[tokio::test]
async fn the_other_tenant_gets_its_own_events_and_not_the_first_ones() {
	let t = three().await;
	t.webhook.notify(&received_for("alice@a.example")).await;
	t.webhook.notify(&received_for("bob@b.example")).await;
	settle(|| !bodies(&t.alpha).is_empty() && !bodies(&t.beta).is_empty()).await;
	quiet().await;
	let (alpha, beta) = (bodies(&t.alpha), bodies(&t.beta));
	assert_eq!((alpha.len(), beta.len()), (1, 1));
	assert!(alpha[0].contains("alice@a.example") && !alpha[0].contains("bob@b.example"));
	assert!(beta[0].contains("bob@b.example") && !beta[0].contains("alice@a.example"));
	let (body, signature) = signature_of(&t.beta, 0);
	assert_eq!(
		signature.as_deref(),
		Some(sign(&t.secrets.2, body.as_bytes()).as_str())
	);
	assert!(bodies(&t.default).is_empty());
}

#[tokio::test]
async fn delivery_events_follow_the_domain_the_poster_names() {
	let t = three().await;
	t.webhook
		.notify_for(Some("a.example"), &delivered("x@remote.example"))
		.await;
	t.webhook
		.notify_for(Some("B.Example"), &delivered("y@remote.example"))
		.await;
	settle(|| !bodies(&t.alpha).is_empty() && !bodies(&t.beta).is_empty()).await;
	quiet().await;
	assert_eq!(bodies(&t.alpha).len(), 1);
	assert!(bodies(&t.alpha)[0].contains("x@remote.example"));
	assert_eq!(
		bodies(&t.beta).len(),
		1,
		"the domain is matched without regard to case"
	);
	assert!(bodies(&t.beta)[0].contains("y@remote.example"));
	assert!(bodies(&t.default).is_empty());
}

#[tokio::test]
async fn a_domain_alias_of_a_tenant_domain_belongs_to_that_tenant() {
	let t = three().await;
	t.webhook
		.notify(&received_for("alice@alias-a.example"))
		.await;
	settle(|| !bodies(&t.alpha).is_empty()).await;
	quiet().await;
	assert_eq!(bodies(&t.alpha).len(), 1);
	assert!(bodies(&t.default).is_empty() && bodies(&t.beta).is_empty());
}

#[tokio::test]
async fn domains_outside_every_tenant_and_the_servers_own_events_use_the_default() {
	let t = three().await;
	t.webhook.notify(&received_for("carol@c.example")).await;
	t.webhook
		.notify(&WebhookEvent::Test {
			message: TEST_MESSAGE.into(),
		})
		.await;
	t.webhook
		.notify_for(None, &delivered("z@remote.example"))
		.await;
	settle(|| bodies(&t.default).len() == 3).await;
	quiet().await;
	assert_eq!(bodies(&t.default).len(), 3);
	let (body, signature) = signature_of(&t.default, 0);
	assert_eq!(
		signature.as_deref(),
		Some(sign(&t.secrets.0, body.as_bytes()).as_str())
	);
	assert!(bodies(&t.alpha).is_empty() && bodies(&t.beta).is_empty());
}

#[tokio::test]
async fn a_tenant_without_a_webhook_stays_on_the_default() {
	let (default_url, default) = signed_receiver().await;
	let (beta_url, beta) = signed_receiver().await;
	let config = tenant_config(
		Some((&default_url, &fresh_secret())),
		None,
		Some((&beta_url, &fresh_secret())),
	);
	let webhook = from_config(&config).expect("a poster");
	webhook.notify(&received_for("alice@a.example")).await;
	settle(|| !bodies(&default).is_empty()).await;
	quiet().await;
	assert_eq!(bodies(&default).len(), 1, "alpha has no webhook of its own");
	assert!(bodies(&beta).is_empty());
}

#[tokio::test]
async fn a_tenant_whose_webhook_is_off_posts_nowhere_not_to_the_default() {
	let (default_url, default) = signed_receiver().await;
	let (beta_url, beta) = signed_receiver().await;
	let mut config = tenant_config(
		Some((&default_url, &fresh_secret())),
		Some((&default_url, &fresh_secret())),
		Some((&beta_url, &fresh_secret())),
	);
	config.tenants[0].webhook.as_mut().expect("alpha").enabled = false;
	let webhook = from_config(&config).expect("a poster");
	webhook.notify(&received_for("alice@a.example")).await;
	webhook.notify(&received_for("bob@b.example")).await;
	settle(|| !bodies(&beta).is_empty()).await;
	quiet().await;
	assert!(
		bodies(&default).is_empty(),
		"alpha's off webhook fell back to the default"
	);
	assert_eq!(bodies(&beta).len(), 1);
}

#[tokio::test]
async fn a_failing_tenant_endpoint_does_not_spill_its_event_to_anyone() {
	let (default_url, default) = signed_receiver().await;
	let (beta_url, beta) = signed_receiver().await;
	// Alpha's endpoint refuses connections.
	let config = tenant_config(
		Some((&default_url, &fresh_secret())),
		Some(("http://127.0.0.1:1/hook", &fresh_secret())),
		Some((&beta_url, &fresh_secret())),
	);
	let metrics = Arc::new(crate::metrics::Metrics::new());
	let webhook = from_config(&config)
		.expect("a poster")
		.with_metrics(metrics.clone());
	webhook.notify(&received_for("alice@a.example")).await;
	quiet().await;
	assert!(bodies(&default).is_empty() && bodies(&beta).is_empty());
	assert!(metrics.render().contains("mail_webhook_failed_total 1\n"));
	// The failure left no state behind: beta delivers, once, as usual.
	webhook.notify(&received_for("bob@b.example")).await;
	settle(|| !bodies(&beta).is_empty()).await;
	assert_eq!(bodies(&beta).len(), 1);
	assert!(metrics.render().contains("mail_webhook_sent_total 1\n"));
}

#[tokio::test]
async fn tenants_alone_are_enough_to_have_a_poster() {
	let (alpha_url, alpha) = signed_receiver().await;
	let config = tenant_config(None, Some((&alpha_url, &fresh_secret())), None);
	let webhook = from_config(&config).expect("a poster from the tenant alone");
	webhook.notify(&received_for("alice@a.example")).await;
	// No server-wide webhook: the other domains' events have nowhere to go.
	webhook.notify(&received_for("carol@c.example")).await;
	settle(|| !bodies(&alpha).is_empty()).await;
	quiet().await;
	assert_eq!(bodies(&alpha).len(), 1);
}

#[test]
fn no_webhook_anywhere_is_no_poster() {
	assert!(from_config(&tenant_config(None, None, None)).is_none());
}

/// A server on a second port that counts what reaches it, and a first one
/// that answers every POST with a 307 pointing at the second.
async fn redirecting_endpoint() -> (String, Arc<std::sync::atomic::AtomicUsize>) {
	use std::sync::atomic::{AtomicUsize, Ordering};
	let hits = Arc::new(AtomicUsize::new(0));
	let counter = Arc::clone(&hits);
	let internal = axum::Router::new().route(
		"/internal",
		axum::routing::post(move || {
			let counter = Arc::clone(&counter);
			async move {
				counter.fetch_add(1, Ordering::SeqCst);
				"reached"
			}
		}),
	);
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
		.await
		.expect("bind");
	let target = format!("http://{}/internal", listener.local_addr().expect("addr"));
	tokio::spawn(async move { axum::serve(listener, internal).await.expect("serve") });
	let front = axum::Router::new().route(
		"/hook",
		axum::routing::post(move || {
			let target = target.clone();
			async move {
				(
					axum::http::StatusCode::TEMPORARY_REDIRECT,
					[(axum::http::header::LOCATION, target)],
				)
			}
		}),
	);
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
		.await
		.expect("bind");
	let addr = listener.local_addr().expect("addr");
	tokio::spawn(async move { axum::serve(listener, front).await.expect("serve") });
	(format!("http://{addr}/hook"), hits)
}

#[tokio::test]
async fn a_tenant_endpoint_that_redirects_is_not_followed() {
	let (url, hits) = redirecting_endpoint().await;
	let config = tenant_config(None, Some((&url, &fresh_secret())), None);
	let metrics = Arc::new(crate::metrics::Metrics::new());
	let webhook = from_config(&config)
		.expect("a poster")
		.with_metrics(metrics.clone());
	webhook.notify(&received_for("alice@a.example")).await;
	assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0);
	assert!(metrics.render().contains("mail_webhook_failed_total 1\n"));
}

/// A configuration whose tenant `alpha` posts to `url` without saying that a
/// private destination is fine, and whose server-wide webhook is `default`.
fn alpha_to(url: &str, allow_private: bool, default: Option<&str>) -> crate::config::Config {
	let default = default
		.map(|url| format!("[webhook]\nurl = \"{url}\"\nallow_private_webhooks = true\n"))
		.unwrap_or_default();
	toml::from_str(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n\
		 domains = [\"a.example\", \"c.example\"]\n{default}\
		 [[tenant]]\nname = \"alpha\"\ndomains = [\"a.example\"]\n\
		 [tenant.webhook]\nurl = \"{url}\"\nallow_private_webhooks = {allow_private}\n"
	))
	.expect("parses")
}

#[tokio::test]
async fn a_tenant_url_naming_a_private_address_is_refused_like_the_servers() {
	// The cloud metadata address, a loopback port and a private network.
	for url in [
		"http://169.254.169.254/latest/meta-data",
		"http://127.0.0.1:9/hook",
		"http://10.0.0.7/hook",
		"http://[::1]:9/hook",
		"http://0x7f.1/hook",
		"http://user@192.168.1.5/hook",
	] {
		let (default_url, default) = signed_receiver().await;
		let config = alpha_to(url, false, Some(&default_url));
		let webhook = from_config(&config).expect("the default still posts");
		webhook.notify(&received_for("alice@a.example")).await;
		quiet().await;
		assert!(
			bodies(&default).is_empty(),
			"{url}: a refused tenant webhook fell back to the default"
		);
	}
}

#[test]
fn a_private_tenant_url_alone_makes_no_poster_until_the_operator_allows_it() {
	let url = "http://169.254.169.254/latest/meta-data";
	assert!(from_config(&alpha_to(url, false, None)).is_none());
	assert!(from_config(&alpha_to(url, true, None)).is_some());
}

#[tokio::test]
async fn the_test_event_without_a_server_wide_webhook_is_an_error_not_a_panic() {
	let url = "http://169.254.169.254/latest/meta-data";
	let webhook = from_config(&alpha_to(url, true, None)).expect("a tenant poster");
	let error = webhook
		.send_test()
		.await
		.expect_err("no endpoint to post to");
	assert!(matches!(error, WebhookError::NoEndpoint), "{error:?}");
}

#[tokio::test]
async fn one_tenant_allowing_private_destinations_does_not_allow_them_for_the_others() {
	let (private_url, _) = signed_receiver().await;
	// Alpha may post to a private address; the server-wide webhook may not.
	let config: crate::config::Config = toml::from_str(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n\
		 domains = [\"a.example\", \"c.example\"]\n\
		 [webhook]\nurl = \"{private_url}\"\n\
		 [[tenant]]\nname = \"alpha\"\ndomains = [\"a.example\"]\n\
		 [tenant.webhook]\nurl = \"{private_url}\"\nallow_private_webhooks = true\n"
	))
	.expect("parses");
	let webhook = from_config(&config).expect("alpha's poster");
	assert!(webhook.endpoint_for(Some("a.example")).is_some());
	assert!(
		webhook.endpoint_for(Some("c.example")).is_none(),
		"the server-wide webhook posted to a private address it was not allowed"
	);
}

#[test]
fn the_domain_of_an_event_is_the_recipients_and_an_owner_is_one_domain() {
	assert_eq!(
		received_for("Alice@A.Example").hosted_domain().as_deref(),
		Some("a.example")
	);
	assert_eq!(received_for("no-at-sign").hosted_domain(), None);
	assert_eq!(delivered("x@y.example").hosted_domain(), None);
	assert_eq!(
		single_domain(["a@A.example", "b@a.example"]).as_deref(),
		Some("a.example")
	);
	assert_eq!(single_domain(["a@a.example", "b@b.example"]), None);
	assert_eq!(single_domain(["no-at-sign"]), None);
	assert_eq!(single_domain([] as [&str; 0]), None);
}
