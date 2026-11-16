//! A rule on `own_ip_blocklisted` posts one event per new listing, and a
//! listing that stays does not post again.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::integration::capture_server;
use crate::alerts::{context, run};
use crate::config::{Alert, AlertOp};
use crate::dnsbl::own::Listing;
use crate::metrics::Metrics;
use crate::storage::FsSpool;
use crate::webhook::{Webhook, WebhookEvent};

fn rule() -> Alert {
	Alert {
		name: "own-ip".into(),
		metric: "own_ip_blocklisted".into(),
		op: AlertOp::Ge,
		threshold: 1,
		window_secs: 1,
		cooldown_secs: 1,
		enabled: true,
		webhook: true,
		email: Vec::new(),
	}
}

fn listing(first_seen: u64) -> Listing {
	Listing {
		address: "93.184.216.34".parse::<IpAddr>().expect("ip"),
		zone: "zen.spamhaus.org".into(),
		delist_url: Some("https://check.spamhaus.org/listed/".into()),
		first_seen,
	}
}

#[tokio::test]
async fn a_new_listing_alerts_once_and_a_relisting_alerts_again() {
	let captured = Arc::new(Mutex::new(Vec::new()));
	let url = capture_server(Arc::clone(&captured)).await;
	let webhook = Arc::new(Webhook::new_allowing_private(&url, None).expect("webhook"));
	let metrics = Arc::new(Metrics::new());
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = Arc::new(FsSpool::open(dir.path()).expect("spool"));
	let ctx = context(Some(webhook), spool, "mail.example.org".into(), true, true);
	let handle = run(vec![rule()], Arc::clone(&metrics), ctx).expect("engine");

	metrics.own_ip_blocklisted(listing(1));
	tokio::time::sleep(Duration::from_millis(1300)).await;
	// Still listed for several windows: nothing new is counted.
	tokio::time::sleep(Duration::from_millis(2200)).await;
	assert_eq!(captured.lock().expect("lock").len(), 1);

	metrics.clear_own_ip_listing(listing(1).address);
	tokio::time::sleep(Duration::from_millis(1200)).await;
	metrics.own_ip_blocklisted(listing(2));
	tokio::time::sleep(Duration::from_millis(1300)).await;
	handle.stop();

	let events = captured.lock().expect("lock").clone();
	assert_eq!(events.len(), 2, "{events:?}");
	match &events[0] {
		WebhookEvent::OwnIpBlocklisted {
			address,
			zone,
			delist_url,
		} => {
			assert_eq!(address, "93.184.216.34");
			assert_eq!(zone, "spamhaus.org");
			assert_eq!(
				delist_url.as_deref(),
				Some("https://check.spamhaus.org/listed/")
			);
		}
		other => panic!("expected own_ip_blocklisted, got {other:?}"),
	}
}

const KEY: &str = "k3yA1b2C3d4E5f6";

fn keyed_listing() -> Listing {
	Listing {
		zone: format!("{KEY}.zen.dq.spamhaus.net"),
		..listing(1)
	}
}

async fn fire_keyed_listing(
	with_webhook: bool,
	email: &[&str],
) -> (Vec<WebhookEvent>, Vec<String>) {
	let captured = Arc::new(Mutex::new(Vec::new()));
	let url = capture_server(Arc::clone(&captured)).await;
	let webhook =
		with_webhook.then(|| Arc::new(Webhook::new_allowing_private(&url, None).expect("webhook")));
	let metrics = Arc::new(Metrics::new());
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = Arc::new(FsSpool::open(dir.path()).expect("spool"));
	let ctx = context(
		webhook,
		Arc::clone(&spool),
		"mail.example.org".into(),
		true,
		true,
	);
	let mut alert = rule();
	alert.webhook = with_webhook;
	alert.email = email.iter().map(|to| to.to_string()).collect();
	let handle = run(vec![alert], Arc::clone(&metrics), ctx).expect("engine");
	metrics.own_ip_blocklisted(keyed_listing());
	tokio::time::sleep(Duration::from_millis(1500)).await;
	handle.stop();
	let events = captured.lock().expect("lock").clone();
	let emails = spool
		.list()
		.expect("spool list")
		.into_iter()
		.map(|id| String::from_utf8(spool.load(id).expect("load").data).expect("utf-8"))
		.collect();
	(events, emails)
}

#[tokio::test]
async fn the_webhook_names_the_list_without_its_key() {
	let (events, _) = fire_keyed_listing(true, &[]).await;
	assert_eq!(events.len(), 1, "{events:?}");
	let json = serde_json::to_string(&events[0]).expect("json");
	assert!(!json.contains(KEY), "{json}");
	assert!(json.contains("\"zone\":\"spamhaus.net\""), "{json}");
}

#[tokio::test]
async fn the_alert_email_names_the_list_without_its_key() {
	let (_, emails) = fire_keyed_listing(false, &["ops@example.org"]).await;
	assert_eq!(emails.len(), 1, "one alert email");
	assert!(!emails[0].contains(KEY), "{}", emails[0]);
	assert!(
		emails[0].contains("listed in spamhaus.net"),
		"{}",
		emails[0]
	);
}
