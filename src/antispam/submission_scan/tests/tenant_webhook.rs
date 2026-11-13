//! A detection is announced to the webhook of the tenant that owns the
//! sender's domain, and to no other.

use super::*;
use crate::antispam::clamd::tests::fake::{FakeClamd, eicar};
use crate::smtp::sink::MemorySink;
use crate::test_support::fixtures::fresh_secret;
use crate::webhook::tests::support::{bodies, quiet, settle, signed_receiver, tenant_config};

fn from(sender: &str) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: sender.into(),
		recipients: vec!["bob@elsewhere.example".into()],
		data: format!("From: {sender}\r\nSubject: s\r\n\r\n{}\r\n", eicar()).into_bytes(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: false,
		no_dsn: Vec::new(),
	}
}

#[tokio::test]
async fn an_infected_submission_is_announced_to_the_senders_tenant_alone() {
	let (default_url, default) = signed_receiver().await;
	let (alpha_url, alpha) = signed_receiver().await;
	let (beta_url, beta) = signed_receiver().await;
	let config = tenant_config(
		Some((&default_url, &fresh_secret())),
		Some((&alpha_url, &fresh_secret())),
		Some((&beta_url, &fresh_secret())),
	);
	let webhook = Arc::new(crate::webhook::from_config(&config).expect("a poster"));
	let directory =
		crate::directory_store::DirectoryHandle::new(crate::smtp::directory::Directory::new(
			[
				"a.example".to_string(),
				"b.example".to_string(),
				"c.example".to_string(),
			],
			[
				("alice@a.example".to_string(), "alice".to_string()),
				("erin@c.example".to_string(), "erin".to_string()),
			],
		));
	let clamd = FakeClamd::start();
	let metrics = Arc::new(Metrics::new());
	let hook = Arc::new(ClamdHook::new(clamd.socket.clone()).with_metrics(metrics.clone()));
	let sink = ScanningSink::wrap_resolving(
		true,
		Arc::new(MemorySink::new()),
		Some(hook),
		None,
		(Some(metrics), Some(webhook), Some(directory)),
	)
	.expect("scanner");
	// Alice (alpha) writes MAIL FROM in beta's domain; erin belongs to no tenant.
	for (account, sender) in [("alice", "ceo@b.example"), ("erin", "erin@c.example")] {
		let sent = sink.submit(
			from(sender),
			uuid::Uuid::now_v7(),
			account,
			&crate::smtp::sink::Submission::default(),
		);
		assert!(sent.is_err(), "the detection was not refused");
	}
	settle(|| !bodies(&alpha).is_empty() && !bodies(&default).is_empty()).await;
	quiet().await;
	assert_eq!(
		bodies(&alpha).len(),
		1,
		"alpha got its own account's detection"
	);
	assert_eq!(
		bodies(&default).len(),
		1,
		"the unclaimed domain's went to the default"
	);
	assert!(
		bodies(&beta).is_empty(),
		"a forged sender moved the event to beta"
	);
	assert!(bodies(&alpha)[0].contains("outbound_virus"));
}
