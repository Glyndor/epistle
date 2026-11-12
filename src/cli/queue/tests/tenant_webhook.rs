//! Removing a queue entry tells the webhook of the tenant that owns it, as the
//! server does, and nobody's when that tenant's webhook is off.

use std::collections::BTreeMap;
use std::process::ExitCode;

use super::{QueueCli, run, webhook_for};
use crate::smtp::session::AcceptedMessage;
use crate::storage::FsSpool;
use crate::test_support::fixtures::fresh_secret;
use crate::webhook::tests::support::{bodies, quiet, settle, signed_receiver, tenant_config};

fn message(sender: &str, recipient: &str) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: sender.into(),
		recipients: vec![recipient.into()],
		data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: false,
		no_dsn: Vec::new(),
	}
}

#[tokio::test]
async fn a_removal_follows_the_owner_of_the_entry_and_a_tenant_that_is_off_hears_nothing() {
	let (default_url, default) = signed_receiver().await;
	let (alpha_url, alpha) = signed_receiver().await;
	let (beta_url, beta) = signed_receiver().await;
	let mut config = tenant_config(
		Some((&default_url, &fresh_secret())),
		Some((&alpha_url, &fresh_secret())),
		Some((&beta_url, &fresh_secret())),
	);
	config.tenants[1].webhook.as_mut().expect("beta").enabled = false;
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("spool");
	let mut ids = Vec::new();
	for (sender, recipient, owner) in [
		("alice@a.example", "carol@remote.example", Some("a.example")),
		("bob@b.example", "dave@remote.example", Some("b.example")),
		// No owner: the sender's domain is not consulted.
		("legacy@a.example", "frank@remote.example", None),
	] {
		ids.push(
			spool
				.store_owned(&message(sender, recipient), owner, &BTreeMap::new())
				.expect("store"),
		);
	}
	let webhook = std::sync::Arc::new(webhook_for(&config).expect("a poster"));
	for id in ids {
		let mut out = Vec::new();
		let code = run(
			dir.path(),
			None,
			30,
			Some(QueueCli::Remove { id, yes: true }),
			false,
			1_700_000_000,
			Some(&webhook),
			&mut out,
		);
		assert_eq!(code, ExitCode::SUCCESS);
	}
	settle(|| !bodies(&alpha).is_empty() && !bodies(&default).is_empty()).await;
	quiet().await;
	let (alpha, beta, default) = (bodies(&alpha), bodies(&beta), bodies(&default));
	assert_eq!((alpha.len(), default.len()), (1, 1));
	assert!(alpha[0].contains("carol@remote.example"), "{}", alpha[0]);
	assert!(
		default[0].contains("frank@remote.example"),
		"{}",
		default[0]
	);
	assert!(beta.is_empty(), "a tenant that is off was told");
	assert!(
		!default.iter().any(|body| body.contains("dave@")),
		"the off tenant's removal fell back to the default"
	);
}
