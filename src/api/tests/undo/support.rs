//! Two accounts (`ann`, `bob`), a key bound to each, the configured token,
//! and the undo sink in front of a routing sink, as the server wires it.

use std::sync::Arc;

use axum::Router;

use super::super::base::TOKEN;
use super::super::router;
use crate::smtp::sink::MessageSink;
use crate::storage::undo::{NoticeStyle, Releaser, UndoPolicy, UndoSink, UndoStore};
use crate::storage::{FsSpool, MessageCrypto, SplitDelivery};

pub(super) const ANN: &str = "ann";
pub(super) const BOB: &str = "bob";

pub(super) fn secret(account: &str) -> String {
	format!("{account}-secret")
}

fn account(name: &str) -> crate::config::Account {
	crate::config::Account {
		send: None,
		receive: None,
		display_name: None,
		name: name.to_string(),
		addresses: vec![format!("{name}@example.org")],
		password_hash: Some(crate::smtp::auth::tests::base::hash(
			crate::test_support::fixtures::password(),
		)),
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
		allowed_protocols: None,
	}
}

pub(super) struct Rig {
	pub app: Router,
	pub releaser: Releaser,
	pub dir: tempfile::TempDir,
}

/// The app. `delay_secs` is the server-wide send delay; `0` leaves the
/// submission path as it is without undo send.
pub(super) fn rig(delay_secs: u32, scopes: &[&str]) -> Rig {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut keys = crate::api::ApiKeyStore::open(dir.path()).expect("open key store");
	for (name, scopes) in [
		(ANN, vec!["read", "write", "send"]),
		(BOB, vec!["read", "write", "send"]),
		("ann-read", vec!["read"]),
	] {
		keys.add(crate::api::api_keys::ApiKey {
			grants: Vec::new(),
			label: format!("{name}-only"),
			hash: crate::api::api_keys::sha256_hash(&secret(name)),
			expires_at: None,
			ip_cidr: None,
			scopes: scopes.into_iter().map(str::to_string).collect(),
			domains: Vec::new(),
			account: Some(name.trim_end_matches("-read").to_string()),
			auto_submitted: false,
		})
		.expect("add key");
	}
	drop(keys);
	let domains = vec!["example.org".to_string()];
	let store = Arc::new(
		crate::directory_store::AccountStore::open(
			dir.path(),
			domains.clone(),
			std::collections::HashMap::new(),
			vec![account(ANN), account(BOB)],
		)
		.expect("open store"),
	);
	let routing: Arc<dyn MessageSink> =
		Arc::new(SplitDelivery::new(dir.path(), store.handle()).expect("routing"));
	let held =
		Arc::new(UndoStore::open(dir.path(), MessageCrypto::disabled()).expect("held store"));
	let config: crate::config::Config = toml::from_str(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n\
		 domains = [\"example.org\"]\n[queue.undo_send]\ndelay_secs = {delay_secs}\n{}",
		scopes.join("\n")
	))
	.expect("config");
	let mut state = crate::api::ApiState::new(
		&crate::smtp::auth::tests::base::hash(TOKEN.as_str()),
		dir.path().to_path_buf(),
		domains,
		store.clone(),
		FsSpool::open(dir.path()).expect("open spool"),
	)
	.with_directory(store.handle());
	let policy = UndoPolicy::from_config(&config);
	if !policy.is_off() {
		let sink = UndoSink::new(
			Arc::clone(&routing),
			Arc::clone(&held),
			policy,
			store.handle(),
		);
		state = state.with_outbound(Arc::new(sink));
	} else {
		state = state.with_outbound(Arc::clone(&routing));
	}
	let releaser = Releaser::new(
		held,
		routing,
		NoticeStyle {
			hostname: "mail.example.org".into(),
			auto_submitted: true,
			auto_response_suppress: true,
		},
	);
	Rig {
		app: router(state),
		releaser,
		dir,
	}
}

/// The ids of the messages the remote part of mail left in the spool.
pub(super) fn queued(dir: &std::path::Path) -> Vec<uuid::Uuid> {
	FsSpool::open(dir).expect("spool").list().expect("list")
}
