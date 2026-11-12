//! Removing an account while mail for it is still being delivered.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use epistle::directory_store::{AccountStore, DynamicAccount, QueuePolicy, remove_account};
use epistle::smtp::server::Server;
use epistle::storage::{FsSpool, LocalDelivery};
use tokio::sync::{Barrier, Semaphore};

use super::{support::*, wire};

const LINES: usize = 8;
const DEPTH: usize = 16;

fn account_store(root: &Path) -> Arc<AccountStore> {
	let store = AccountStore::open(root, vec!["epistle.test".into()], HashMap::new(), vec![])
		.expect("open store");
	add_tester(&store);
	Arc::new(store)
}

fn add_tester(store: &AccountStore) {
	let hash = epistle::smtp::auth::hash_password(&wire::PASSWORD).expect("password hash");
	store
		.add(DynamicAccount {
			name: "tester".into(),
			addresses: vec!["tester@epistle.test".into()],
			password_hash: hash,
			..DynamicAccount::default()
		})
		.expect("add account");
}

/// Sessions with the recipient accepted and the whole body queued; only the
/// final dot is withheld, so the race is the finalisation and nothing else.
async fn sessions_before_the_dot(listener: &Listener) -> Vec<tokio::net::TcpStream> {
	let mut sessions = Vec::new();
	for id in 0..DEPTH {
		let mut stream = listener.connect().await;
		data(&mut stream, false).await;
		wire::send(&mut stream, &message(id, LINES, false)).await;
		sessions.push(stream);
	}
	sessions
}

async fn finish(stream: &mut tokio::net::TcpStream) -> String {
	wire::send(stream, b".\r\n").await;
	wire::line(stream)
		.await
		.expect("DATA reply")
		.expect("connection open")
}

/// Everything left under the removed account's mailbox root. The empty root
/// itself is allowed; any entry below it is mail or state that should be gone.
fn leftovers(root: &Path) -> Vec<String> {
	fn walk(dir: &Path, found: &mut Vec<String>) {
		let Ok(entries) = std::fs::read_dir(dir) else {
			return;
		};
		for entry in entries.flatten() {
			found.push(entry.path().display().to_string());
			walk(&entry.path(), found);
		}
	}
	let mut found = Vec::new();
	walk(&root.join("accounts/tester"), &mut found);
	found
}

/// `after_removal`: every final dot arrives once the removal has returned.
/// Otherwise the removal and the dots start together from one barrier.
async fn run(after_removal: bool) -> (Vec<String>, Vec<String>) {
	let root = tempfile::tempdir().expect("data dir");
	let store = account_store(root.path());
	let spool = FsSpool::open(root.path()).expect("spool");
	let sink = Arc::new(LocalDelivery::new(root.path(), store.handle()).expect("local delivery"));
	let listener =
		Listener::start(Server::new("mx.epistle.test", sink).with_directory(store.handle())).await;
	// One acknowledged delivery first, so the mailbox exists and has something to lose.
	let mut control = listener.connect().await;
	data(&mut control, false).await;
	wire::send(&mut control, &message(DEPTH, LINES, false)).await;
	assert_eq!(finish(&mut control).await, wire::OK);
	wire::quit(&mut control).await;
	assert!(
		!leftovers(root.path()).is_empty(),
		"setup: the mailbox exists before removal"
	);

	let sessions = sessions_before_the_dot(&listener).await;
	let barrier = Arc::new(Barrier::new(DEPTH + 1));
	let released = Arc::new(Semaphore::new(0));
	let mut tasks = tokio::task::JoinSet::new();
	for mut stream in sessions {
		let (barrier, released) = (barrier.clone(), released.clone());
		tasks.spawn(async move {
			if after_removal {
				released.acquire().await.expect("gate open").forget();
			} else {
				barrier.wait().await;
			}
			finish(&mut stream).await
		});
	}
	let remover = {
		let (store, path) = (store.clone(), root.path().to_path_buf());
		tokio::spawn(async move {
			if !after_removal {
				barrier.wait().await;
			}
			remove_account(&store, &spool, &path, "tester", QueuePolicy::Drain, None)
				.await
				.expect("removal returns");
		})
	};
	let mut replies = Vec::new();
	let mut remover = Some(remover);
	if after_removal {
		remover.take().unwrap().await.expect("removal task");
		assert_eq!(
			leftovers(root.path()),
			Vec::<String>::new(),
			"removal completed before the dots"
		);
		released.add_permits(DEPTH);
	}
	while let Some(reply) = tasks.join_next().await {
		replies.push(reply.expect("delivery task"));
	}
	if let Some(remover) = remover {
		remover.await.expect("removal task");
	}
	(replies, leftovers(root.path()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn removal_and_delivery_do_not_interleave() {
	seed("account removal");
	// One round with every dot after the removal, then several where the
	// removal and the dots leave the same barrier together.
	for after_removal in [true, false, false, false, false] {
		let (replies, left) = run(after_removal).await;
		assert!(
			left.is_empty(),
			"seed={SEED:#x} after_removal={after_removal}: a delivery wrote after the removal; left={left:?} replies={replies:?}"
		);
	}
}
