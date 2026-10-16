use std::sync::Arc;

use super::*;
use crate::evidence::chain::Chain;
use crate::evidence::test_support::{accepted, at};
use crate::evidence::tsa::fake::FakeTsa;
use crate::evidence::tsa::settings::Authority;
use crate::storage::MessageCrypto;

pub(super) const DAY: i64 = 20_740;

pub(super) fn service(dir: &Path) -> Arc<EvidenceService> {
	Arc::new(EvidenceService::open(dir, Vec::new(), MessageCrypto::disabled()).expect("evidence"))
}

pub(super) async fn with_tsa(dir: &Path, gen_time: u64) -> Arc<FakeTsa> {
	let tsa = Arc::new(FakeTsa::new(gen_time));
	let url = Arc::clone(&tsa).serve().await;
	let settings = Settings {
		enabled: true,
		authorities: vec![Authority {
			url,
			anchors: vec![crate::evidence::record::to_hex(&tsa.anchor)],
			policy: None,
			local_test: true,
			token_file: None,
		}],
	};
	settings::save(&dir.join("evidence"), &settings).expect("settings");
	tsa
}

#[tokio::test]
async fn a_tick_seals_stamps_and_verifies_without_holding_mail() {
	let dir = tempfile::tempdir().expect("tempdir");
	let service = service(dir.path());
	let _tsa = with_tsa(dir.path(), at(DAY + 1, 1)).await;
	Chain::open(service.root())
		.expect("chain")
		.append_at(at(DAY, 1), accepted(1))
		.expect("append");
	let tasks = Tasks::new(Arc::clone(&service)).expect("tasks");
	let status = tasks.tick_following(at(DAY + 1, 1)).await;
	assert_eq!(status.held, None, "{:?}", status.errors);
	assert_eq!((status.days, status.stamped), (1, 1));
	assert!(
		service
			.root()
			.join("checkpoints")
			.join(format!("{}.tsr", Day(DAY).name()))
			.exists()
	);
	assert_eq!(last_status(service.root()).expect("read"), Some(status));
	assert_eq!(service.held(), None);
}

#[tokio::test]
async fn a_broken_chain_holds_transactional_mail_until_acknowledged() {
	let dir = tempfile::tempdir().expect("tempdir");
	let service = service(dir.path());
	let _tsa = with_tsa(dir.path(), at(DAY + 1, 1)).await;
	let chain = Chain::open(service.root()).expect("chain");
	chain.append_at(at(DAY, 1), accepted(1)).expect("append");
	chain.append_at(at(DAY, 2), accepted(2)).expect("append");
	let tasks = Tasks::new(Arc::clone(&service)).expect("tasks");
	assert_eq!(tasks.tick_following(at(DAY + 1, 1)).await.held, None);
	let path = chain.day_file(Day(DAY));
	let text = std::fs::read_to_string(&path).expect("read");
	std::fs::write(&path, text.replacen("Notice 1", "Notice X", 1)).expect("tamper");
	let status = tasks.tick_following(at(DAY + 1, 2)).await;
	let reason = status.held.clone().expect("held");
	assert!(
		reason.starts_with("2026-10-14 line 2: record does not chain"),
		"{reason}"
	);
	assert_eq!(service.held(), Some(reason));
	let key = EvidenceKey::load_or_create(service.root()).expect("key");
	// A break in a sealed day shows twice: the chain, then the seal that no
	// longer matches. Each is accepted on its own.
	let mut accepted = 0;
	for hour in 3..6 {
		let report = verify(
			service.root(),
			&Options {
				from: None,
				to: None,
				anchors: Vec::new(),
				now: at(DAY + 1, 2),
			},
		)
		.expect("verify");
		let Some(at_break) = report.first_break else {
			break;
		};
		crate::evidence::ack::acknowledge_at(
			service.root(),
			&key,
			&at_break,
			"restored from backup, see ticket 12",
			&crate::evidence::ack::Operator::named("uid=0 host=mail"),
			at(DAY + 1, hour),
		)
		.expect("acknowledge");
		accepted += 1;
	}
	assert_eq!(accepted, 2, "the chain and the seal");
	let status = tasks.tick_following(at(DAY + 1, 6)).await;
	assert_eq!(status.held, None);
	assert_eq!(status.acknowledged, 2);
	assert_eq!(service.held(), None);
}

#[tokio::test]
async fn a_token_still_being_requested_is_reported_not_held() {
	let dir = tempfile::tempdir().expect("tempdir");
	let service = service(dir.path());
	let tsa = with_tsa(dir.path(), at(DAY + 1, 1)).await;
	Chain::open(service.root())
		.expect("chain")
		.append_at(at(DAY, 1), accepted(1))
		.expect("append");
	drop(tsa);
	// An authority that refuses: the day is sealed, its token is missing.
	let refusing = Arc::new({
		let mut tsa = FakeTsa::new(at(DAY + 1, 1));
		tsa.faults.refuse = Some(2);
		tsa
	});
	let url = Arc::clone(&refusing).serve().await;
	let mut current = settings::load(service.root()).expect("settings");
	current.authorities[0].url = url;
	settings::save(service.root(), &current).expect("save");
	let tasks = Tasks::new(Arc::clone(&service)).expect("tasks");
	let status = tasks.tick_following(at(DAY + 1, 1)).await;
	assert_eq!(status.held, None);
	assert!(status.pending.expect("pending").contains("not timestamped"));
	// Three days later it is no longer pending: it holds.
	let status = tasks.tick_following(at(DAY + 5, 0)).await;
	assert!(status.held.is_some());
}

#[tokio::test]
async fn settings_that_turn_untrustworthy_keep_the_last_good_ones() {
	let dir = tempfile::tempdir().expect("tempdir");
	let service = service(dir.path());
	let tasks = Tasks::new(Arc::clone(&service)).expect("tasks");
	std::fs::write(service.root().join("timestamp.json"), "{").expect("corrupt");
	use std::os::unix::fs::PermissionsExt;
	std::fs::set_permissions(
		service.root().join("timestamp.json"),
		std::fs::Permissions::from_mode(0o600),
	)
	.expect("chmod");
	let status = tasks.tick_following(at(DAY, 1)).await;
	assert!(
		status
			.errors
			.iter()
			.any(|error| error.starts_with("timestamp settings refused"))
	);
	assert!(
		tasks.settings.lock().expect("lock").enabled,
		"the last good settings stayed"
	);
	assert!(
		Tasks::new(service).is_err(),
		"no last good copy at start: refuse"
	);
}

#[tokio::test]
async fn a_check_that_runs_too_long_holds_mail_and_is_not_started_twice() {
	let dir = tempfile::tempdir().expect("tempdir");
	let service = service(dir.path());
	let tasks = Tasks::new(Arc::clone(&service))
		.expect("tasks")
		.with_audit_timeout(Duration::from_millis(20), Duration::from_millis(400));
	service.set_gate(None);
	let status = tasks.tick_following(at(DAY, 1)).await;
	let held = status.held.expect("held");
	assert!(held.contains("took longer than"), "{held}");
	assert_eq!(service.held(), Some(held));
	let again = tasks.tick_following(at(DAY, 2)).await;
	assert_eq!(
		again.held.as_deref(),
		Some("the previous evidence check is still running")
	);
}

#[tokio::test]
async fn a_seal_that_keeps_failing_holds_mail_once_its_grace_passes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let service = service(dir.path());
	let _tsa = with_tsa(dir.path(), at(DAY + 1, 1)).await;
	Chain::open(service.root())
		.expect("chain")
		.append_at(at(DAY, 1), accepted(1))
		.expect("append");
	// An unreadable signing key: sealing fails, even as root, while the
	// verification (which needs only the public key) still runs.
	EvidenceKey::load_or_create(service.root()).expect("key");
	std::fs::write(service.root().join("key.pk8"), b"not a key").expect("corrupt");
	let tasks = Tasks::new(Arc::clone(&service)).expect("tasks");
	let early = tasks.tick_following(at(DAY + 1, 0)).await;
	assert!(
		early
			.errors
			.iter()
			.any(|error| error.starts_with("evidence key")),
		"{:?}",
		early.errors
	);
	assert_eq!(early.held, None, "within the seal grace");
	let late = tasks.tick_following(at(DAY + 1, 2)).await;
	assert!(
		late.held.is_some(),
		"a day left unsealed past its grace holds mail"
	);
	assert!(service.held().is_some());
}

#[tokio::test]
async fn the_status_file_cannot_open_the_gate() {
	let dir = tempfile::tempdir().expect("tempdir");
	let service = service(dir.path());
	let chain = Chain::open(service.root()).expect("chain");
	chain.append_at(at(DAY, 1), accepted(1)).expect("append");
	chain.append_at(at(DAY, 2), accepted(2)).expect("append");
	let path = chain.day_file(Day(DAY));
	let text = std::fs::read_to_string(&path).expect("read");
	std::fs::write(&path, text.replacen("Notice 1", "Notice X", 1)).expect("tamper");
	let tasks = Tasks::new(Arc::clone(&service)).expect("tasks");
	assert!(tasks.tick_following(at(DAY, 3)).await.held.is_some());
	let opened = Status {
		time: at(DAY, 3),
		..Status::default()
	};
	std::fs::write(
		service.root().join(STATUS_FILE),
		serde_json::to_vec(&opened).expect("json"),
	)
	.expect("write");
	assert!(
		service.held().is_some(),
		"the gate is in memory, not in the report"
	);
}
