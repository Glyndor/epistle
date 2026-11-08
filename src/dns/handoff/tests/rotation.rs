//! The rotation through the hand-off: the whole path, from the journal
//! entry to the key that signs, and the case where the other container does
//! not answer.
//!
//! The selector in service at the start is the one the operator configured
//! (`mail`), not one a rotation makes: that is the selector every install
//! starts with, and the one the first rotation has to retire.

use std::sync::Arc;
use std::time::Duration;

use super::super::{HandoffProvider, Server, Writer};
use super::{FakeResolver, FakeZone, configured, domains, zones};
use crate::dkim::domain_rotate::DomainRotator;
use crate::dkim::rotate::{ReloadableSigner, RotationState, Rotator, read_state};
use crate::dkim::{Signer, generate_key};

/// A day, the unit the rotation counts in.
const DAY: u64 = 86_400;

/// The overlap window the retired selector stays published for.
const OVERLAP: u64 = 14 * DAY;

/// How long a write waits for its answer in these tests.
const WAIT: Duration = Duration::from_millis(500);

/// The rotation of the `[dkim]` key, over a hand-off in a temp directory.
struct Fixture {
	/// The temporary directory, kept alive by the fixture.
	_dir: tempfile::TempDir,
	/// The data directory.
	data_dir: std::path::PathBuf,
	/// The rotator.
	rotator: Rotator,
	/// The live signer, so the test can see the swap.
	signer: ReloadableSigner,
	/// The zone the certificates container writes.
	zone: Arc<FakeZone>,
}

impl Fixture {
	/// A rotator whose active key is the configured `mail`, with its state
	/// saved.
	fn new() -> Fixture {
		let dir = tempfile::tempdir().expect("tempdir");
		let data_dir = dir.path().to_path_buf();
		let (pem, _) = generate_key().expect("key");
		let active = data_dir.join("dkim-mail.key");
		std::fs::write(&active, &pem).expect("write");
		let signer = Signer::load("mail", &active).expect("load");
		let handle = ReloadableSigner::new(Arc::new(signer));
		let zone = FakeZone::new();
		// The operator published the record of the selector in service.
		zone.seed("mail._domainkey.example.org", "v=DKIM1; k=ed25519; p=old");
		let rotator = Rotator::new(
			data_dir.clone(),
			handle.clone(),
			Arc::new(HandoffProvider::new(
				Writer::new(&data_dir).with_timeout(WAIT),
			)),
			"example.org".to_string(),
			vec!["example.org".to_string()],
			30 * DAY,
			OVERLAP,
		)
		.with_publication_check(Arc::new(FakeResolver::new(zone.clone())), Vec::new());
		let state = RotationState {
			selector: "mail".into(),
			key_file: active,
			rotated_at: 0,
			previous: None,
			pending: None,
			rsa: None,
		};
		std::fs::write(
			data_dir.join("dkim-rotation.json"),
			serde_json::to_vec_pretty(&state).expect("encode"),
		)
		.expect("write state");
		Fixture {
			_dir: dir,
			data_dir,
			rotator,
			signer: handle,
			zone,
		}
	}

	/// The certificates container: it takes the requests and writes them.
	fn serving(&self) -> tokio::task::JoinHandle<()> {
		let server = Server::new(
			self.data_dir.join("dns-handoff"),
			self.zone.clone(),
			zones(),
			domains(),
			configured(),
		)
		.with_poll(Duration::from_millis(5));
		tokio::spawn(server.run())
	}

	/// The saved state of the rotation.
	fn state(&self) -> Option<RotationState> {
		read_state(&self.data_dir).expect("state reads")
	}
}

#[tokio::test]
async fn the_rotation_publishes_through_the_hand_off_and_switches_the_key() {
	let fixture = Fixture::new();
	let serving = fixture.serving();

	let decision = fixture.rotator.tick(31 * DAY).await.expect("the tick");
	assert_eq!(decision, crate::dkim::rotate::Decision::Rotate);

	// The certificates container wrote the record of the new selector.
	let name = "ed31._domainkey.example.org";
	let published = fixture.zone.values(name);
	assert_eq!(
		published.len(),
		1,
		"the record was published: {published:?}"
	);
	assert!(
		published[0].starts_with("v=DKIM1;"),
		"the record is a DKIM key record: {published:?}"
	);
	// The state names the new key and the live signer signs with it.
	let state = fixture.state().expect("the state names the key in service");
	assert_eq!(state.selector, "ed31");
	assert!(state.pending.is_none(), "the rotation is finished");
	assert_eq!(fixture.signer.current().selector(), "ed31");
	// The selector that was in service is the one the operator configured,
	// and it stays published until the overlap window ends.
	let previous = state.previous.expect("the replaced selector");
	assert_eq!(previous.selector, "mail");
	serving.abort();
}

#[tokio::test]
async fn the_rotation_retires_the_configured_selector_through_the_hand_off() {
	let fixture = Fixture::new();
	let serving = fixture.serving();
	fixture
		.rotator
		.tick(31 * DAY)
		.await
		.expect("the first tick");

	// The overlap window ends: the selector the operator configured is
	// retired, and the hand-off has to accept it.
	let decision = fixture
		.rotator
		.tick(31 * DAY + OVERLAP + 1)
		.await
		.expect("the retiring tick");
	assert_eq!(
		decision,
		crate::dkim::rotate::Decision::Retire("mail".to_string())
	);
	assert!(
		fixture
			.zone
			.values("mail._domainkey.example.org")
			.is_empty(),
		"the record of the retired selector is gone: {:?}",
		fixture.zone.records()
	);
	assert!(
		fixture.state().expect("the state").previous.is_none(),
		"the state no longer names the retired selector"
	);
	serving.abort();
}

#[tokio::test]
async fn a_certificates_container_that_does_not_answer_leaves_the_old_key_signing() {
	let fixture = Fixture::new();
	// No certificates container: nothing answers the request.
	let error = fixture
		.rotator
		.tick(31 * DAY)
		.await
		.expect_err("the rotation cannot finish");
	assert!(
		error.to_string().contains("did not answer"),
		"the reason names the missing answer: {error}"
	);
	// The key in service keeps signing, and the journal keeps the rotation
	// so the next tick takes it back.
	assert_eq!(fixture.signer.current().selector(), "mail");
	let state = fixture.state().expect("the state");
	assert_eq!(state.selector, "mail", "the old key is still in service");
	let pending = state.pending.expect("the rotation is journaled");
	assert!(
		pending.withdrawing.is_some(),
		"the rotation is being taken back: {pending:?}"
	);
	// Nothing new was published: the zone still holds only the record of
	// the selector that was in service.
	assert!(
		fixture
			.zone
			.values("ed31._domainkey.example.org")
			.is_empty(),
		"nothing was published: {:?}",
		fixture.zone.records()
	);
	assert_eq!(
		fixture.zone.records().len(),
		1,
		"only the record in service is there: {:?}",
		fixture.zone.records()
	);
}

/// The rotation of a domain's own key, over the same hand-off.
#[tokio::test]
async fn the_rotation_of_a_domain_publishes_through_the_hand_off() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().to_path_buf();
	let key_dir = data_dir.join("keys/dkim/example.org");
	std::fs::create_dir_all(&key_dir).expect("mkdir");
	let (pem, _) = generate_key().expect("key");
	let key_file = key_dir.join("ed25519.pem");
	std::fs::write(&key_file, &pem).expect("write");
	// The key was made long ago, so the interval has elapsed.
	std::fs::File::options()
		.write(true)
		.open(&key_file)
		.expect("open")
		.set_times(std::fs::FileTimes::new().set_modified(std::time::UNIX_EPOCH))
		.expect("mtime");
	// The selector the operator configured for this domain.
	let entry = crate::config::DkimDomain {
		name: "example.org".to_string(),
		selector: "custom".into(),
		key_file: key_file.clone(),
		rsa_selector: None,
		rsa_key_file: None,
	};
	let zone = FakeZone::new();
	let serving = {
		let server = Server::new(
			data_dir.join("dns-handoff"),
			zone.clone(),
			zones(),
			domains(),
			configured(),
		)
		.with_poll(Duration::from_millis(5));
		tokio::spawn(server.run())
	};
	let signer = ReloadableSigner::new(Arc::new(Signer::load("custom", &key_file).expect("load")));
	let rotator = DomainRotator::new(
		data_dir.clone(),
		entry,
		signer.clone(),
		Arc::new(crate::dkim::domain_rotate::HandoffPublisher::new(
			Writer::new(&data_dir).with_timeout(WAIT),
		)),
		Arc::new(FakeResolver::new(zone.clone())),
		Vec::new(),
	)
	.expect("rotator")
	.with_windows(30 * DAY, 5 * DAY);
	rotator.tick(31 * DAY).await.expect("the tick");
	let published = zone.values("own31._domainkey.example.org");
	assert_eq!(
		published.len(),
		1,
		"the record was published: {published:?}"
	);
	assert_eq!(signer.current().selector(), "own31");
	serving.abort();
}
