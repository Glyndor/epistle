//! Two writers of one zone do not interleave.
//!
//! The reconcile loop and the certificate rotation write the same zone,
//! and nothing kept them apart: a value the rotation published could be
//! overwritten by a plan the loop made against an older listing, and the
//! zone would name the certificate it named before. Both take the lock of
//! the zone (see [`crate::dns::zone_lock`]), and the lock is held for the
//! whole read-modify-write of the zone, so one writer is never inside the
//! provider while the other one is.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::run::block;
use crate::config::Config;
use crate::dns::provider::{DnsProvider, DnsRecord};

/// The zone every writer of this test publishes in.
const ZONE: &str = "example.org";

/// The mail host whose TLSA record the rotation publishes.
const HOST: &str = "mail.example.org";

/// A provider that records the entry and the exit of every write and
/// yields in the middle of it: without a lock between the writers, the
/// second one gets in while the first is still inside.
struct Phases {
	/// The events, in order: `enter` and `exit`.
	events: Mutex<Vec<&'static str>>,
	/// The records the zone holds.
	records: Mutex<Vec<DnsRecord>>,
}

impl Phases {
	fn new() -> Self {
		Phases {
			events: Mutex::new(Vec::new()),
			records: Mutex::new(Vec::new()),
		}
	}

	/// The events, in order.
	fn events(&self) -> Vec<&'static str> {
		self.events.lock().expect("events").clone()
	}

	/// Whether two writes were inside the provider at the same time.
	fn interleaved(&self) -> bool {
		let mut inside = false;
		for event in self.events() {
			match event {
				"enter" => {
					if inside {
						return true;
					}
					inside = true;
				}
				_ => inside = false,
			}
		}
		false
	}
}

impl DnsProvider for Phases {
	fn upsert(&self, _zone: &str, record: DnsRecord) -> crate::dns::provider::Op<'_> {
		Box::pin(async move {
			self.events.lock().expect("events").push("enter");
			// The other writer gets a chance to start here.
			tokio::task::yield_now().await;
			self.records.lock().expect("records").push(record);
			self.events.lock().expect("events").push("exit");
			Ok(())
		})
	}
	fn delete(&self, _zone: &str, _record: DnsRecord) -> crate::dns::provider::Op<'_> {
		Box::pin(async { Ok(()) })
	}
	fn list(&self, _zone: &str) -> crate::dns::provider::ListOp<'_> {
		// The provider holds one zone and names no zone of its own: it
		// answers for every name, so the two writers name the same zone
		// differently (the reconcile loop by the domain, the rotation by
		// the mail host).
		let records = self.records.lock().expect("records").clone();
		Box::pin(async move { Ok(records) })
	}
	fn has_zone<'a>(&'a self, _zone: &'a str) -> crate::dns::provider::ZoneOp<'a> {
		Box::pin(async move { Ok(true) })
	}
}

/// The reconcile loop and the certificate rotation write the same zone at
/// the same time: their writes do not interleave.
#[test]
fn the_reconcile_loop_and_the_rotation_do_not_interleave_their_writes() {
	let dir = tempfile::tempdir().expect("directory");
	let config: Config = toml::from_str(&format!(
		"hostname = '{HOST}'\ndata_dir = {:?}\ndomains = ['{ZONE}']\n\
		 [dns]\nprovider = 'cloudflare'\nzone = '{ZONE}'\ntoken = 'inline-token'\n",
		dir.path()
	))
	.expect("config");
	let provider = Arc::new(Phases::new());
	// The certificate the rotation publishes the association of.
	let certified =
		rcgen::generate_simple_self_signed(vec![HOST.to_string()]).expect("certificate");
	let pem = certified.cert.pem();
	let target = crate::dns::tlsa::Target {
		provider: Some(provider.as_ref()),
		hostname: HOST,
		data_dir: &config.data_dir,
	};
	block(async {
		let (run, rotation) = tokio::join!(
			crate::dns::reconcile::once::run(
				&config,
				provider.as_ref(),
				1_800_000_000,
				Duration::from_secs(5),
			),
			crate::dns::tlsa::refresh(&target, &pem, None, 1_800_000_000),
		);
		assert!(run.is_ok(), "the reconcile run went through: {run:?}");
		assert!(
			matches!(rotation, crate::dns::tlsa::Outcome::Published { .. }),
			"the rotation published: {rotation:?}"
		);
	});
	let events = provider.events();
	assert!(
		!provider.interleaved(),
		"the two writers were inside the provider at the same time: {events:?}"
	);
	assert!(events.len() >= 4, "the two writers did write: {events:?}");
}
