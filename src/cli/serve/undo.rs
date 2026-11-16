//! Undo send at start-up: open the held submissions, release what is due,
//! and put the holding sink in front of the submission path when some scope
//! holds anything.

use std::sync::Arc;

use crate::config::Config;
use crate::directory_store::DirectoryHandle;
use crate::smtp::sink::MessageSink;
use crate::storage::MessageCrypto;
use crate::storage::undo::{NoticeStyle, Releaser, UndoPolicy, UndoSink, UndoStore};

/// The sink submissions go through, with `routing` (the sink that delivers
/// local mail and queues the rest) behind it.
///
/// The releaser runs whether or not anything is configured to hold: a
/// submission held before the delay was turned off, or before a restart, is
/// still on disk and still goes out at its time. With every delay at zero
/// the sink is `routing` itself, and a submission is handled the instant it
/// is accepted, as it was before undo send existed.
pub(super) fn wrap(
	config: &Config,
	crypto: &MessageCrypto,
	directory: &DirectoryHandle,
	routing: Arc<dyn MessageSink>,
) -> std::io::Result<Arc<dyn MessageSink>> {
	let store = Arc::new(UndoStore::open(&config.data_dir, crypto.clone())?);
	let identification = crate::smtp::identification::Policy::from_config(config);
	Arc::new(Releaser::new(
		Arc::clone(&store),
		Arc::clone(&routing),
		NoticeStyle {
			hostname: config.hostname.clone(),
			auto_submitted: identification.system_auto_submitted,
			auto_response_suppress: identification.system_auto_response_suppress,
		},
	))
	.spawn();
	let policy = UndoPolicy::from_config(config);
	if policy.is_off() {
		return Ok(routing);
	}
	Ok(Arc::new(UndoSink::new(
		routing,
		store,
		policy,
		directory.clone(),
	)))
}
