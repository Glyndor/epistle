//! The evidence log and the class bindings, opened before any listener.

use std::sync::Arc;

use crate::config::Config;
use crate::evidence::bindings::BindingSet;
use crate::evidence::service::{EvidenceService, reconcile};
use crate::storage::{FsSpool, MessageCrypto};

/// What the server holds for classes and evidence.
pub(super) struct Evidence {
	/// The evidence service the routing sink and the worker record through.
	pub service: Arc<EvidenceService>,
	/// The default classes of accounts and credentials.
	pub bindings: Arc<BindingSet>,
}

/// Open the evidence service and the class bindings, and reconcile what a
/// crash left staged in the spool. Fails closed: bindings or a policy that
/// cannot be trusted stop the start, since no last good copy exists yet.
pub(super) fn open(config: &Config, crypto: &MessageCrypto) -> std::io::Result<Evidence> {
	let tenants = config
		.tenants
		.iter()
		.filter_map(|tenant| Some((tenant.name.clone()?, tenant.domains.clone())))
		.collect();
	let service = Arc::new(EvidenceService::open(
		&config.data_dir,
		tenants,
		crypto.clone(),
	)?);
	let bindings = Arc::new(BindingSet::open(&config.data_dir)?);
	let spool = FsSpool::open_with_crypto(&config.data_dir, crypto.clone())?;
	let reconciled = reconcile(&spool, &service)?;
	if reconciled > 0 {
		tracing::warn!(reconciled, "discarded submissions a stop left half-queued");
	}
	Ok(Evidence { service, bindings })
}
