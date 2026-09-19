//! Bayesian corpus startup wiring, split out so `serve_tasks.rs` stays
//! under the line limit.

use std::sync::Arc;

use crate::config::Config;

/// Open the Bayesian store over `pool` and start the one training worker
/// of the process. `None` without a database. A corpus key that cannot
/// be read or created stops the start (fail closed).
pub fn open_bayes(
	config: &Config,
	pool: &Option<sqlx::PgPool>,
	crypto: &crate::storage::MessageCrypto,
	metrics: &Arc<crate::metrics::Metrics>,
) -> std::io::Result<
	Option<(
		crate::antispam::corpus::BayesStore,
		crate::antispam::training_queue::TrainingQueue,
	)>,
> {
	let Some(pool) = pool else {
		return Ok(None);
	};
	let store = crate::antispam::corpus::BayesStore::open(pool.clone(), &config.data_dir)
		.inspect_err(|error| eprintln!("error: cannot open bayes corpus key: {error}"))?;
	let queue = crate::antispam::training_queue::TrainingQueue::start(
		Arc::new(store.clone()),
		crypto.clone(),
		Arc::clone(metrics),
	);
	Ok(Some((store, queue)))
}
