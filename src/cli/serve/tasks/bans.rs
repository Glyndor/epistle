//! Ban sweep and greylist store wiring for `serve`.

use std::sync::Arc;

use crate::antispam::PgGreylistStore;
use crate::antispam::bans::BanStore;
use crate::antispam::greylist::GreylistStore;
use crate::config::Config;

/// Hourly ban sweep: drops `auth_failure` rows older than 24 hours and
/// `auth_ban` rows whose `until` is older than 24 hours ago, so the ban
/// tables stay bounded. No-op when no database is configured; the ban
/// store is absent in that case. The `known_network_window_secs` from
/// `[limits] known-network-window` is plumbed in so the bypass list ages
/// by what the operator configured, not by the 30-day default.
pub(in crate::cli::serve) fn spawn_ban_sweep(
	pool: Option<sqlx::PgPool>,
	known_network_window_secs: u64,
) {
	let Some(pool) = pool else {
		return;
	};
	tokio::spawn(async move {
		let mut ticker = tokio::time::interval(std::time::Duration::from_secs(3600));
		ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
		loop {
			ticker.tick().await;
			let now = std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH)
				.map(|d| d.as_secs())
				.unwrap_or(0);
			run_ban_sweep_once(&pool, known_network_window_secs, now).await;
		}
	});
}

/// One pass of the ban sweep, with the configured `known_network_window_secs`.
/// Extracted from [`spawn_ban_sweep`] so a test can drive a sweep with a
/// controlled `now_secs` and observe the configured window without waiting
/// on the hourly ticker.
pub(in crate::cli::serve) async fn run_ban_sweep_once(
	pool: &sqlx::PgPool,
	known_network_window_secs: u64,
	now_secs: u64,
) {
	let policy = crate::antispam::bans::BanPolicy {
		known_network_window_secs,
		..crate::antispam::bans::BanPolicy::default()
	};
	let store = crate::antispam::bans::PgBanStore::with_policy(pool.clone(), None, policy);
	store.sweep(now_secs).await;
}

/// Build the shared greylist store when `greylist_delay_secs` is set. With
/// a configured `[database]` the state lives in PostgreSQL and survives a
/// restart; without one, the in-memory store is used and the operator gets
/// a startup line saying so. In either case the hourly sweep drops triplets
/// older than a day so the table never grows without bound. `None` when
/// greylisting is disabled.
pub(in crate::cli::serve) async fn build_greylist(
	config: &Config,
	pool: Option<&sqlx::PgPool>,
) -> Option<Arc<dyn crate::antispam::greylist::GreylistStore>> {
	if config.greylist_delay_secs == 0 {
		return None;
	}
	// Lifetime in seconds for an unseen triplet. Matches the memory store's
	// historical default (one day); the constant lives here so the
	// sweep task and the SQL store agree.
	const LIFETIME_SECS: u64 = 24 * 3600;
	let store: Arc<dyn crate::antispam::greylist::GreylistStore> = match pool {
		Some(pool) => {
			tracing::info!("greylist: using PostgreSQL store; triplets survive restarts");
			let pg = Arc::new(PgGreylistStore::new(pool.clone()));
			let store = Arc::clone(&pg) as Arc<dyn crate::antispam::greylist::GreylistStore>;
			tokio::spawn(async move {
				let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
				loop {
					interval.tick().await;
					let now = std::time::SystemTime::now()
						.duration_since(std::time::UNIX_EPOCH)
						.map(|d| d.as_secs())
						.unwrap_or(0);
					pg.sweep(now, LIFETIME_SECS).await;
				}
			});
			store
		}
		None => {
			tracing::warn!(
				"greylist: no [database] configured; using the in-memory store. State is lost on restart, so every legitimate sender waits out the delay once per server reload. Configure [database] to make greylist persistent."
			);
			let mem: Arc<dyn crate::antispam::greylist::GreylistStore> =
				Arc::new(crate::antispam::greylist::MemoryGreylist::new());
			let prune_store = Arc::clone(&mem);
			tokio::spawn(async move {
				let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
				loop {
					interval.tick().await;
					let now = std::time::SystemTime::now()
						.duration_since(std::time::UNIX_EPOCH)
						.map(|d| d.as_secs())
						.unwrap_or(0);
					prune_store.sweep(now, LIFETIME_SECS).await;
				}
			});
			mem
		}
	};
	Some(store)
}
