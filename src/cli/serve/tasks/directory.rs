//! Database connection and SQL/LDAP directory loading for `serve`.

use std::sync::Arc;

use crate::config::Config;

/// Connect to the configured database and apply its migrations, degrading when
/// the database only backs the antispam engine.
///
/// The database plays two roles behind one connection, and only one of them can
/// degrade. Reputation screening and the Bayesian corpus are advisory: without
/// them mail arrives unfiltered, which is worse than filtered but far better
/// than not arriving at all, so an unreachable database leaves the server
/// running with those features off. The SQL directory is not advisory: with
/// `[database] directory = true` the accounts themselves come from SQL, so
/// without the database there is nobody to deliver to and starting would be a
/// silent black hole. That case keeps failing closed.
///
/// The degraded path is announced twice on purpose: a `warn!` for whoever reads
/// the log, and the `database_unavailable` counter so the alert engine in
/// [`crate::alerts`] can act on it without anybody reading anything.
pub(in crate::cli) async fn connect_database(
	config: &Config,
	metrics: &crate::metrics::Metrics,
) -> std::io::Result<Option<sqlx::PgPool>> {
	let Some(db) = &config.database else {
		// No `[database]` at all: warn once about which antispam features
		// need one and are silently off. Mail still flows; the operator
		// sees this in the same startup window every other warning lands
		// in, so a misconfigured install surfaces without log scraping.
		// The warning is omitted when the install is clearly minimal
		// (no greylist, no Bayes, no reputation-aware delivery at all):
		// in that case the absence is not surprising.
		let greylist_off = config.greylist_delay_secs == 0;
		let subjectpass_off = !config.subjectpass.enabled;
		if !greylist_off || !subjectpass_off {
			tracing::warn!(
				"antispam: no [database] configured. The Bayes classifier, \
				 per-domain reputation, persistent auth-ban storage, and \
				 greylist persistence are off; mail flows unfiltered. \
				 Add [database] to enable them."
			);
		}
		return Ok(None);
	};
	match crate::db::connect(
		&db.url,
		db.tls,
		db.max_connections,
		db.password_file.as_deref(),
	)
	.await
	{
		Ok(pool) => Ok(Some(pool)),
		// Fatal: the directory backend resolves recipients from this database.
		Err(error) if db.directory => Err(std::io::Error::other(format!(
			"cannot reach the database, and `[database] directory = true` means the \
			 mail accounts are resolved from it: starting would leave nobody to \
			 deliver to. This failure is fatal for that reason only; with \
			 `directory = false` the same failure merely disables the antispam \
			 engine. Cause: {error}"
		))),
		Err(error) => {
			metrics.database_unavailable();
			tracing::warn!(
				%error,
				"cannot reach the database: starting without the antispam engine. \
				 Reputation screening and the Bayesian corpus are disabled and mail \
				 is accepted unfiltered. Account resolution is unaffected because \
				 `[database] directory` is off."
			);
			Ok(None)
		}
	}
}

/// Load the SQL directory accounts into the store once, then spawn an hourly
/// refresh task. A no-op unless `[database] directory = true` and a reputation
/// pool is present. The initial load fails closed (a fatal startup error) so the
/// server never runs with a silently empty SQL directory; later refresh failures
/// keep the previously loaded accounts. Account precedence (static and dynamic
/// over SQL) is handled by [`crate::directory_store::AccountStore`].
pub(in crate::cli::serve) async fn spawn_sql_directory(
	config: &Config,
	pool: &Option<sqlx::PgPool>,
	store: Arc<crate::directory_store::AccountStore>,
) -> std::io::Result<()> {
	let (Some(true), Some(pool)) = (config.database.as_ref().map(|db| db.directory), pool) else {
		return Ok(());
	};
	let accounts = crate::directory_store::load_sql_accounts(pool)
		.await
		.map_err(|error| std::io::Error::other(format!("sql directory load: {error}")))?;
	tracing::info!(count = accounts.len(), "loaded SQL directory accounts");
	store.set_sql_accounts(accounts);
	let pool = pool.clone();
	tokio::spawn(async move {
		let mut ticker = tokio::time::interval(std::time::Duration::from_secs(3600));
		ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
		loop {
			ticker.tick().await;
			match crate::directory_store::load_sql_accounts(&pool).await {
				Ok(accounts) => store.set_sql_accounts(accounts),
				Err(error) => tracing::warn!(%error, "sql directory refresh failed"),
			}
		}
	});
	Ok(())
}

/// Build the live LDAP authenticator from `[ldap]`, or `None` when no section is
/// present. Attached to the store at construction so per-request binds (including
/// for LDAP-only logins) work before the first resolution load completes.
pub(in crate::cli::serve) fn build_ldap_authenticator(
	config: &Config,
) -> Option<Arc<crate::directory_store::LdapAuthenticator>> {
	config
		.ldap
		.clone()
		.map(|ldap| Arc::new(crate::directory_store::LdapAuthenticator::new(ldap)))
}

/// Load+refresh the LDAP resolution accounts into the store. A no-op unless an
/// `[ldap]` section is present. The initial resolution load fails closed (a fatal
/// startup error) so the server never runs with a silently empty LDAP directory;
/// later refreshes keep the previous set. Account precedence (static/dynamic/SQL
/// over LDAP) is handled by [`crate::directory_store::AccountStore`].
pub(in crate::cli::serve) async fn spawn_ldap_directory(
	config: &Config,
	store: Arc<crate::directory_store::AccountStore>,
) -> std::io::Result<()> {
	let Some(ldap) = config.ldap.clone() else {
		return Ok(());
	};
	let initial = load_ldap_blocking(ldap.clone())
		.await
		.map_err(|error| std::io::Error::other(format!("ldap directory load: {error}")))?;
	tracing::info!(count = initial.len(), "loaded LDAP directory accounts");
	store.set_ldap_accounts(initial);
	let refresh = std::time::Duration::from_secs(ldap.refresh_secs);
	let task_store = Arc::clone(&store);
	tokio::spawn(async move {
		let mut ticker = tokio::time::interval(refresh);
		ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
		loop {
			ticker.tick().await;
			match load_ldap_blocking(ldap.clone()).await {
				Ok(accounts) => task_store.set_ldap_accounts(accounts),
				Err(error) => tracing::warn!(%error, "ldap directory refresh failed"),
			}
		}
	});
	Ok(())
}

/// Run the blocking LDAP resolution search on a blocking thread so the async
/// runtime is never stalled by the synchronous ldap3 I/O.
async fn load_ldap_blocking(
	ldap: crate::config::Ldap,
) -> std::io::Result<Vec<crate::directory_store::LdapAccount>> {
	tokio::task::spawn_blocking(move || crate::directory_store::load_ldap_accounts(&ldap))
		.await
		.map_err(std::io::Error::other)?
		.map_err(std::io::Error::other)
}
