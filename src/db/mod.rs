//! PostgreSQL access for the antispam subsystem.
//!
//! The mail server itself is filesystem-first; the database backs only the
//! antispam engine (reputation and, later, the statistical classifier). The
//! pool is created lazily and migrations are applied at startup.

use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

/// Errors from database setup.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
	#[error("database connection failed: {0}")]
	Connect(#[source] sqlx::Error),
	#[error("database migration failed: {0}")]
	Migrate(#[source] sqlx::migrate::MigrateError),
}

/// Connect to PostgreSQL and apply all pending migrations. The pool is bounded
/// so a misbehaving database cannot exhaust connections.
pub async fn connect(url: &str, max_connections: u32) -> Result<PgPool, DbError> {
	let pool = PgPoolOptions::new()
		.max_connections(max_connections)
		.connect(url)
		.await
		.map_err(DbError::Connect)?;
	migrate(&pool).await?;
	Ok(pool)
}

/// Apply the embedded migrations to an existing pool.
pub async fn migrate(pool: &PgPool) -> Result<(), DbError> {
	sqlx::migrate!("./migrations")
		.run(pool)
		.await
		.map_err(DbError::Migrate)
}
