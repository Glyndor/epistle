//! Database integration tests. These need a real PostgreSQL and only run when
//! `DATABASE_URL` is set (the `Database` CI workflow provides one); otherwise
//! they skip so the default test run needs no database.

/// The connection URL, or `None` when no database is configured for this run.
fn database_url() -> Option<String> {
	std::env::var("DATABASE_URL").ok().filter(|u| !u.is_empty())
}

#[tokio::test]
async fn migrations_apply_and_reputation_roundtrips() {
	let Some(url) = database_url() else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};

	let pool = mail::db::connect(&url, 5)
		.await
		.expect("connect and migrate");

	// A fresh insert and read-back exercises the migrated schema end to end.
	let id = uuid::Uuid::now_v7();
	sqlx::query("INSERT INTO reputation (id, scope, value, ham_count) VALUES ($1, $2, $3, $4)")
		.bind(id)
		.bind("domain")
		.bind("example.org")
		.bind(3_i64)
		.execute(&pool)
		.await
		.expect("insert reputation");

	let (scope, ham): (String, i64) =
		sqlx::query_as("SELECT scope, ham_count FROM reputation WHERE id = $1")
			.bind(id)
			.fetch_one(&pool)
			.await
			.expect("read reputation");
	assert_eq!(scope, "domain");
	assert_eq!(ham, 3);

	// Clean up so reruns against a persistent database stay deterministic.
	sqlx::query("DELETE FROM reputation WHERE id = $1")
		.bind(id)
		.execute(&pool)
		.await
		.expect("cleanup");
}
