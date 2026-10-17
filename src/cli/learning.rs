//! `epistle learning`: what the corpus of each account has learned from its
//! user, and the switch that stops it.
//!
//! The server teaches an account's Bayesian corpus when its user moves mail
//! into Junk or out of it, or sets `$Junk` and `$NotJunk` (see
//! [`crate::antispam::learning`]). The counters and the switch live in
//! PostgreSQL, so a change made here reaches the running server on its next
//! lesson, with no restart. Without `[database]` there is no corpus and the
//! command says so.

use std::io::Write;
use std::process::ExitCode;

use clap::Subcommand;
use serde_json::json;

use super::json_out::{Report, dry_run_object};
use crate::antispam::corpus::BayesStore;
use crate::antispam::learning::LearningStats;
use crate::antispam::learning::stats::MAX_LISTED;
use crate::config::Config;
use crate::directory_store::{AccountStore, load_sql_accounts};

/// Learning actions.
#[derive(Debug, Subcommand)]
pub enum LearningCli {
	/// Show what the corpus of each account has learned from its user.
	///
	/// Without an account, every account that has learned or been switched
	/// off. With one, that account (an account that never learned reads as
	/// on, with zero counters).
	Status {
		/// The account to show; all of them when omitted.
		#[arg(value_parser = super::account_name::parse)]
		account: Option<String>,
		/// Print JSON instead of text lines.
		#[arg(long)]
		json: bool,
	},
	/// Let the decisions of an account teach its corpus (the default).
	Enable {
		/// The account to switch on.
		#[arg(value_parser = super::account_name::parse)]
		account: String,
		/// Print what would change and write nothing.
		#[arg(long)]
		dry_run: bool,
		/// Print one JSON object on success.
		#[arg(long)]
		json: bool,
	},
	/// Stop the decisions of an account from teaching its corpus.
	///
	/// What the corpus already learned stays; `reset` drops it.
	Disable {
		/// The account to switch off.
		#[arg(value_parser = super::account_name::parse)]
		account: String,
		/// Print what would change and write nothing.
		#[arg(long)]
		dry_run: bool,
		/// Print one JSON object on success.
		#[arg(long)]
		json: bool,
	},
	/// Drop the corpus of an account and the record of what it learned.
	///
	/// The account scores with the shared corpus again until it has learned
	/// enough of its own. The on/off switch is kept: an account switched off
	/// stays off. Use it when a corpus was taught the wrong thing.
	Reset {
		/// The account whose corpus to drop.
		#[arg(value_parser = super::account_name::parse)]
		account: String,
		/// Print what would be dropped and write nothing.
		#[arg(long)]
		dry_run: bool,
		/// Skip the confirmation.
		#[arg(long, short = 'y')]
		yes: bool,
		/// Print one JSON object on success.
		#[arg(long)]
		json: bool,
	},
}

/// Run one learning action. Data goes to `out`.
pub(super) fn run(config: &Config, action: LearningCli, out: &mut impl Write) -> ExitCode {
	let Some(database) = &config.database else {
		return super::exit::policy(
			"no [database] is configured: the corpus lives in PostgreSQL, so there is nothing to show or switch",
		);
	};
	let runtime = match tokio::runtime::Runtime::new() {
		Ok(runtime) => runtime,
		Err(error) => {
			super::style::error(format_args!("starting runtime: {error}"));
			return ExitCode::FAILURE;
		}
	};
	runtime.block_on(async {
		let pool = match crate::db::connect(
			&database.url,
			database.tls,
			database.max_connections,
			database.password_file.as_deref(),
		)
		.await
		{
			Ok(pool) => pool,
			Err(error) => {
				super::style::error(error);
				return ExitCode::FAILURE;
			}
		};
		let store = match BayesStore::open(pool.clone(), &config.data_dir) {
			Ok(store) => store,
			Err(error) => {
				super::style::error(format_args!("cannot open the corpus key: {error}"));
				return ExitCode::FAILURE;
			}
		};
		match execute(config, &pool, &store, action, out).await {
			Ok(code) => code,
			Err(error) => {
				super::style::error(format_args!("database: {error}"));
				ExitCode::FAILURE
			}
		}
	})
}

async fn execute(
	config: &Config,
	pool: &sqlx::PgPool,
	store: &BayesStore,
	action: LearningCli,
	out: &mut impl Write,
) -> Result<ExitCode, sqlx::Error> {
	match action {
		LearningCli::Status { account, json } => status(store, account, json, out).await,
		LearningCli::Enable {
			account,
			dry_run,
			json,
		} => switch(config, pool, store, &account, true, dry_run, json, out).await,
		LearningCli::Disable {
			account,
			dry_run,
			json,
		} => switch(config, pool, store, &account, false, dry_run, json, out).await,
		LearningCli::Reset {
			account,
			dry_run,
			yes,
			json,
		} => reset(config, pool, store, &account, dry_run, yes, json, out).await,
	}
}

async fn status(
	store: &BayesStore,
	account: Option<String>,
	json: bool,
	out: &mut impl Write,
) -> Result<ExitCode, sqlx::Error> {
	let Some(account) = account else {
		let rows = store.learning_stats_all().await?;
		if let Some(note) = cut_note(rows.len()) {
			super::style::warn(note);
		}
		if json {
			return Ok(super::json_out::print(out, &json!(rows)));
		}
		for row in &rows {
			let _ = writeln!(out, "{}", line(row));
		}
		let _ = writeln!(out, "{} accounts", rows.len());
		return Ok(ExitCode::SUCCESS);
	};
	let row = store.learning_stats(&account).await?;
	if json {
		return Ok(super::json_out::print(out, &json!(row)));
	}
	let _ = writeln!(out, "{}", line(&row));
	Ok(ExitCode::SUCCESS)
}

/// The warning for a listing that stopped at the cap, so a list of exactly
/// that many is not taken for the whole.
fn cut_note(listed: usize) -> Option<String> {
	let cap = usize::try_from(MAX_LISTED).unwrap_or(usize::MAX);
	(listed >= cap).then(|| format!("the list stops at {MAX_LISTED} accounts; name one to see it"))
}

/// `text` with control and invisible characters written as `\u{..}` escapes,
/// so a name read from the database cannot drive the terminal.
fn shown(text: &str) -> String {
	let quoted = format!("{text:?}");
	quoted[1..quoted.len() - 1].to_string()
}

/// One account as a text line: tab-separated `key=value` fields.
fn line(row: &LearningStats) -> String {
	format!(
		"{}\tlearning={}\tspam={}\tham={}\tunlearned={}\trepeated={}\trefused={}\tthrottled={}\tmessages={}\ttoken-rows={}\tunrecorded={}\tcorpus-spam={}\tcorpus-ham={}",
		shown(&row.account),
		if row.enabled { "on" } else { "off" },
		row.spam_learned,
		row.ham_learned,
		row.unlearned,
		row.repeated,
		row.refused,
		row.throttled,
		row.entries,
		row.token_rows,
		row.unrecorded,
		row.corpus_spam,
		row.corpus_ham,
	)
}

/// Whether `name` is an account of this server: in the configuration or the
/// account store, or in the SQL directory.
async fn is_account(config: &Config, pool: &sqlx::PgPool, name: &str) -> Result<bool, String> {
	let store = AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	)
	.map_err(|error| format!("opening account store: {error}"))?;
	if store
		.account_views()
		.iter()
		.any(|(known, _, _)| known == name)
	{
		return Ok(true);
	}
	let sql = load_sql_accounts(pool)
		.await
		.map_err(|error| format!("reading the SQL directory: {error}"))?;
	Ok(sql.iter().any(|account| account.name == name))
}

/// Refuse a name that is not an account, so a typo does not leave a switch
/// behind for an account that does not exist.
async fn require_account(config: &Config, pool: &sqlx::PgPool, name: &str) -> Option<ExitCode> {
	match is_account(config, pool, name).await {
		Ok(true) => None,
		Ok(false) => Some(super::exit::refused(format_args!(
			"no such account: {name}"
		))),
		Err(error) => {
			super::style::error(error);
			Some(ExitCode::FAILURE)
		}
	}
}

#[allow(clippy::too_many_arguments)]
async fn switch(
	config: &Config,
	pool: &sqlx::PgPool,
	store: &BayesStore,
	account: &str,
	enabled: bool,
	dry_run: bool,
	json: bool,
	out: &mut impl Write,
) -> Result<ExitCode, sqlx::Error> {
	if let Some(code) = require_account(config, pool, account).await {
		return Ok(code);
	}
	let action = if enabled { "enable" } else { "disable" };
	let word = if enabled { "on" } else { "off" };
	let before = store.learning_stats(account).await?;
	if dry_run {
		let diff = format!(
			"learning: {} -> {word}",
			if before.enabled { "on" } else { "off" }
		);
		if json {
			let value = dry_run_object(action, json!({ "account": account }), diff);
			return Ok(super::json_out::print(out, &value));
		}
		let _ = writeln!(out, "{diff}");
		return Ok(ExitCode::SUCCESS);
	}
	let changed = store.set_learning(account, enabled).await?;
	let mut report = Report::new(out, json);
	report.line(format_args!(
		"{}: learning {word}{}",
		shown(account),
		if changed { "" } else { " (already)" }
	));
	Ok(report.change(
		action,
		changed,
		json!({ "account": account, "enabled": enabled }),
		None,
	))
}

#[allow(clippy::too_many_arguments)]
async fn reset(
	config: &Config,
	pool: &sqlx::PgPool,
	store: &BayesStore,
	account: &str,
	dry_run: bool,
	yes: bool,
	json: bool,
	out: &mut impl Write,
) -> Result<ExitCode, sqlx::Error> {
	if let Some(code) = require_account(config, pool, account).await {
		return Ok(code);
	}
	let before = store.learning_stats(account).await?;
	if dry_run {
		let diff = format!(
			"drop the corpus of {} ({} spam, {} ham) and {} learned messages",
			shown(account),
			before.corpus_spam,
			before.corpus_ham,
			before.entries
		);
		if json {
			let value = dry_run_object("reset", json!({ "account": account }), diff);
			return Ok(super::json_out::print(out, &value));
		}
		let _ = writeln!(out, "{diff}");
		return Ok(ExitCode::SUCCESS);
	}
	let question = format!(
		"Drop the corpus of {} ({} spam, {} ham messages)? It scores with the shared corpus until it learns again.",
		shown(account),
		before.corpus_spam,
		before.corpus_ham
	);
	if let Err(code) = super::prompt::confirm_destructive("learning-reset", &question, yes) {
		return Ok(code);
	}
	let tokens = store.reset_learning(account).await?;
	let mut report = Report::new(out, json);
	report.line(format_args!(
		"{}: corpus dropped ({tokens} tokens)",
		shown(account)
	));
	Ok(report.change(
		"reset",
		true,
		json!({ "account": account, "tokens": tokens }),
		None,
	))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_listing_at_the_cap_says_it_was_cut() {
		assert_eq!(cut_note(3), None);
		assert_eq!(cut_note(9_999), None);
		assert!(cut_note(10_000).is_some_and(|note| note.contains("10000")));
	}
}
