//! `epistle queue undo`: the messages held by the send delay
//! (`[queue.undo_send]`), before anything of them is delivered.
//!
//! The operator sees who sent each and when it goes out, never its content,
//! and may cancel one. The running server reads the same directory on every
//! pass, so a cancellation here reaches it without a restart.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use clap::Subcommand;
use serde::Serialize;
use uuid::Uuid;

use crate::config::Storage;
use crate::storage::MessageCrypto;
use crate::storage::undo::{CancelError, Canceller, UndoStore};

/// Actions on the held submissions.
#[derive(Debug, Subcommand)]
pub enum UndoCli {
	/// List the held messages: id, sender account and release time.
	List {
		/// Print one JSON array instead of text lines.
		#[arg(long)]
		json: bool,
	},
	/// Cancel a held message so nothing of it is delivered.
	Cancel {
		/// The id the sender was given for the message.
		id: Uuid,
	},
}

#[derive(Serialize)]
struct Row {
	id: String,
	account: String,
	release_at: u64,
	seconds_left: u64,
}

/// Run one action against the store under `data_dir`.
pub(super) fn run(
	data_dir: &Path,
	storage: Option<&Storage>,
	action: UndoCli,
	json: bool,
	now: u64,
	out: &mut impl Write,
) -> ExitCode {
	let store = match MessageCrypto::from_config(storage)
		.map_err(std::io::Error::other)
		.and_then(|crypto| UndoStore::open(data_dir, crypto))
	{
		Ok(store) => store,
		Err(error) => return super::fail(format_args!("opening the held messages: {error}")),
	};
	match action {
		UndoCli::List { json: leaf } => list(&store, leaf || json, now, out),
		UndoCli::Cancel { id } => cancel(&store, id, json, out),
	}
}

fn list(store: &UndoStore, json: bool, now: u64, out: &mut impl Write) -> ExitCode {
	let pending = match store.pending() {
		Ok(pending) => pending,
		Err(error) => return super::fail(format_args!("reading the held messages: {error}")),
	};
	let rows: Vec<Row> = pending
		.into_iter()
		.map(|(held, account)| Row {
			id: held.id.to_string(),
			account,
			release_at: held.release_at,
			seconds_left: held.release_at.saturating_sub(now),
		})
		.collect();
	if json {
		let _ = writeln!(
			out,
			"{}",
			serde_json::to_string(&rows).unwrap_or_else(|_| "[]".into())
		);
		return ExitCode::SUCCESS;
	}
	for row in &rows {
		let _ = writeln!(
			out,
			"{}\taccount={}\treleases in {}s",
			row.id,
			crate::cli::term::sanitize(&row.account),
			row.seconds_left
		);
	}
	let _ = writeln!(out, "{} held", rows.len());
	ExitCode::SUCCESS
}

fn cancel(store: &UndoStore, id: Uuid, json: bool, out: &mut impl Write) -> ExitCode {
	match store.cancel_now(id, Canceller::Operator) {
		Ok(()) => {
			let mut report = super::super::json_out::Report::new(out, json);
			report.line(format_args!("cancelled {id}"));
			let fields = serde_json::json!({ "id": id.to_string() });
			report.change("undo-cancel", true, fields, None)
		}
		Err(CancelError::NotFound) => {
			super::super::exit::refused(format_args!("no such held message: {id}"))
		}
		Err(CancelError::AlreadySent) => super::super::exit::refused(format_args!(
			"{id} was already handed on and cannot be cancelled; use `queue remove` on its queue entry"
		)),
		Err(CancelError::Io(error)) => super::fail(format_args!("held message {id}: {error}")),
	}
}
