//! Per-action handlers for `epistle account …`.
//!
//! Lives in a sibling so `account.rs` stays under the per-file code-line
//! budget. Every function takes a pre-built [`AccountStore`] so the test
//! harness can drive the mutators end-to-end without spinning up a
//! real epistle server; the dispatcher in `account::run` opens the
//! store once per call and hands it down here.

use std::process::ExitCode;

use crate::config::Protocol;
use crate::directory_store::{AccountStore, DynamicAccount, StoreError};

use super::style;
use crate::cli::util::read_line;

/// Pretty rendering of a `DynamicAccount` for `account show`. The
/// fields here are exactly the ones a release / wire operator wants to
/// read; secrets (password hash, SCRAM credentials, TOTP secret) are
/// deliberately omitted.
pub(crate) fn render(account: &DynamicAccount, out: &mut impl std::io::Write) {
	let _ = writeln!(out, "name: {}", account.name);
	let _ = writeln!(out, "log_id: {}", crate::log_id::account(&account.name));
	let _ = writeln!(out, "source: dynamic");
	let _ = writeln!(out, "addresses: {}", account.addresses.join(","));
	let _ = writeln!(
		out,
		"disabled: {}",
		if account.disabled { "yes" } else { "no" }
	);
	let quota = match account.quota_bytes {
		Some(bytes) => bytes.to_string(),
		None => "server default".to_string(),
	};
	let _ = writeln!(out, "quota_bytes: {quota}");
	let _ = writeln!(
		out,
		"protocols: {}",
		render_protocols(account.allowed_protocols.as_ref())
	);
}

/// Render the protocol allowlist. `None` is the pre-restriction
/// behaviour (every protocol authenticates); an empty list is the
/// "no protocol authenticates" case the SCIM `set protocols []`
/// path produces.
pub(crate) fn render_protocols(allowed: Option<&Vec<Protocol>>) -> String {
	match allowed {
		None => "all".to_string(),
		Some(list) if list.is_empty() => "none".to_string(),
		Some(list) => list
			.iter()
			.map(|protocol| protocol.as_str())
			.collect::<Vec<_>>()
			.join(","),
	}
}

/// Update the password for a dynamic account using the given store and
/// password reader. Splits the dispatcher from the CLI glue so tests
/// can drive the password flow without touching stdin.
pub(crate) fn password_with_store(
	store: &AccountStore,
	name: &str,
	reader: impl std::io::BufRead,
) -> ExitCode {
	let Ok(plain) = read_line(reader) else {
		return ExitCode::FAILURE;
	};
	if let Err(rejection) = crate::password::validate(&plain) {
		style::error(rejection.message());
		return ExitCode::FAILURE;
	}
	let hash = match crate::smtp::auth::hash_password(&plain) {
		Ok(hash) => hash,
		Err(error) => {
			style::error(format_args!("account {name}: {error}"));
			return ExitCode::FAILURE;
		}
	};
	let scram = match crate::smtp::scram::ScramStored::with_fresh_salt(&plain) {
		Some(scram) => scram,
		None => {
			style::error(format_args!("account {name}: cannot derive SCRAM salt"));
			return ExitCode::FAILURE;
		}
	};
	match store.set_password_hash(name, hash, Some(scram)) {
		Ok(()) => {
			println!("updated password for {name}");
			ExitCode::SUCCESS
		}
		Err(error) => handle_error(name, error),
	}
}

pub(crate) fn disable_with_store(store: &AccountStore, name: &str) -> ExitCode {
	match store.set_disabled(name, true) {
		Ok(previous) => {
			let state = if previous {
				"already disabled"
			} else {
				"disabled"
			};
			println!("{state} {name}");
			ExitCode::SUCCESS
		}
		Err(error) => handle_error(name, error),
	}
}

pub(crate) fn enable_with_store(store: &AccountStore, name: &str) -> ExitCode {
	match store.set_disabled(name, false) {
		Ok(previous) => {
			let state = if previous {
				"enabled"
			} else {
				"already enabled"
			};
			println!("{state} {name}");
			ExitCode::SUCCESS
		}
		Err(error) => handle_error(name, error),
	}
}

pub(crate) fn address_add_with_store(store: &AccountStore, name: &str, address: &str) -> ExitCode {
	match store.add_address(name, address) {
		Ok(()) => {
			println!("added address {address} for {name}");
			ExitCode::SUCCESS
		}
		Err(error) => handle_error(name, error),
	}
}

pub(crate) fn address_remove_with_store(
	store: &AccountStore,
	name: &str,
	address: &str,
) -> ExitCode {
	match store.remove_address(name, address) {
		Ok(()) => {
			println!("removed address {address} for {name}");
			ExitCode::SUCCESS
		}
		Err(error) => handle_error(name, error),
	}
}

pub(crate) fn quota_with_store(store: &AccountStore, name: &str, size: Option<u64>) -> ExitCode {
	match store.set_quota_bytes(name, size) {
		Ok(previous) => {
			let previous_text = match previous {
				Some(bytes) => bytes.to_string(),
				None => "server default".to_string(),
			};
			let new_text = match size {
				Some(bytes) => bytes.to_string(),
				None => "server default".to_string(),
			};
			println!("quota for {name}: {previous_text} -> {new_text}");
			ExitCode::SUCCESS
		}
		Err(error) => handle_error(name, error),
	}
}

pub(crate) fn protocols_with_store(
	store: &AccountStore,
	name: &str,
	allowed: Option<Vec<Protocol>>,
) -> ExitCode {
	match store.set_allowed_protocols(name, allowed.clone()) {
		Ok(previous) => {
			let previous_text = render_protocols(previous.as_ref());
			let new_text = render_protocols(allowed.as_ref());
			println!("protocols for {name}: {previous_text} -> {new_text}");
			ExitCode::SUCCESS
		}
		Err(error) => handle_error(name, error),
	}
}

/// Print the name of every account whose log pseudonym is `id`. A login
/// that was an address (SMTP and IMAP clients often present one) is
/// pseudonymised as a whole, so an account also matches when one of its
/// addresses does. A miss prints nothing and fails.
pub(crate) fn find_log_id_with_store(
	store: &AccountStore,
	id: &str,
	out: &mut impl std::io::Write,
) -> ExitCode {
	let id = id.trim().to_ascii_lowercase();
	let mut views = store.account_views();
	views.sort_by(|a, b| a.0.cmp(&b.0));
	let mut found = false;
	for (name, addresses, _) in &views {
		let matches = crate::log_id::account(name) == id
			|| addresses
				.iter()
				.any(|address| crate::log_id::account(address) == id);
		if matches {
			found = true;
			let _ = writeln!(out, "{name}");
		}
	}
	if !found {
		style::error("no account matches that log id on this server");
		return ExitCode::FAILURE;
	}
	ExitCode::SUCCESS
}

pub(crate) fn show_with_store(
	store: &AccountStore,
	name: &str,
	out: &mut impl std::io::Write,
) -> ExitCode {
	match store.dynamic(name) {
		Some(account) => {
			render(&account, out);
			ExitCode::SUCCESS
		}
		None => handle_error(name, StoreError::NotFound(name.to_string())),
	}
}

/// Convert a store error into the exit code plus the message the
/// operator sees on stderr. Static-account errors carry a hint that
/// tells the operator to edit the config file; the mutators return
/// `NotFound` for both static and unknown names, but every action here
/// already calls `is_static` first to disambiguate.
pub(crate) fn handle_error(name: &str, error: StoreError) -> ExitCode {
	match error {
		StoreError::NotFound(_) => {
			style::error(format_args!(
				"account {name}: edit the config file to change a static account"
			));
			ExitCode::FAILURE
		}
		StoreError::Duplicate(what) => {
			style::error(format_args!("account {name}: {what} already exists"));
			ExitCode::FAILURE
		}
		StoreError::Invalid(message) => {
			style::error(format_args!("account {name}: {message}"));
			ExitCode::FAILURE
		}
		StoreError::Io(error) => {
			style::error(format_args!("account {name}: {error}"));
			ExitCode::FAILURE
		}
		other => {
			style::error(format_args!("account {name}: {other}"));
			ExitCode::FAILURE
		}
	}
}
