//! `epistle account …`: in-place mutators on a dynamic account that
//! would otherwise need an `accounts.toml` edit and a server reload.
//!
//! The action list is intentionally narrow: each subcommand maps to a
//! single `AccountStore` mutator, refuses a static account with a
//! message that tells the operator to edit the config file, and
//! returns `ExitCode::SUCCESS` only when the mutator reports success.
//! Anything beyond a thin wrapper here would belong on the store's
//! mutator, not on the CLI handler.
//!
//! The store lives in `<data_dir>/accounts.toml`; the running server
//! watches the file and rebuilds its directory within a few seconds,
//! so no service restart is needed. The watcher reload API is the same
//! one the sibling process drives from `add`, `remove` and
//! `set_password_hash`.

use std::path::Path;
use std::process::ExitCode;

use clap::Subcommand as ClapSubcommand;

use crate::cli::style;
use crate::config::{Config, Protocol};
use crate::directory_store::{AccountStore, StoreError};

mod actions;
mod args;
mod class;
mod dispatch;
mod encryption_key;
mod forward_catch_all;
pub(super) mod json;
pub(super) mod list_aliases;
pub(super) mod name;
mod parse;
pub(super) mod reload;
mod store_access;
mod subcommand;
mod switches;
mod two_factor;
#[allow(unused_imports)]
pub(super) use actions::{
	address_add_with_store, address_remove_with_store, disable_with_store, enable_with_store,
	find_log_id_with_store, handle_error, password_with_store, protocols_changed,
	protocols_with_store, quota_changed, quota_with_store, render, render_protocols,
	save_sent_with_store, set_name_with_store, show_with_store,
};
pub use args::{
	AddressArgs, AddressSubcommand, CatchAllArgs, CatchAllSubcommand, ForwardArgs,
	ForwardSubcommand, TwoFactorArgs, TwoFactorSubcommand,
};
use dispatch::{dispatch_catch_all, dispatch_forward, dispatch_two_factor};
#[allow(unused_imports)]
pub(super) use forward_catch_all::{
	catch_all_add_with_store, catch_all_list, catch_all_remove_with_store, forward_add_with_store,
	forward_list, forward_remove_with_store,
};
pub(super) use parse::{parse_on_off, parse_protocol_list, parse_quota_size};
use store_access::{init_log_id, open_store};
pub(super) use store_access::{prepare, prepare_show};
pub use subcommand::Subcommand;
#[allow(unused_imports)]
pub(super) use two_factor::{two_factor_disable, two_factor_show};
/// Dispatch every `epistle account …` subcommand. The umbrella exists
/// so the operator can `tab-complete` from one root and so the
/// per-action handler signatures stay short.
pub(super) fn run(
	config_path: &Path,
	subcommand: Subcommand,
	json: bool,
	out: &mut impl std::io::Write,
) -> ExitCode {
	// `list`/`add`/`remove` route to the same handlers the flat
	// `accounts`/`account-add`/`account-remove` commands drive, so the two
	// parsers cannot drift. `list` only reads; `add` is the one action that
	// reads from stdin (a new password) and so re-opens its own prompt
	// reader, while `remove` decides the queue policy before it touches
	// anything.
	match subcommand {
		Subcommand::List {
			json: leaf,
			aliases,
		} => {
			let config = match Config::load(config_path) {
				Ok(config) => config,
				Err(error) => {
					style::error(error);
					return ExitCode::FAILURE;
				}
			};
			if leaf || json {
				return crate::cli::account::json::list(&config, aliases, out);
			}
			super::accounts::list_with(&config, aliases, out)
		}
		Subcommand::Add {
			name,
			addresses,
			display_name,
		} => {
			let config = match Config::load(config_path) {
				Ok(config) => config,
				Err(error) => {
					style::error(error);
					return ExitCode::FAILURE;
				}
			};
			super::accounts::add_with_display_name(
				&config,
				&name,
				addresses,
				display_name.as_deref(),
				super::prompt::stdin(),
				out,
				json,
			)
		}
		Subcommand::Remove { name, queue, yes } => {
			let config = match Config::load(config_path) {
				Ok(config) => config,
				Err(error) => {
					style::error(error);
					return ExitCode::FAILURE;
				}
			};
			super::accounts::remove_reporting(&config, &name, queue, yes, out, json)
		}
		Subcommand::Password { name } => {
			let store = match prepare(config_path, &name) {
				Ok(store) => store,
				Err(code) => return code,
			};
			password_with_store(&store, &name, super::prompt::stdin(), out, json)
		}
		Subcommand::SetName { name, display_name } => match prepare(config_path, &name) {
			Ok(store) => set_name_with_store(&store, &name, &display_name, out, json),
			Err(code) => code,
		},
		Subcommand::Disable { name } => {
			let store = match prepare(config_path, &name) {
				Ok(store) => store,
				Err(code) => return code,
			};
			disable_with_store(&store, &name, out, json)
		}
		Subcommand::Enable { name } => {
			let store = match prepare(config_path, &name) {
				Ok(store) => store,
				Err(code) => return code,
			};
			enable_with_store(&store, &name, out, json)
		}
		Subcommand::Address(args) => match args.action {
			AddressSubcommand::Add { name, address } => {
				let store = match prepare(config_path, &name) {
					Ok(store) => store,
					Err(code) => return code,
				};
				address_add_with_store(&store, &name, &address, out, json)
			}
			AddressSubcommand::Remove { name, address } => {
				let store = match prepare(config_path, &name) {
					Ok(store) => store,
					Err(code) => return code,
				};
				address_remove_with_store(&store, &name, &address, out, json)
			}
		},
		Subcommand::Quota { name, size } => {
			let parsed = match parse_quota_size(&size) {
				Ok(size) => size,
				Err(error) => {
					return crate::cli::exit::refused(format_args!("account {name}: {error}"));
				}
			};
			let store = match prepare(config_path, &name) {
				Ok(store) => store,
				Err(code) => return code,
			};
			quota_with_store(&store, &name, parsed, out, json)
		}
		Subcommand::Protocols { name, list } => {
			let parsed = match parse_protocol_list(&list) {
				Ok(list) => list,
				Err(error) => {
					return crate::cli::exit::refused(format_args!("account {name}: {error}"));
				}
			};
			let store = match prepare(config_path, &name) {
				Ok(store) => store,
				Err(code) => return code,
			};
			protocols_with_store(&store, &name, parsed, out, json)
		}
		Subcommand::Set {
			name,
			default_class: Some(class),
			..
		} => crate::cli::account::class::set(config_path, &name, &class, json, out),
		Subcommand::Set {
			name,
			send,
			receive,
			..
		} => {
			let send = match switches::parse(&name, "send", send.as_deref()) {
				Ok(send) => send,
				Err(code) => return code,
			};
			let receive = match switches::parse(&name, "receive", receive.as_deref()) {
				Ok(receive) => receive,
				Err(code) => return code,
			};
			match prepare(config_path, &name) {
				Ok(store) => switches::set(&store, &name, send, receive, out, json),
				Err(code) => code,
			}
		}
		Subcommand::SaveSent { name, state } => {
			let value = match parse_on_off(&state) {
				Ok(value) => value,
				Err(error) => {
					return crate::cli::exit::refused(format_args!("account {name}: {error}"));
				}
			};
			let store = match prepare(config_path, &name) {
				Ok(store) => store,
				Err(code) => return code,
			};
			save_sent_with_store(&store, &name, value, out, json)
		}
		Subcommand::Show { name, json: leaf } => {
			let store = match prepare_show(config_path, &name) {
				Ok(store) => store,
				Err(code) => return code,
			};
			if let Err(code) = init_log_id(config_path) {
				return code;
			}
			let key = encryption_key::describe(config_path, &store, &name);
			if leaf || json {
				return encryption_key::show_json(&store, &name, &key, out);
			}
			let code = show_with_store(&store, &name, out);
			if code == ExitCode::SUCCESS {
				encryption_key::show_line(out, &key);
			}
			code
		}
		Subcommand::FindLogId { log_id } => {
			let config = match Config::load(config_path) {
				Ok(config) => config,
				Err(error) => {
					style::error(error);
					return ExitCode::FAILURE;
				}
			};
			if let Err(error) = crate::log_id::init(&config.data_dir) {
				style::error(format_args!("cannot open the log pseudonym key: {error}"));
				return ExitCode::FAILURE;
			}
			match open_store(&config) {
				Ok(store) => find_log_id_with_store(&store, &log_id, out, json),
				Err(error) => {
					style::error(format_args!("opening account store: {error}"));
					ExitCode::FAILURE
				}
			}
		}
		// `forward` and `catch-all` accept the same umbrella shape, with a
		// dynamic-only mutator behind each: the dispatcher refuses a
		// static account with the config-file hint before any mutator
		// runs, mirroring `account enable`/`disable`.
		Subcommand::Forward(args) => dispatch_forward(args, config_path, json, out),
		Subcommand::CatchAll(args) => dispatch_catch_all(args, config_path, json, out),
		Subcommand::TwoFactor(args) => dispatch_two_factor(args, config_path, json, out),
	}
}
