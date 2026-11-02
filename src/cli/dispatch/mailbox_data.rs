//! The commands that read or write the stored mail through the message
//! crypto: `export`, `import` and `verify`. Split from `mod.rs`, which keeps
//! the exhaustive match over `Command`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::cli::term::live;
use crate::cli::util::message_crypto;
use crate::cli::{export, import, style, verify};
use crate::config::Config;

pub(super) fn export(config: &Path, account: String, maildir: Option<PathBuf>) -> ExitCode {
	match Config::load(config) {
		Ok(config) => match message_crypto(&config) {
			Ok(crypto) => live::run(
				&format!("export {account}"),
				false,
				|mut out| match maildir {
					Some(dir) => export::run_maildir(&config.data_dir, &account, &crypto, &dir),
					None => export::run(&config.data_dir, &account, &crypto, &mut out),
				},
			),
			Err(code) => code,
		},
		Err(error) => {
			style::error(error);
			ExitCode::FAILURE
		}
	}
}

pub(super) fn import(
	config: &Path,
	account: String,
	maildir: Option<PathBuf>,
	json: bool,
) -> ExitCode {
	match Config::load(config) {
		Ok(config) => match message_crypto(&config) {
			Ok(crypto) => match maildir {
				Some(dir) => import::run_maildir(&config.data_dir, &account, &crypto, &dir, json),
				None => import::run(
					&config.data_dir,
					&account,
					&crypto,
					std::io::stdin().lock(),
					json,
				),
			},
			Err(code) => code,
		},
		Err(error) => {
			style::error(error);
			ExitCode::FAILURE
		}
	}
}

pub(super) fn verify(config: &Path, json: bool) -> ExitCode {
	match Config::load(config) {
		Ok(config) => match message_crypto(&config) {
			Ok(crypto) => live::run("verify", json, |mut out| {
				verify::run(&config.data_dir, &crypto, json, &mut out)
			}),
			Err(code) => code,
		},
		Err(error) => {
			style::error(error);
			ExitCode::FAILURE
		}
	}
}
