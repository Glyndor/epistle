//! `epistle migrate imap`: read the arguments, the password and the local
//! account's limits, then run [`crate::migrate::imap::run`] and report.

use std::path::Path;
use std::process::ExitCode;

use tokio_rustls::rustls::pki_types::CertificateDer;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use zeroize::Zeroizing;

use super::ImapArgs;
use crate::cli::style;
use crate::config::Config;
use crate::directory_store::AccountStore;
use crate::migrate::imap::{
	Endpoint, Filter, MigrateError, Security, Settings, Source, Summary, Target, Verify,
};

/// The most a password file is read: a password is at most a line.
const MAX_PASSWORD_FILE: u64 = 4096;

/// Run `epistle migrate imap`.
pub(super) fn run(config: &Path, args: ImapArgs) -> ExitCode {
	let config = match Config::load(config) {
		Ok(config) => config,
		Err(error) => {
			style::error(error);
			return ExitCode::FAILURE;
		}
	};
	let endpoint = match endpoint(&args) {
		Ok(endpoint) => endpoint,
		Err(code) => return code,
	};
	let mut target = match target(&config, &args.account) {
		Ok(target) => target,
		Err(code) => return code,
	};
	let password = match password(args.password_file.as_deref()) {
		Ok(password) => password,
		Err(code) => return code,
	};
	let source = Source {
		endpoint,
		user: args.user.clone(),
		password,
	};
	let settings = Settings::new(Filter::new(&args.folders), args.dry_run);
	let runtime = match tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
	{
		Ok(runtime) => runtime,
		Err(error) => {
			style::error(format_args!("starting the runtime: {error}"));
			return ExitCode::FAILURE;
		}
	};
	let mut progress = super::report::Live::start(args.json, args.dry_run);
	let (summary, error) = runtime.block_on(crate::migrate::imap::run(
		&source,
		&mut target,
		&settings,
		&mut progress,
	));
	progress.finish(&summary, error.as_ref());
	report(&summary, error.as_ref(), args.json)
}

/// The endpoint the flags describe, with the warnings the insecure ones
/// owe the operator.
fn endpoint(args: &ImapArgs) -> Result<Endpoint, ExitCode> {
	let security = if args.insecure_plaintext {
		style::warn(
			"--insecure-plaintext: the password and every message cross the network unencrypted",
		);
		Security::Plaintext
	} else if args.starttls {
		Security::StartTls
	} else {
		Security::Tls
	};
	let verify = if args.insecure_skip_verify {
		style::warn(
			"--insecure-skip-verify: the server certificate is NOT checked; anyone on the \
			 network path can pose as the server and read the password and the mail",
		);
		Verify::Skip
	} else {
		let mut extra = Vec::new();
		if let Some(path) = &args.ca_file {
			match CertificateDer::pem_file_iter(path).and_then(|certs| certs.collect()) {
				Ok(certs) => extra = certs,
				Err(error) => {
					return Err(crate::cli::exit::refused(format_args!(
						"reading {}: {error}",
						shown(path)
					)));
				}
			}
			if extra.is_empty() {
				return Err(crate::cli::exit::refused(format_args!(
					"{} holds no certificate",
					path.display()
				)));
			}
		}
		Verify::Roots { extra }
	};
	let port = args.port.unwrap_or(match security {
		Security::Tls => 993,
		Security::StartTls | Security::Plaintext => 143,
	});
	Ok(Endpoint {
		host: args.host.clone(),
		port,
		address: None,
		security,
		verify,
	})
}

/// The local account, its quota and what it already stores. The account
/// must exist: mail for a name nobody can log in as would be unreachable.
fn target(config: &Config, account: &str) -> Result<Target, ExitCode> {
	let crypto = crate::cli::util::message_crypto(config)?;
	let store = AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	)
	.map(|store| store.with_domain_quotas(config.domain_quotas.clone()))
	.map_err(|error| {
		style::error(format_args!("opening account store: {error}"));
		ExitCode::FAILURE
	})?;
	if !store
		.account_views()
		.iter()
		.any(|(name, _, _)| name == account)
	{
		return Err(crate::cli::exit::refused(format_args!(
			"no account named {account}; create it first with `epistle account add`"
		)));
	}
	let default = config
		.quota_bytes
		.unwrap_or(crate::imap::session::DEFAULT_QUOTA_BYTES);
	let quota = crate::smtp::quota::limit_for(&store.handle().current(), account, default);
	let usage = crate::imap::mailbox::account_usage(&config.data_dir, account, &crypto);
	Ok(Target {
		data_dir: config.data_dir.clone(),
		account: account.to_string(),
		crypto,
		quota,
		usage,
		max_message_size: config
			.max_message_size
			.unwrap_or(crate::smtp::session::MAX_MESSAGE_SIZE as u64) as usize,
	})
}

/// The remote password: the first line of `file`, or one line of stdin
/// (typed with echo off on a terminal).
pub(super) fn password(file: Option<&Path>) -> Result<Zeroizing<String>, ExitCode> {
	let Some(path) = file else {
		return match crate::cli::prompt::secret_line(
			"remote IMAP password",
			&mut crate::cli::prompt::stdin(),
		) {
			crate::cli::prompt::Secret::Read(value) => Ok(Zeroizing::new(value)),
			_ => Err(crate::cli::exit::refused("no password given on stdin")),
		};
	};
	let read = || -> std::io::Result<Zeroizing<String>> {
		let file = std::fs::File::open(path)?;
		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			if file.metadata()?.permissions().mode() & 0o077 != 0 {
				style::warn(format_args!(
					"{} is readable by other users; keep password files mode 0600",
					path.display()
				));
			}
		}
		let mut text = Zeroizing::new(String::new());
		std::io::Read::read_to_string(
			&mut std::io::Read::take(file, MAX_PASSWORD_FILE),
			&mut text,
		)?;
		Ok(Zeroizing::new(
			text.lines().next().unwrap_or_default().to_string(),
		))
	};
	match read() {
		Ok(password) if !password.is_empty() => Ok(password),
		Ok(_) => Err(crate::cli::exit::refused(format_args!(
			"{} holds no password",
			shown(path)
		))),
		Err(error) => Err(crate::cli::exit::refused(format_args!(
			"reading {}: {error}",
			shown(path)
		))),
	}
}

/// Print the outcome and pick the exit code: 0 when everything was copied,
/// 1 when the run stopped early.
fn report(summary: &Summary, error: Option<&MigrateError>, json: bool) -> ExitCode {
	if json {
		let mut value = serde_json::to_value(summary).unwrap_or_default();
		if let (Some(error), Some(object)) = (error, value.as_object_mut()) {
			object.insert("error".into(), error.to_string().into());
		}
		let code = crate::cli::json_out::print(&mut std::io::stdout().lock(), &value);
		if code != ExitCode::SUCCESS {
			return code;
		}
	} else if summary.dry_run {
		super::report::plan(summary, &mut std::io::stdout().lock());
	}
	match error {
		Some(error) => {
			style::error(error);
			ExitCode::FAILURE
		}
		None => ExitCode::SUCCESS,
	}
}

/// `path` as the operator named it, when a root run staged a copy.
fn shown(path: &Path) -> String {
	crate::cli::staging::shown(&path.display().to_string())
}

#[cfg(test)]
#[path = "migrate_imap_tests.rs"]
mod tests;
