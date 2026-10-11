//! Build the desired `Config` value from the answers and merge it with
//! whatever the operator already has on disk. The types live in a
//! sibling so `apply.rs` keeps under the per-file line limit.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use serde::Serialize;

use crate::cli::init::answers::{Answers, Services};
use crate::cli::init::apply::ApplyError;
use crate::config::{Listener, ListenerKind};

pub(super) const STACK_DATABASE_URL: &str = "postgres://epistle@%2Frun%2Fpostgresql/epistle";

/// Build the desired `Config` value from the answers. Each listener
/// line carries its kind and an explicit `addr`; the operator-visible
/// default of `127.0.0.1` is no longer the answer for any listener
/// `init` writes, because loopback-only mail listeners receive no
/// mail and serve nobody.
#[derive(Debug, Serialize)]
pub(super) struct DesiredConfig {
	pub(super) hostname: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(super) public_ipv4: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(super) public_ipv6: Option<String>,
	pub(super) data_dir: String,
	pub(super) domains: Vec<String>,
	pub(super) listeners: Vec<DesiredListener>,
	pub(super) dkim: DesiredDkim,
	pub(super) tls: DesiredTls,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(super) dns: Option<DesiredDns>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(super) database: Option<DesiredDatabase>,
	/// The `[acme]` block init writes when ACME is on. Absent on
	/// disk is the "ACME off" shape; a present block carries the
	/// directory URL, contact list, and domains the renewal loop
	/// should request certificates for.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(super) acme: Option<DesiredAcme>,
	pub(super) antispam: DesiredAntispam,
}

/// The `[acme]` section `init` writes when the answers (or the
/// public-hostname heuristic) say ACME should be on. `directory_url`
/// is the CA's ACME directory endpoint (Let's Encrypt production
/// today); `contacts` is the list of URIs the CA uses to reach the
/// operator; `domains` is the list of names a certificate should
/// cover; `renew_before_days` matches the schema default (30) so
/// the field appears explicitly and a future change to the schema
/// default flows through `init` as well.
#[derive(Debug, Serialize)]
pub(super) struct DesiredAcme {
	pub(super) directory_url: String,
	pub(super) contacts: Vec<String>,
	pub(super) domains: Vec<String>,
	pub(super) renew_before_days: u32,
}

#[derive(Debug, Serialize)]
pub(super) struct DesiredAntispam {
	clamd_socket: String,
}

#[derive(Debug, Serialize)]
pub(super) struct DesiredListener {
	pub(super) kind: String,
	/// Bind address the listener uses. Always written so the schema
	/// default (`127.0.0.1`) cannot silently take over: an init
	/// config that names only `kind` would bind loopback and miss
	/// every packet the network delivers.
	pub(super) addr: IpAddr,
}

#[derive(Debug, Serialize)]
pub(super) struct DesiredDkim {
	pub(super) selector: String,
	pub(super) key_file: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(super) rsa_selector: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(super) rsa_key_file: Option<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct DesiredTls {
	pub(super) cert_file: String,
	pub(super) key_file: String,
}

#[derive(Debug, Serialize)]
pub(super) struct DesiredDns {
	pub(super) provider: String,
	pub(super) zone: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(super) token: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(super) token_file: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(super) token_env: Option<String>,
}

/// The `[database]` section `init` writes when the operator asks
/// for the database service. The URL is the percent-encoded socket
/// form (`postgres://epistle@%2Frun%2Fpostgresql/epistle`) so the
/// same connection string works on the host (where `init` and
/// `config-check` run) and inside the `mail` container (where
/// `serve` runs). The password file points at the secret the
/// compose file mounts; the `mail` container reads it through the
/// data-directory bind mount at the same path.
#[derive(Debug, Serialize)]
pub(super) struct DesiredDatabase {
	pub(super) url: String,
	pub(super) password_file: String,
}

/// The outcome of trying to merge the desired config with whatever is
/// on disk. `Identical` means the file is already byte-for-byte what we
/// want and stays untouched; `Wrote` means the file did not exist or
/// was rewritten; `Updated` means an existing file was overwritten with
/// a different value.
pub(crate) enum ConfigWrite {
	Identical,
	Wrote,
	Updated,
}

/// Construct the desired config tree from the answers and the paths to
/// the keys `apply` generated.
///
/// `mail_addr` is the bind address used by every mail-facing listener
/// (smtp, submission, imap, pop3s, manage-sieve, web-dav). The
/// management API listener is closed to the network by design and
/// binds loopback (`127.0.0.1`) regardless. `mail_addr` is decided
/// once in `plan` so the operator sees the same address on the
/// confirmation prompt that `apply` writes into the config.
pub(super) fn build_config(
	answers: &Answers,
	mail_addr: IpAddr,
	dkim_ed25519: Option<&Path>,
	dkim_rsa: Option<&Path>,
	cert_file: &Path,
	key_file: &Path,
) -> Result<DesiredConfig, ApplyError> {
	// ACME: the operator opt-out (`acme.enabled = false`) wins; the
	// public-hostname heuristic decides when the opt-out is
	// absent. Loopback and reserved-TLD hostnames fall through to
	// `false` so the resulting config has no `[acme]` block and no
	// `acme` listener; port 80 stays closed. The presence of the
	// block is the same flag the listener array reads below, so
	// the two stay in sync.
	let acme_block = super::apply_config_acme::build_acme_block(answers);
	// When ACME is on, the `[tls]` section has to point at the
	// ACME cert / key paths (the renewal loop in
	// `crate::acme::renew` writes to `<data_dir>/acme/cert.pem`
	// and `<data_dir>/acme/key.pem`, then hot-reloads the SMTP
	// acceptor). Pointing at `keys/cert.pem` would mean the
	// renewal loop writes a different file the server never
	// reads; the issued cert would land on disk and never reach
	// a listener. The keys/ path stays the bootstrap target
	// when ACME is off.
	let tls_cert = if acme_block.is_some() {
		answers.data_dir.join("acme").join("cert.pem")
	} else {
		cert_file.to_path_buf()
	};
	let tls_key = if acme_block.is_some() {
		answers.data_dir.join("acme").join("key.pem")
	} else {
		key_file.to_path_buf()
	};
	let mut listeners = Vec::new();
	let services: &Services = &answers.services;
	// SMTP (port 25, inbound mail) is always written. It is the
	// listener the rest of the internet talks to, and a fresh install
	// that does not bind it receives no mail. The kind is unconditional
	// even when every other optional service is off, so the operator
	// never has to add it back by hand.
	listeners.push(DesiredListener {
		kind: "smtp".to_string(),
		addr: mail_addr,
	});
	if services.imap {
		listeners.push(DesiredListener {
			kind: "imap".to_string(),
			addr: mail_addr,
		});
		// The implicit-TLS sibling ships whenever STARTTLS IMAP does:
		// most mail clients default to port 993 first and only fall
		// back to STARTTLS on 143 if the implicit handshake fails.
		// Without the implicit listener, the server is reachable only
		// by clients that have been told to use STARTTLS, which is
		// not the default for Apple Mail, Outlook, Thunderbird, or
		// any other client I know of.
		listeners.push(DesiredListener {
			kind: "imaps".to_string(),
			addr: mail_addr,
		});
	}
	if services.submission {
		listeners.push(DesiredListener {
			kind: "submission".to_string(),
			addr: mail_addr,
		});
		// Submissions (465) ships alongside submission (587): modern
		// clients open 465 first and only try STARTTLS on 587 if the
		// implicit handshake fails. Without the implicit listener, the
		// server accepts submissions only from clients that have been
		// told to use STARTTLS, which is no longer the default.
		listeners.push(DesiredListener {
			kind: "submissions".to_string(),
			addr: mail_addr,
		});
	}
	if services.pop3 {
		listeners.push(DesiredListener {
			kind: "pop3s".to_string(),
			addr: mail_addr,
		});
	}
	if services.managesieve {
		listeners.push(DesiredListener {
			kind: "manage-sieve".to_string(),
			addr: mail_addr,
		});
	}
	if services.webdav {
		listeners.push(DesiredListener {
			kind: "web-dav".to_string(),
			addr: mail_addr,
		});
	}
	if services.api {
		listeners.push(DesiredListener {
			kind: "api".to_string(),
			addr: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
		});
	}
	// ACME: when on, init writes the `acme` listener on port 80 so
	// the HTTP-01 challenge responder is reachable from the public
	// internet. The listener is on the same mail bind address as
	// every other mail-facing listener; the responder never
	// authenticates, but it still has to bind the same dual-stack
	// `::` to answer both v4 and v6 challengers. The decision
	// reads off the block the helper computed above, so the
	// listener and the config block cannot drift.
	if acme_block.is_some() {
		listeners.push(DesiredListener {
			kind: "acme".to_string(),
			addr: mail_addr,
		});
	}

	let dkim = match (dkim_ed25519, dkim_rsa) {
		(Some(ed), Some(rsa)) => DesiredDkim {
			selector: "s1".to_string(),
			key_file: ed.display().to_string(),
			rsa_selector: Some("s2".to_string()),
			rsa_key_file: Some(rsa.display().to_string()),
		},
		// When the RSA key is absent (no `openssl` on `PATH`, or key
		// generation failed), omit both RSA fields entirely so the
		// server configuration does not name an RSA selector pointing
		// at Ed25519 material. The single-signature warning from
		// `#[allow(dead_code)]` / issue #911 already explains what is
		// missing to the operator.
		(Some(ed), None) => DesiredDkim {
			selector: "s1".to_string(),
			key_file: ed.display().to_string(),
			rsa_selector: None,
			rsa_key_file: None,
		},
		// The (None, _) arm would have refused to write a config without
		// an ed25519 key, but `apply` always supplies Some and `plan`
		// only calls `build_config` with `Some(dkim_ed25519)`. The arm
		// is unreachable from any caller, so the refusal message is
		// documented in the test that exercises the function directly.
		(None, _) => unreachable!("apply always supplies a dkim ed25519 path"),
	};

	let dns = answers.dns.as_ref().map(|d| DesiredDns {
		provider: d.provider.clone(),
		zone: d.zone.clone(),
		token: d.token.clone(),
		token_file: d.token_file.as_ref().map(|p| p.display().to_string()),
		token_env: d.token_env.clone(),
	});

	// The `[database]` section is written only when the operator
	// opted into the database service. The URL is the percent-encoded
	// socket form; the password file is the secret the compose
	// file mounts into the `mail` container. Both the host (where
	// `init` and `config-check` run) and the container (where
	// `serve` runs) see the same path because the data directory
	// is bind-mounted at the same path on both sides.
	let database = if answers.services.database {
		Some(DesiredDatabase {
			url: STACK_DATABASE_URL.to_string(),
			password_file: crate::cli::init::compose::db_password_path(&answers.data_dir)
				.display()
				.to_string(),
		})
	} else {
		None
	};

	Ok(DesiredConfig {
		hostname: answers.hostname.clone(),
		public_ipv4: answers.public_ipv4.map(|a| a.to_string()),
		public_ipv6: answers.public_ipv6.map(|a| a.to_string()),
		data_dir: answers.data_dir.display().to_string(),
		domains: answers.domains.clone(),
		listeners,
		dkim,
		tls: DesiredTls {
			cert_file: tls_cert.display().to_string(),
			key_file: tls_key.display().to_string(),
		},
		dns,
		database,
		acme: acme_block,
		antispam: DesiredAntispam {
			clamd_socket: "/run/clamav/clamd.sock".to_string(),
		},
	})
}

/// Top-level keys `init` writes into the desired config. The merge
/// removes these from the existing config when the desired config does
/// not include them, so omitting `services.api = true`, `public_ipv4`,
/// the `[dns]` section, or every listener actually clears the entry
/// from the file instead of leaving it preserved as an "operator
/// setting" the operator never asked for.
///
/// `[database]` is merged per key when enabled. When disabled, only
/// the section identifying the generated stack socket is removed;
/// an operator's different database URL remains untouched.
pub(super) const INIT_MANAGED_KEYS: &[&str] = &[
	"hostname",
	"public_ipv4",
	"public_ipv6",
	"data_dir",
	"domains",
	"listeners",
	"dkim",
	"tls",
	"dns",
];

/// The dual-stack IPv6 any address every mail listener binds when
/// `init` writes the config. The `apply` phase uses the same
/// constant so the plan and the apply path agree on what address
/// the listener will reach the wire with. A loopback-only mail
/// listener would receive no mail.
const MAIL_BIND_ADDR: IpAddr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);

/// The loopback address the management API listener binds when
/// `init` writes the config. The API is closed to the network by
/// design; the operator reaches it through the host's pasta
/// mapping once the stack is up.
const API_BIND_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// Return the listeners `init` will write into the config: either
/// the operator's existing array (when the keep-existing-listeners
/// path applies) or the array derived from the answers. The compose
/// step uses this to derive the `ports:` list so a published port
/// always matches a listener init just wrote.
///
/// Use the same verified reader as the merge so a non-empty operator listener
/// array is preserved as-is.
pub(crate) fn listeners_to_write(answers: &Answers) -> Result<Vec<Listener>, ApplyError> {
	if let Some(existing) = existing_operators_listeners(&answers.config_path)? {
		return Ok(existing);
	}
	// ACME: same gate the config writer uses. The two listeners
	// the config block and the typed listener vec see must agree,
	// because the compose writer derives the published-port list
	// from this typed vec (not from the config block) and a
	// missing `acme` listener here would keep port 80 out of the
	// publish map even when the config says ACME is on.
	let acme_enabled = super::apply_config_acme::should_enable_acme(answers);
	Ok(desired_listeners(&answers.services, acme_enabled))
}

/// Build the listener array `init` would write from the answers.
/// `smtp` is always present; the rest follow the `Services` flags.
/// Mail listeners bind the dual-stack IPv6 any (`::`); the API
/// listener binds loopback (`127.0.0.1`) and is closed to the
/// network by design. Port is left as `None` so the schema default
/// is what `serve` binds; the published-ports helper resolves it
/// from the kind.
fn desired_listeners(services: &Services, acme_enabled: bool) -> Vec<Listener> {
	let mut listeners = Vec::new();
	listeners.push(Listener {
		kind: ListenerKind::Smtp,
		addr: MAIL_BIND_ADDR,
		port: None,
	});
	if services.imap {
		listeners.push(Listener {
			kind: ListenerKind::Imap,
			addr: MAIL_BIND_ADDR,
			port: None,
		});
		// IMAPS (993): the implicit-TLS sibling of the STARTTLS IMAP
		// listener above. Most mail clients default to 993; the
		// listener entries mirror the typed/serialised split
		// `build_config` uses so the plan, the apply write, and the
		// compose publish list all agree on which ports init binds.
		listeners.push(Listener {
			kind: ListenerKind::Imaps,
			addr: MAIL_BIND_ADDR,
			port: None,
		});
	}
	if services.submission {
		listeners.push(Listener {
			kind: ListenerKind::Submission,
			addr: MAIL_BIND_ADDR,
			port: None,
		});
		// Submissions (465): the implicit-TLS sibling of the
		// STARTTLS submission listener above. Modern clients
		// negotiate the implicit port first.
		listeners.push(Listener {
			kind: ListenerKind::Submissions,
			addr: MAIL_BIND_ADDR,
			port: None,
		});
	}
	if services.pop3 {
		listeners.push(Listener {
			kind: ListenerKind::Pop3s,
			addr: MAIL_BIND_ADDR,
			port: None,
		});
	}
	if services.managesieve {
		listeners.push(Listener {
			kind: ListenerKind::ManageSieve,
			addr: MAIL_BIND_ADDR,
			port: None,
		});
	}
	if services.webdav {
		listeners.push(Listener {
			kind: ListenerKind::WebDav,
			addr: MAIL_BIND_ADDR,
			port: None,
		});
	}
	if services.api {
		listeners.push(Listener {
			kind: ListenerKind::Api,
			addr: API_BIND_ADDR,
			port: None,
		});
	}
	if acme_enabled {
		listeners.push(Listener {
			kind: ListenerKind::Acme,
			addr: MAIL_BIND_ADDR,
			port: None,
		});
	}
	listeners
}

// Re-export the merge / staging helpers that `apply_config_merge`
// owns. Callers that reach for `apply_config::existing_operators_listeners`,
// `apply_config::merge_with_existing`, `apply_config::reconcile`,
// or `apply_config::write_validated_config` (the plan, the apply
// path, and several tests) keep working without an import
// rewrite every time a helper moves. The actual implementations
// live in the sibling so this file stays under the per-file line
// limit.
//
// The `unused_imports` lint fires inside this module because the
// re-export is consumed by callers, not here. The lint is
// suppressed on the line so the helper still works as a re-export.
#[allow(unused_imports)]
pub(super) use super::apply_config_merge::{
	create_unique_staging_with, existing_operators_listeners, listeners_from_existing,
	merge_with_read_config, reconcile, write_validated_config,
};

#[cfg(test)]
#[path = "apply_config_tests_clamav.rs"]
mod tests_clamav;

#[cfg(test)]
#[path = "apply_config_tests_database_off.rs"]
mod tests_database_off;

#[cfg(all(test, unix))]
#[path = "apply_config_tests_read_safety.rs"]
mod tests_read_safety;

#[cfg(test)]
pub(super) use super::apply_config_merge::merge_with_existing;

#[path = "apply_config_read.rs"]
mod read;
pub(crate) use read::{ExistingConfig, read_config};
