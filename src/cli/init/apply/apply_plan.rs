//! Build the plan from the answers and the disk state.
//!
//! Split off from `src/cli/init/apply/mod.rs` to keep the per-file line limit; the
//! functions here are read-only and never touch the operator's
//! machine. `apply` re-derives the same decisions step by step so a
//! step that succeeds here cannot silently disappear in `apply`.

use super::Answers;
use super::ApplyError;
use super::apply_config;
use super::apply_config_acme;
use super::apply_keys::key_file_present;
use crate::cli::init::plan::{ListenerEntry, Plan, PlanStep};

mod identical;
mod oauth_pair;
use identical::{
	compose_is_identical_to_desired, config_is_identical_to_desired, managed_key_count,
};
use oauth_pair::resolve_oauth_pair;

/// Walk the answers and produce the plan, WITHOUT writing anything. The
/// plan is what the operator reads before the confirmation prompt; it
/// is computed from the disk so a re-run says `reuse` for every key
/// the apply phase would also reuse, and `identical` for a config the
/// apply phase would leave alone. The apply phase re-derives the
/// decision on every step so a step that succeeds in `plan` cannot
/// silently disappear in `apply`.
///
/// Mail listeners always bind the dual-stack IPv6 any (`::`) so an
/// IPv4 client and an IPv6 client can both reach the server. There
/// is no host probe: `init` runs only inside containers, where `::`
/// binds regardless of the host's network namespace.
pub fn plan(answers: &Answers) -> Result<Plan, ApplyError> {
	let existing = match apply_config::read_config(&answers.config_path) {
		Ok(existing) => existing,
		// Preserve the plan's treatment of I/O failures as an unknown file state.
		Err(ApplyError::ConfigRead(_, _)) => None,
		Err(error) => return Err(error),
	};
	let keys_dir = answers.data_dir.join("keys");
	let s1 = keys_dir.join("s1.pem");
	let s2 = keys_dir.join("s2.pem");
	// Both keys end up outside data_dir; an install from before that
	// still has them under keys/, where apply moves them from.
	use super::super::host_secrets;
	let storage = host_secrets::storage_key(&answers.data_dir);
	let storage_now = host_secrets::effective(&answers.data_dir, host_secrets::STORAGE_KEY);
	let oauth_private = host_secrets::oauth_signing_key(&answers.data_dir);
	let oauth_private_now =
		host_secrets::effective(&answers.data_dir, host_secrets::OAUTH_SIGNING_KEY);
	let oauth_public = keys_dir.join("oauth_public.key");
	let cert_path = keys_dir.join("cert.pem");
	let key_path = keys_dir.join("key.pem");
	let oauth_private_exists = oauth_private_now.exists();
	let oauth_public_exists = oauth_public.exists();
	let oauth_pair = resolve_oauth_pair(
		oauth_private_exists,
		oauth_public_exists,
		&oauth_private_now,
		&oauth_public,
	)?;
	// Directory steps first: every write that follows needs the
	// directory it lives in. The previous shape listed the five key
	// writes ahead of the directory creation that those writes
	// depend on, so the operator read a plan that said "we will
	// write s1.pem" before "we will create data_dir". The apply
	// phase creates the directories first, and the plan now
	// mirrors that order so the operator sees the same shape they
	// will see in the report.
	let mut steps = Vec::new();
	if !answers.data_dir.exists() {
		steps.push(PlanStep::DataDir {
			path: answers.data_dir.clone(),
		});
	}
	if let Some(parent) = answers.config_path.parent()
		&& !parent.as_os_str().is_empty()
		&& !parent.exists()
	{
		steps.push(PlanStep::ConfigDir {
			path: parent.to_path_buf(),
		});
	}
	steps.extend([
		PlanStep::DkimEd25519 {
			path: s1.clone(),
			reused: key_file_present(&s1),
		},
		PlanStep::DkimRsa {
			path: s2.clone(),
			reused: key_file_present(&s2),
		},
		PlanStep::Storage {
			path: storage.clone(),
			reused: key_file_present(&storage_now),
		},
		PlanStep::OAuthPrivate {
			path: oauth_private.clone(),
			reused: oauth_pair.private_reused,
		},
		PlanStep::OAuthPublic {
			path: oauth_public.clone(),
			reused: oauth_pair.public_reused,
		},
	]);
	let cert_exists = cert_path.exists();
	let key_exists = key_path.exists();
	if cert_exists && !key_exists {
		// The apply phase refuses with a recoverable diagnostic;
		// the plan carries the same shape so the operator sees the
		// refusal before confirming.
		return Err(ApplyError::CertPairIncomplete(format!(
			"self-signed certificate {} exists but the matching private key {} is missing; restore the private key from backup or delete {} and rerun init",
			cert_path.display(),
			key_path.display(),
			cert_path.display()
		)));
	}
	steps.push(PlanStep::SelfSignedCert {
		cert_path: cert_path.clone(),
		key_path: key_path.clone(),
		reused: cert_exists && key_exists,
		key_reused: key_exists,
	});
	let existing_listeners =
		apply_config::listeners_from_existing(&answers.config_path, existing.as_ref())?;
	steps.push(PlanStep::Listeners {
		entries: if let Some(existing) = &existing_listeners {
			existing
				.iter()
				.map(|l| ListenerEntry {
					kind: l.kind.as_str().to_string(),
					addr: l.addr,
					port: l.port.unwrap_or_else(|| l.kind.default_port()),
				})
				.collect()
		} else {
			listener_entries(&answers.services, answers)
		},
		kept: existing_listeners.is_some(),
	});
	let identical = config_is_identical_to_desired(
		answers,
		std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
		&s1,
		&s2,
		&cert_path,
		&key_path,
		existing.as_ref(),
	)?;
	let file_exists = answers.config_path.exists();
	let count = managed_key_count(answers);
	// The database password step goes in the plan before the
	// config step: the config's `[database]` section points at the
	// password file, and `Config::load` opens it during validation.
	// The plan mirrors the apply order so the operator sees the
	// same shape they will see in the report.
	if answers.services.database {
		let path = crate::cli::init::compose::db_password_path(&answers.data_dir);
		// The plan says `reused: true` only when the apply
		// phase will actually reuse the file: it exists, is
		// non-empty, and can be read. A directory at the path
		// or a `mode 0o000` file would fail the apply phase
		// with `ExistingSecretUnreadable`; the plan surfaces
		// the same shape by reading the bytes here and only
		// saying `reuse` when the read returned non-empty
		// content. A non-existent or empty file is reported
		// as `reused: false` (the apply will mint a new one).
		let reused = crate::cli::init::compose::db_password_reused(&answers.data_dir);
		steps.push(PlanStep::DbPassword { path, reused });
		let path = crate::cli::init::host_secrets::db_admin_password(&answers.data_dir);
		let reused = std::fs::symlink_metadata(&path)
			.is_ok_and(|metadata| metadata.file_type().is_file() && metadata.len() > 0);
		steps.push(PlanStep::DbAdminPassword { path, reused });
	}
	if answers.services.panel_image.is_some() {
		let decision = crate::cli::init::compose::panel_secrets::decide(
			&answers.data_dir,
			crate::cli::init::compose::panel_secrets::now(),
		)?;
		steps.push(PlanStep::PanelSecrets {
			api_token: crate::cli::init::compose::panel_secrets::api_token_path(&answers.data_dir),
			key: decision.key.to_string(),
			session_secret: crate::cli::init::compose::panel_secrets::session_secret_path(
				&answers.data_dir,
			),
			session: decision.session.to_string(),
		});
	}
	steps.push(PlanStep::Config {
		path: answers.config_path.clone(),
		identical,
		file_exists,
		count,
		preserves_comments: false,
	});
	// The compose file is the last step. It is regenerated when
	// the answers change, byte-for-byte otherwise. The plan tells
	// the operator whether the file already matches the desired
	// version, will be written, or will be updated.
	let compose_path = crate::cli::init::compose::compose_file_path(&answers.data_dir);
	let compose_identical = compose_is_identical_to_desired(answers)?;
	let compose_file_exists = compose_path.exists();
	steps.push(PlanStep::ComposeFile {
		path: compose_path,
		identical: compose_identical,
		file_exists: compose_file_exists,
	});
	if let Some(dns) = &answers.dns {
		steps.push(PlanStep::Dns {
			provider: dns.provider.clone(),
			zone: dns.zone.clone(),
		});
	}
	if let Some(first) = &answers.first_account {
		let address = first.stored_address();
		steps.push(PlanStep::Account {
			name: first.name(),
			address: address.clone(),
		});
		for role in first.role_addresses(&answers.domains) {
			steps.push(PlanStep::RoleAlias {
				address: role,
				target: address.clone(),
			});
		}
	}
	Ok(Plan { steps })
}

/// Build the listener lines the plan prints, in the same order
/// `build_config` writes them. `smtp` first (always), then the
/// service-toggle listeners, then `api` (always loopback). Mail
/// listeners bind the dual-stack IPv6 any (`::`); the API listener
/// binds loopback (`127.0.0.1`) regardless. The port is read from
/// `crate::config::ListenerKind::default_port()` so a future change
/// to the schema default flows through both the plan and the serve
/// path together; the schema-vs-plan drift test in
/// `src/cli/init/apply/tests/steps/lines.rs` is what catches a
/// `listener_entries` that hardcoded the old number alongside a
/// `ListenerKind` that switched.
fn listener_entries(
	services: &crate::cli::init::answers::Services,
	answers: &crate::cli::init::Answers,
) -> Vec<ListenerEntry> {
	let mail_addr = std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED);
	let acme_enabled = apply_config_acme::should_enable_acme(answers);
	let mut entries = Vec::new();
	entries.push(ListenerEntry {
		kind: "smtp".to_string(),
		addr: mail_addr,
		port: crate::config::ListenerKind::Smtp.default_port(),
	});
	if services.imap {
		entries.push(ListenerEntry {
			kind: "imap".to_string(),
			addr: mail_addr,
			port: crate::config::ListenerKind::Imap.default_port(),
		});
		// IMAPS (993): the implicit-TLS sibling of STARTTLS IMAP
		// (143). Most clients default to the implicit port; the
		// plan has to show both so the operator can match what
		// `serve` will bind against the publish map.
		entries.push(ListenerEntry {
			kind: "imaps".to_string(),
			addr: mail_addr,
			port: crate::config::ListenerKind::Imaps.default_port(),
		});
	}
	if services.submission {
		entries.push(ListenerEntry {
			kind: "submission".to_string(),
			addr: mail_addr,
			port: crate::config::ListenerKind::Submission.default_port(),
		});
		// Submissions (465): the implicit-TLS sibling of STARTTLS
		// submission (587). Same reasoning as IMAPS.
		entries.push(ListenerEntry {
			kind: "submissions".to_string(),
			addr: mail_addr,
			port: crate::config::ListenerKind::Submissions.default_port(),
		});
	}
	if services.pop3 {
		entries.push(ListenerEntry {
			kind: "pop3s".to_string(),
			addr: mail_addr,
			port: crate::config::ListenerKind::Pop3s.default_port(),
		});
	}
	if services.managesieve {
		entries.push(ListenerEntry {
			kind: "manage-sieve".to_string(),
			addr: mail_addr,
			port: crate::config::ListenerKind::ManageSieve.default_port(),
		});
	}
	if services.webdav {
		entries.push(ListenerEntry {
			kind: "web-dav".to_string(),
			addr: mail_addr,
			port: crate::config::ListenerKind::WebDav.default_port(),
		});
	}
	if services.api {
		entries.push(ListenerEntry {
			kind: "api".to_string(),
			addr: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
			port: crate::config::ListenerKind::Api.default_port(),
		});
	}
	if acme_enabled {
		entries.push(ListenerEntry {
			kind: "acme".to_string(),
			addr: mail_addr,
			port: crate::config::ListenerKind::Acme.default_port(),
		});
	}
	entries
}
