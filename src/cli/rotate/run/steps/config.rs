//! Secrets kept in the configuration file: the server's webhook secret and
//! the SRS secret of each domain that has its own.
//!
//! Each edit is one validated, atomic rewrite of the file. The journal holds
//! the sha256 of the secret the edit writes, so a later run sees whether the
//! file already carries it. Applying an SRS rotation twice would move the new
//! secret into `previous_secret` and drop the old one, which still verifies
//! the return addresses already out; the check is what prevents it.

use std::path::Path;

use toml_edit::Value;

use crate::cli::config_edit::ConfigDocument;
use crate::config::Config;

use super::super::journal::{Intent, Kind, Step};
use super::super::secrets::{Secrets, digest};

/// The steps and the notes for what the file holds.
pub(super) fn plan(path: &Path, config: &Config) -> Result<(Vec<Step>, Vec<String>), String> {
	let document = ConfigDocument::open(path)?;
	let (mut steps, mut notes) = (Vec::new(), Vec::new());
	match document.table_string(&["webhook"], "secret") {
		Some(raw) if raw.contains("${") => notes.push(
			"webhook-secret: `[webhook] secret` is read from the environment; put a new secret \
			 there and at the receiver, then restart"
				.to_string(),
		),
		Some(_) => steps.push(Step::pending(Kind::WebhookSecret, "", None)),
		None => {}
	}
	for tenant in config.tenants.iter().filter(|tenant| {
		tenant
			.webhook
			.as_ref()
			.is_some_and(|hook| hook.secret.is_some())
	}) {
		let name = tenant.name.as_deref().unwrap_or("(unnamed)");
		notes.push(format!(
			"webhook-secret: the `[tenant.webhook] secret` of tenant {name} is not rotated by this \
			 command; replace it in the file and at its receiver"
		));
	}
	if config
		.api
		.as_ref()
		.is_some_and(|api| api.token_hash.is_some())
	{
		notes.push(
			"api-key: the static `[api] token_hash` is not rotated by this command; make a new \
			 token, put its `epistle token-hash` in the file and hand it to its client"
				.to_string(),
		);
	}
	for entry in &config.srs_domain {
		steps.push(Step::pending(
			Kind::SrsSecret,
			&entry.name.to_ascii_lowercase(),
			None,
		));
	}
	let shared = config.srs_domains_on_shared_secret();
	if !shared.is_empty() {
		notes.push(format!(
			"srs-secret: {} sign with the shared `srs_secret`, which this command does not \
			 rotate; run `epistle srs split` and then `epistle rotate --all` again",
			shared.join(", ")
		));
	}
	Ok((steps, notes))
}

/// The secret in the file now, exactly as written.
fn current(path: &Path, step: &Step) -> Result<Option<String>, String> {
	let document = ConfigDocument::open(path)?;
	Ok(match step.kind {
		Kind::WebhookSecret => document.table_string(&["webhook"], "secret"),
		_ => document
			.element_field("srs_domain", "name", &step.item, "secret")
			.and_then(|value| value.as_str().map(str::to_string)),
	})
}

/// Make the new secret and keep it before the file changes.
pub(super) fn prepare(path: &Path, step: &Step, secrets: &mut Secrets) -> Result<Intent, String> {
	let secret = match step.kind {
		Kind::WebhookSecret => crate::cli::generate_secret(),
		_ => crate::queue::srs::generate_secret(),
	}
	.ok_or("the system gave no random bytes for a secret")?;
	let old = current(path, step)?.map(|raw| digest(&raw));
	let new = digest(&secret);
	secrets.put(step.secret_key(), secret)?;
	Ok(Intent::Replace { old, new })
}

/// Whether the file already carries the secret the step decided on.
pub(super) fn landed(path: &Path, step: &Step, new: &str) -> Result<bool, String> {
	Ok(current(path, step)?.is_some_and(|raw| digest(&raw) == new))
}

/// Write the kept secret. An SRS domain keeps the secret it had as
/// `previous_secret`, as it is written (a `${VAR}` stays a reference).
pub(super) fn apply(path: &Path, step: &Step, secrets: &Secrets) -> Result<(), String> {
	let secret = secrets.get(&step.secret_key()).ok_or_else(|| {
		format!(
			"the new secret for {} is missing from the secrets file; the file was changed outside \
			 this command",
			describe(step)
		)
	})?;
	let mut document = ConfigDocument::open(path)?;
	match step.kind {
		Kind::WebhookSecret => document.set_table_fields(
			&["webhook"],
			&[("secret", Some(Value::from(secret.to_string())))],
		)?,
		_ => {
			let old = document
				.element_field("srs_domain", "name", &step.item, "secret")
				.ok_or_else(|| {
					format!("cannot read the SRS secret of {} from the file", step.item)
				})?;
			crate::cli::srs::set_domain_secret(
				&mut document,
				&step.item,
				secret.to_string(),
				Some(old),
			)?;
		}
	}
	document.commit().map(|_| ())
}

fn describe(step: &Step) -> String {
	match step.kind {
		Kind::WebhookSecret => "the webhook".to_string(),
		_ => format!("the SRS secret of {}", step.item),
	}
}
