//! Blob storage administration: the `[storage.blobs]` section.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use clap::{Args, Subcommand};
use serde_json::{Map, Value, json};

use super::resource;
use super::stack::StackAction;
use crate::config::{BlobBackendConfig, Config};

#[path = "storage_blobs_set.rs"]
mod set;

#[cfg(test)]
#[path = "storage_blobs_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "storage_blobs_tests_set.rs"]
mod tests_set;

/// Storage administration areas.
#[derive(Debug, Subcommand)]
pub enum StorageCli {
	/// Manage where uploaded blobs are stored.
	Blobs {
		/// Blob storage action.
		#[command(subcommand)]
		action: BlobsCli,
	},
}

/// Blob storage actions.
#[derive(Debug, Subcommand)]
pub enum BlobsCli {
	/// Show the blob backend. The secret access key is never printed.
	Show {
		/// Print the backend settings as JSON.
		#[arg(long)]
		json: bool,
	},
	/// Choose the blob backend. Existing blobs are not migrated.
	Set {
		/// The backend to use.
		#[command(subcommand)]
		backend: Backend,
	},
}

/// A blob backend.
#[derive(Debug, Subcommand)]
pub enum Backend {
	/// Keep blobs on the local disk under `<data_dir>/blobs/`.
	Fs,
	/// Keep blobs in an S3-compatible bucket.
	S3(Box<S3Args>),
}

/// Settings of the S3 backend. The secret access key is only ever referenced.
#[derive(Debug, Clone, Args)]
pub struct S3Args {
	/// S3 endpoint URL, for example https://s3.us-east-1.amazonaws.com.
	#[arg(long)]
	pub endpoint: String,
	/// Bucket name.
	#[arg(long)]
	pub bucket: String,
	/// Region used for request signing, for example us-east-1.
	#[arg(long)]
	pub region: String,
	/// Access key id (not a secret).
	#[arg(long)]
	pub access_key_id: String,
	/// Environment variable holding the secret access key.
	#[arg(long, value_name = "VAR")]
	pub secret_env: Option<String>,
	/// 0600 file holding the secret access key.
	#[arg(long, value_name = "FILE")]
	pub secret_file: Option<String>,
	/// Switch even though local blobs would be left behind.
	#[arg(long)]
	pub force: bool,
}

fn show(config: &Config, json: bool, out: &mut impl Write) -> Result<(), String> {
	let mut rows: Vec<(&str, String)> = Vec::new();
	match config.storage.as_ref().and_then(|s| s.blobs.as_ref()) {
		None | Some(BlobBackendConfig::Fs) => rows.push(("backend", "fs".into())),
		Some(BlobBackendConfig::S3(s3)) => {
			rows.push(("backend", "s3".into()));
			rows.push(("endpoint", s3.endpoint.clone()));
			rows.push(("bucket", s3.bucket.clone()));
			rows.push(("region", s3.region.clone()));
			rows.push(("access_key_id", s3.access_key_id.clone()));
			if let Some(var) = &s3.secret_access_key_env {
				rows.push(("secret_access_key_env", var.clone()));
			}
			if let Some(path) = &s3.secret_access_key_file {
				rows.push(("secret_access_key_file", path.display().to_string()));
			}
		}
	}
	if json {
		let map: Map<String, Value> = rows
			.into_iter()
			.map(|(k, v)| (k.into(), json!(v)))
			.collect();
		return resource::json(out, &map);
	}
	for (key, value) in rows {
		writeln!(out, "{key}\t{value}").map_err(|error| error.to_string())?;
	}
	Ok(())
}

pub(super) fn run(path: &Path, action: StorageCli, dry_run: bool, json: bool) -> ExitCode {
	resource::exit_resource(execute_with(
		path,
		action,
		dry_run,
		json,
		&mut std::io::stdout().lock(),
		&mut super::style::stderr(),
		super::stack::run,
	))
}

fn execute_with(
	path: &Path,
	action: StorageCli,
	dry_run: bool,
	json: bool,
	out: &mut impl Write,
	status: &mut impl Write,
	restart: impl FnOnce(&Config, StackAction) -> ExitCode,
) -> Result<ExitCode, resource::ResourceError> {
	let StorageCli::Blobs { action } = action;
	let backend = match action {
		BlobsCli::Show { json: leaf } => {
			show(
				&Config::load(path)
					.map_err(|error| resource::ResourceError::Failure(error.to_string()))?,
				leaf || json,
				out,
			)?;
			return Ok(ExitCode::SUCCESS);
		}
		BlobsCli::Set { backend } => backend,
	};
	let current =
		Config::load(path).map_err(|error| resource::ResourceError::Failure(error.to_string()))?;
	let plan = set::plan(&current, &backend)?;
	let backend_name = match backend {
		Backend::Fs => "fs",
		Backend::S3(_) => "s3",
	};
	if plan.leaves_blobs_behind {
		writeln!(
			status,
			"Existing blobs are not migrated: those stored in the previous backend stay there and stop being served."
		)
		.map_err(|error| resource::ResourceError::Failure(error.to_string()))?;
	}
	let fields = plan.fields;
	let change: resource::Change = Box::new(move |document, _| {
		document
			.set_table_fields(&["storage", "blobs"], &fields)
			.map_err(resource::ResourceError::Failure)
	});
	let edit = resource::Edit {
		label: "blob storage",
		action: "blobs set",
		fields: json!({ "backend": backend_name }),
		json,
	};
	resource::apply_edit(path, dry_run, edit, out, status, restart, change)
}
