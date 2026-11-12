//! The compose document: the top-level tables and the service map one `init` serializes.

use serde::Serialize;
use std::collections::BTreeMap;

use super::services::ComposeService;
use super::{KEY_SECRETS, db_password_path, resolve_image};
use crate::cli::init::answers::Answers;

#[derive(Debug, Serialize)]
struct TopLevelSecret {
	file: String,
}

#[derive(Debug, Serialize)]
struct TopLevelVolume {}

#[derive(Debug, Serialize)]
struct TopLevelConfig {
	content: &'static str,
}

/// The full compose file. `serde_json` writes the field order from
/// the struct definition, so the rendered file matches the order
/// the operator reads here.
#[derive(Debug, Serialize)]
pub(in crate::cli::init) struct ComposeFile {
	name: String,
	#[serde(rename = "x-epistle-managed-image")]
	managed_image: bool,
	/// `false` when the stack runs no clamav on purpose, which `stack
	/// update` reads back; absent otherwise, so a file from before clamav
	/// was part of the stack still gets it.
	#[serde(
		rename = "x-epistle-antivirus",
		skip_serializing_if = "Option::is_none"
	)]
	antivirus: Option<bool>,
	/// The operator's `services.panel` choice, which `stack update` reads
	/// back: `false` keeps the panel out of a stack that has the package,
	/// `true` demands it. Absent leaves the package to decide.
	#[serde(rename = "x-epistle-panel", skip_serializing_if = "Option::is_none")]
	panel: Option<bool>,
	/// The limits the answers set, which `stack update` reads back.
	#[serde(
		rename = "x-epistle-resources",
		skip_serializing_if = "BTreeMap::is_empty"
	)]
	resources: BTreeMap<String, crate::cli::init::resources::ServiceResources>,
	services: BTreeMap<String, ComposeService>,
	secrets: BTreeMap<String, TopLevelSecret>,
	#[serde(skip_serializing_if = "BTreeMap::is_empty")]
	configs: BTreeMap<String, TopLevelConfig>,
	#[serde(skip_serializing_if = "BTreeMap::is_empty")]
	volumes: BTreeMap<String, TopLevelVolume>,
}

impl ComposeFile {
	pub(in crate::cli::init) fn build(
		answers: &Answers,
		published_ports: Vec<String>,
		database: bool,
	) -> Self {
		let nofile = super::services::mail_nofile(super::services::host_hard_nofile());
		Self::build_with_nofile(answers, published_ports, database, nofile)
	}

	/// [`Self::build`] asking for `nofile` open files in the `mail` service.
	pub(in crate::cli::init) fn build_with_nofile(
		answers: &Answers,
		published_ports: Vec<String>,
		database: bool,
		nofile: Option<u64>,
	) -> Self {
		let image = resolve_image(answers.image.as_deref());
		let mut services = BTreeMap::new();
		services.insert(
			"mail".to_string(),
			ComposeService::new_mail(&image, answers, database, published_ports, nofile),
		);
		if answers.services.certs {
			services.insert(
				"certs".to_string(),
				ComposeService::new_certs(&image, answers),
			);
		}
		// Off only when the answers or the host's memory said so.
		let antivirus = answers.services.antivirus != Some(false);
		if antivirus {
			services.insert(
				"clamav".to_string(),
				ComposeService::new_clamav(answers, false),
			);
			services.insert(
				"freshclam".to_string(),
				ComposeService::new_clamav(answers, true),
			);
		}
		let mut secrets = BTreeMap::new();
		for (name, path) in KEY_SECRETS {
			secrets.insert(
				name.to_string(),
				TopLevelSecret {
					file: path(&answers.data_dir).display().to_string(),
				},
			);
		}
		if answers.services.certs {
			secrets.insert(
				super::services::ACME_ACCOUNT_SECRET.to_string(),
				TopLevelSecret {
					file: crate::cli::init::host_secrets::acme_account_key(&answers.data_dir)
						.display()
						.to_string(),
				},
			);
		}
		let mut configs = BTreeMap::new();
		let mut volumes = BTreeMap::new();
		if antivirus {
			volumes.insert("clamd-socket".to_string(), TopLevelVolume {});
			volumes.insert("clamav-db".to_string(), TopLevelVolume {});
		}
		if database {
			services.insert("db".to_string(), ComposeService::new_db());
			secrets.insert(
				"epistle_db_password".to_string(),
				TopLevelSecret {
					file: db_password_path(&answers.data_dir).display().to_string(),
				},
			);
			secrets.insert(
				crate::cli::init::db_roles::ADMIN_SECRET.to_string(),
				TopLevelSecret {
					file: crate::cli::init::host_secrets::db_admin_password(&answers.data_dir)
						.display()
						.to_string(),
				},
			);
			configs.insert(
				super::services::DB_ROLES_CONFIG.to_string(),
				TopLevelConfig {
					content: crate::cli::init::db_roles::INIT_SCRIPT,
				},
			);
			volumes.insert("epistle-pgdata".to_string(), TopLevelVolume {});
			volumes.insert("epistle-pgsock".to_string(), TopLevelVolume {});
		}
		let services = services
			.into_iter()
			.map(|(name, service)| {
				let service = service.limited(&name, &answers.resources);
				(name, service)
			})
			.collect();
		Self {
			name: "epistle".to_string(),
			managed_image: answers.image.is_none(),
			antivirus: (!antivirus).then_some(false),
			panel: answers.services.panel,
			resources: answers.resources.clone(),
			services,
			secrets,
			configs,
			volumes,
		}
	}
}
