//! The keys and credentials that protect mail at rest.

use super::{Entry, Handling, TRACKING_ISSUE};

pub(super) const ENTRIES: &[Entry] = &[
	Entry {
		id: "storage-encryption-key",
		name: "Storage key: message files, spool, JMAP blobs and sealed TOTP seeds",
		stored_in: "`[storage] encryption_key_file` or `encryption_key_env`, and `retired_key_files`",
		config_fields: &[
			"Storage.encryption_key_env",
			"Storage.encryption_key_file",
			"Storage.retired_key_files",
		],
		rotate: Handling::Unsupported {
			issue: TRACKING_ISSUE,
			meanwhile: "`epistle storage-keygen`, move the old file to `retired_key_files`, point `encryption_key_file` at the new one and run `epistle storage tenant-keys migrate` with the stack stopped (docs/security.md, Keys per tenant); changing only the key makes the existing mail unreadable",
		},
		revoke: Handling::Unsupported {
			issue: TRACKING_ISSUE,
			meanwhile: "retire the old key only once every file reads under the new one; a copy of the old key still opens every copy of the old files",
		},
		operator_after: &[
			"destroy backups that only the old key opens, or keep that key with them",
		],
	},
	Entry {
		id: "tenant-storage-key",
		name: "Storage key of each tenant",
		stored_in: "`[[tenant]] encryption_key_file`",
		config_fields: &["Tenant.encryption_key_file"],
		rotate: Handling::Unsupported {
			issue: TRACKING_ISSUE,
			meanwhile: "re-encrypt the tenant back to the server key with `--rollback`, change its key and migrate forward again (docs/security.md, Keys per tenant)",
		},
		revoke: Handling::Unsupported {
			issue: TRACKING_ISSUE,
			meanwhile: "the same steps; the old key still opens old copies",
		},
		operator_after: &[],
	},
	Entry {
		id: "s3-blob-credentials",
		name: "S3 blob storage credentials",
		stored_in: "`[storage.blobs] secret_access_key_file` or `secret_access_key_env`",
		config_fields: &[
			"S3BlobConfig.secret_access_key_env",
			"S3BlobConfig.secret_access_key_file",
		],
		rotate: Handling::Operator(
			"create a new access key at the S3 provider, update the file or the environment and restart",
		),
		revoke: Handling::Operator("delete the old access key at the S3 provider"),
		operator_after: &["delete the old access key at the S3 provider"],
	},
];
