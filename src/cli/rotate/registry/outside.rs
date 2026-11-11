//! Credentials issued by someone else: epistle can point at a new one but
//! cannot mint or revoke it, so the operator does that on the other side.

use super::{Entry, Handling};

pub(super) const ENTRIES: &[Entry] = &[
	Entry {
		id: "dns-credentials",
		name: "DNS provider credentials, one per provider and zone",
		stored_in: "`[dns]` token, access and secret keys, consumer key, or their files and environment variables",
		config_fields: &[
			"Dns.token",
			"Dns.token_file",
			"Dns.token_env",
			"Dns.access_key",
			"Dns.secret_key",
			"Dns.secret_key_env",
			"Dns.consumer_key",
			"Dns.consumer_key_env",
			"Dns.credentials_file",
		],
		rotate: Handling::Operator(
			"create the new token at the provider, set it with `epistle dns provider set`, confirm it with `epistle dns provider check` and restart",
		),
		revoke: Handling::Operator("revoke the old token at the provider"),
		operator_after: &[
			"revoke the old token at the provider; epistle holds no credential that can do it",
		],
	},
	Entry {
		id: "tls-certificate",
		name: "TLS certificate and its private key, and the ACME account key",
		stored_in: "`[tls] key_file`, and `acme/account.key` and `acme/key.pem` for a managed certificate",
		config_fields: &["Tls.key_file"],
		rotate: Handling::Epistle(
			"`epistle tls renew` for a managed certificate; a manual PEM is replaced by hand and the server restarted",
		),
		revoke: Handling::Operator(
			"revoke the certificate with the CA; keep the ACME account key unless you register a new account",
		),
		operator_after: &["revoke the old certificate with the CA when its key was exposed"],
	},
	Entry {
		id: "database-password",
		name: "PostgreSQL password",
		stored_in: "`[database] url` or `password_file`",
		config_fields: &["Database.password_file"],
		rotate: Handling::Operator(
			"change it in PostgreSQL, update the url or the file and restart",
		),
		revoke: Handling::Operator("drop the old role or password in PostgreSQL"),
		operator_after: &["change the password on the database side"],
	},
	Entry {
		id: "relay-password",
		name: "Smarthost password",
		stored_in: "`[[transport]] password`",
		config_fields: &["Transport.password"],
		rotate: Handling::Operator("change it at the relay, update the configuration and restart"),
		revoke: Handling::Operator("disable the old credential at the relay"),
		operator_after: &["change the password at the relay"],
	},
	Entry {
		id: "ldap-bind-password",
		name: "LDAP service bind password",
		stored_in: "`[ldap] bind_password`",
		config_fields: &["Ldap.bind_password"],
		rotate: Handling::Operator("change it in LDAP, update the bind configuration and restart"),
		revoke: Handling::Operator("disable the old bind credential in LDAP"),
		operator_after: &["user passwords live in LDAP and are replaced there"],
	},
	Entry {
		id: "llm-scanner-api-key",
		name: "LLM scanner provider key",
		stored_in: "the environment variable named by `[antispam.llm] api_key_env`",
		config_fields: &["Llm.api_key_env"],
		rotate: Handling::Operator(
			"create a new key at the provider, update the service environment and restart",
		),
		revoke: Handling::Operator("revoke the old key at the provider"),
		operator_after: &["revoke the old key at the provider"],
	},
];
