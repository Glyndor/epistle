//! Signing keys and the secrets that sign or authenticate what the server sends.

use super::{Entry, Handling};

pub(super) const ENTRIES: &[Entry] = &[
	Entry {
		id: "dkim-signing-key",
		name: "DKIM signing keys, the shared one and each domain's own",
		stored_in: "`[dkim]` and `[[dkim.domain]]` key files, and the rotated `dkim-*.key` files under `keys/dkim/`",
		config_fields: &[
			"Dkim.key_file",
			"Dkim.rsa_key_file",
			"DkimDomain.key_file",
			"DkimDomain.rsa_key_file",
		],
		rotate: Handling::Epistle(
			"`epistle dkim rotate`, and `epistle dkim rotate --domain DOMAIN` for a domain's own key",
		),
		revoke: Handling::Operator(
			"delete the old selector's TXT record at the DNS provider once its overlap window ends; `epistle dkim cleanup` lists what is left",
		),
		operator_after: &[
			"publish the new TXT records by hand for a domain no `[[dns]]` entry reaches",
		],
	},
	Entry {
		id: "arc-sealing-key",
		name: "ARC sealing key",
		stored_in: "`[arc] key_file`",
		config_fields: &["Arc.key_file"],
		rotate: Handling::Operator(
			"`epistle dkim-keygen --out FILE`, point `[arc] key_file` at it with a new `selector`, publish the selector's TXT record and restart",
		),
		revoke: Handling::Operator("delete the old selector's TXT record at the DNS provider"),
		operator_after: &["publish the new ARC selector's TXT record"],
	},
	Entry {
		id: "evidence-signing-key",
		name: "Evidence signing key",
		stored_in: "`<evidence>/key.pk8`, and `key.next.pk8` while a rotation is staged",
		config_fields: &[],
		rotate: Handling::Epistle("`epistle evidence key rotate`"),
		revoke: Handling::Operator(
			"nothing to delete: keep the old public key and the signed hand-over record so past evidence still verifies, and publish the new key's id",
		),
		operator_after: &["tell whoever verifies the evidence the new key's id"],
	},
	Entry {
		id: "oauth-signing-key",
		name: "OAuth issuer signing key",
		stored_in: "`[oauth] signing_key` or `signing_key_file`",
		config_fields: &["Oauth.signing_key", "Oauth.signing_key_file"],
		rotate: Handling::Operator(
			"`epistle oauth-keygen --out FILE`, replace the private key and the matching `public_key`, restart",
		),
		revoke: Handling::Operator(
			"the rotation is the revocation: every token the old key signed stops verifying at the restart and clients sign in again",
		),
		operator_after: &[],
	},
	Entry {
		id: "webhook-secret",
		name: "Webhook signing secrets, the server's and each tenant's",
		stored_in: "`[webhook] secret` and `[tenant.webhook] secret`",
		config_fields: &["Webhook.secret"],
		rotate: Handling::Operator(
			"`epistle webhook set --secret-stdin` with a new secret, and the same secret at the receiver; a tenant's `[tenant.webhook] secret` is edited in the file",
		),
		revoke: Handling::Epistle(
			"`epistle webhook disable` stops the server's webhook; a tenant's is removed from the file",
		),
		operator_after: &["give the receiver the new secret"],
	},
	Entry {
		id: "srs-secret",
		name: "SRS secrets, one per hosted domain and the shared one",
		stored_in: "`[[srs_domain]] secret` and `srs_secret`",
		config_fields: &[
			"SrsDomain.secret",
			"SrsDomain.previous_secret",
			"Config.srs_secret",
		],
		rotate: Handling::Epistle(
			"`epistle srs rotate DOMAIN`, after `epistle srs split` for a domain that uses the shared secret",
		),
		revoke: Handling::Operator(
			"remove `previous_secret` from `[[srs_domain]]` after 14 days; removing it sooner stops the return addresses already out from verifying",
		),
		operator_after: &[],
	},
	Entry {
		id: "server-hmac-keys",
		name: "Per-server HMAC keys: SubjectPass, log pseudonyms, Bayesian corpus",
		stored_in: "`subjectpass.key`, `log-pseudonym.key` and `bayes-corpus.key` under `data_dir`",
		config_fields: &[],
		rotate: Handling::Operator(
			"stop the server, retire the file and start it again so a new one is made; retrain the Bayesian corpus under its new key",
		),
		revoke: Handling::Operator(
			"the same step: outstanding retry tokens and old log pseudonyms stop matching",
		),
		operator_after: &[],
	},
	Entry {
		id: "timestamp-authority-token",
		name: "Timestamp authority bearer token",
		stored_in: "the `token_file` named in `<evidence>/timestamp.json`",
		config_fields: &[],
		rotate: Handling::Operator(
			"rotate it at the authority and replace the file; it is read on each request",
		),
		revoke: Handling::Operator("revoke the old token at the authority"),
		operator_after: &["revoke the old token at the authority"],
	},
];
