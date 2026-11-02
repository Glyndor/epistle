# Frozen v0.12.5 credentials

Written by epistle **v0.12.5**, tag commit
`19e5fd569c29d21c696be0e1626d99401380749d`, built with rustc 1.98.1.
These are public test credentials, never production secrets. Keep these bytes
frozen: the contract reads them with current code and never regenerates them.
Fresh salts and encryption nonces make a repeat dump bytewise different.

I produced them in a scratch copy without modifying the release sources:

```sh
mkdir /tmp/cred-v0.12.5
git archive v0.12.5 | tar -x -C /tmp/cred-v0.12.5
# Write the dump below as examples/dump_credentials.rs in that scratch copy.
cargo run --locked --manifest-path /tmp/cred-v0.12.5/Cargo.toml \
	--example dump_credentials -- /tmp/cred-produced-final
```

I copied only the six credential files here, preserving their contents; the
store's empty lock files and the scratch example are intentionally excluded.
`accounts.toml` contains password-only and TOTP accounts, both with SCRAM
verifiers. `sealed/accounts.toml` contains a third account with encrypted TOTP.
The app password belongs to the TOTP account. `static_tokens.toml` wraps both
supported static token hashes in a TOML array, using the release's hash helpers.
`encryption.key` is the public test key for the sealed store, base64 encoded.

Test inputs: password `Upgrade-contract-password-0125!`, app password
`Upgrade-contract-app-0125!`, API/static token `Upgrade-contract-api-0125!`,
TOTP bytes `upgrade-contract-totp`, encryption key bytes
`upgrade-contract-encryption-key!`. The dump uses the release's own password,
SCRAM, TOTP encoding, encryption and persistence implementations.

These files intentionally contain literal test secrets, salts and verifier key
material. Secret scanners or CodeQL may flag them; do not disguise the values or
regenerate them to suppress a finding.

```rust
use epistle::api::api_keys::{ApiKey, ApiKeyStore, sha256_hash};
use epistle::directory_store::{AccountStore, AppPassword, DynamicAccount};
use epistle::password::Policy;

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let dir = std::path::PathBuf::from(std::env::args().nth(1).expect("output directory"));
	std::fs::create_dir_all(&dir)?;
	let store = AccountStore::open(&dir, vec!["example.test".into()], Default::default(), vec![])?;
	for name in ["password", "secondfactor"] {
		store.add(DynamicAccount::with_password(
			name.into(), vec![format!("{name}@example.test")],
			"Upgrade-contract-password-0125!", &Policy::ASCII_ONLY, true,
		)?)?;
	}
	store.set_totp("secondfactor", Some(epistle::totp::encode_base32(b"upgrade-contract-totp")))?;
	store.add_app_password("secondfactor", AppPassword {
		label: "upgrade".into(),
		hash: epistle::smtp::auth::hash_password("Upgrade-contract-app-0125!")?,
		expires_at: None, ip_cidr: None, save_sent: None,
	})?;
	ApiKeyStore::open(&dir)?.add(ApiKey {
		label: "upgrade".into(), hash: sha256_hash("Upgrade-contract-api-0125!"),
		expires_at: None, ip_cidr: None, scopes: vec!["read".into()],
		domains: vec![], account: None,
	})?;
	std::fs::write(dir.join("static_tokens.toml"), toml::to_string_pretty(&std::collections::BTreeMap::from([
		("hashes", vec![
		sha256_hash("Upgrade-contract-api-0125!"),
		epistle::smtp::auth::hash_password("Upgrade-contract-api-0125!")?,
		]),
	]))?)?;
	let sealed = dir.join("sealed");
	std::fs::create_dir_all(&sealed)?;
	use base64::Engine;
	let key_file = dir.join("encryption.key");
	std::fs::write(&key_file, base64::engine::general_purpose::STANDARD.encode(b"upgrade-contract-encryption-key!"))?;
	let crypto = epistle::storage::MessageCrypto::from_config(Some(&epistle::config::Storage {
		encrypt_at_rest: true, encryption_key_file: Some(key_file), ..Default::default()
	}))?;
	let encrypted = AccountStore::open(&sealed, vec!["example.test".into()], Default::default(), vec![])?.with_crypto(crypto);
	encrypted.add(DynamicAccount::with_password("sealed".into(), vec!["sealed@example.test".into()], "Upgrade-contract-password-0125!", &Policy::ASCII_ONLY, true)?)?;
	encrypted.set_totp("sealed", Some(epistle::totp::encode_base32(b"upgrade-contract-totp")))?;
	Ok(())
}
```
