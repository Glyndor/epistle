//! Which tenant an account's stored mail belongs to, and the tenant keys
//! read from `[[tenant]] encryption_key_file`.

use std::path::Path;

use zeroize::Zeroizing;

use super::keyring::{KeyOwner, Keyring, StoredKey};
use super::{CryptoError, decode_key_text};

/// Where the account to address mapping comes from. The directory provides
/// it in the server and in the CLI; [`MessageCrypto`](super::MessageCrypto)
/// only asks it when a write has to pick a tenant key.
pub trait AccountAddresses: Send + Sync {
	/// The addresses `account` receives at.
	fn addresses_for(&self, account: &str) -> Vec<String>;
}

impl AccountAddresses for crate::directory_store::DirectoryHandle {
	fn addresses_for(&self, account: &str) -> Vec<String> {
		self.current().addresses_for(account)
	}
}

/// The tenant an account resolves to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TenantChoice {
	/// No address of the account is in a tenant domain.
	None,
	/// Every tenant address of the account is in this one tenant.
	One(String),
	/// The account has addresses in more than one tenant. Its mail stays on
	/// the server key: picking one tenant would hand that tenant's key the
	/// mail of the other, and the account can still be split by address.
	Several(Vec<String>),
}

/// Resolve `addresses` against the domain to tenant map of `keys`.
pub(super) fn choose(keys: &Keyring, addresses: &[String]) -> TenantChoice {
	let mut found: Vec<String> = Vec::new();
	for address in addresses {
		let Some((_, domain)) = address.rsplit_once('@') else {
			continue;
		};
		if let Some(tenant) = keys.domains.get(&domain.to_ascii_lowercase())
			&& !found.contains(tenant)
		{
			found.push(tenant.clone());
		}
	}
	match found.len() {
		0 => TenantChoice::None,
		1 => TenantChoice::One(found.remove(0)),
		_ => {
			found.sort();
			TenantChoice::Several(found)
		}
	}
}

/// Load every `[[tenant]]` key into `keys` and record the domain map.
///
/// Fails closed: a configured key file that cannot be read, is readable by
/// group or others, does not hold a 32-byte key, or repeats another key
/// stops the load, so the server refuses to start rather than writing a
/// tenant's mail under the wrong key.
pub(super) fn load(
	keys: &mut Keyring,
	tenants: &[crate::config::Tenant],
) -> Result<(), CryptoError> {
	for tenant in tenants {
		if let Some(name) = &tenant.name {
			for domain in &tenant.domains {
				keys.domains
					.insert(domain.to_ascii_lowercase(), name.clone());
			}
		}
		let Some(path) = &tenant.encryption_key_file else {
			continue;
		};
		let Some(name) = &tenant.name else {
			return Err(CryptoError::TenantUnnamed);
		};
		let bytes = read_private_key_file(path)?;
		keys.insert(StoredKey::new(&bytes, KeyOwner::Tenant(name.clone()))?)?;
	}
	Ok(())
}

/// Read a key file that must not be readable by group or others.
pub(super) fn read_private_key_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
	use std::os::unix::fs::PermissionsExt;
	let key_file = |source| CryptoError::KeyFile {
		path: path.to_path_buf(),
		source,
	};
	let mode = std::fs::metadata(path)
		.map_err(key_file)?
		.permissions()
		.mode();
	if mode & 0o077 != 0 {
		return Err(CryptoError::KeyFilePermissions {
			path: path.to_path_buf(),
			mode: mode & 0o777,
		});
	}
	let raw: Zeroizing<String> = Zeroizing::new(std::fs::read_to_string(path).map_err(key_file)?);
	decode_key_text(raw.trim())
}
