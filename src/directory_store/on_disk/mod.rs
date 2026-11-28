//! The dynamic accounts as the file holds them now, for a check that has to
//! know whether anything still uses a domain.

use super::DynamicFile;

/// Every dynamic account's name and addresses as `accounts.toml` in
/// `data_dir` holds them. A file that is not there holds none; a file that
/// cannot be read or understood is an error, because a check that treats it as
/// empty would let a domain go that accounts still use.
pub fn dynamic_addresses_on_disk(
	data_dir: &std::path::Path,
) -> std::io::Result<Vec<(String, Vec<String>)>> {
	let text = match std::fs::read_to_string(data_dir.join("accounts.toml")) {
		Ok(text) => text,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
		Err(error) => return Err(error),
	};
	let file: DynamicFile = toml::from_str(&text)
		.map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
	Ok(file
		.accounts
		.into_iter()
		.map(|account| (account.name, account.addresses))
		.collect())
}
