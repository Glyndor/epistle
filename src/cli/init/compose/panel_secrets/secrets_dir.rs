use std::io;
use std::path::Path;

/// Create the secrets directory `dir` (`0700`) and refuse one that resolves
/// into `data_dir`.
///
/// The directory is its own root: it may be a link to another disk, which
/// deployments do use. What it must not be is a link into the data dir, which
/// is mounted into containers and backed up, so the secrets would end up
/// there. The check runs before anything is created or tightened.
pub(super) fn create(dir: &Path, data_dir: &Path) -> io::Result<()> {
	if let (Ok(resolved), Ok(data)) = (dir.canonicalize(), data_dir.canonicalize())
		&& resolved.starts_with(&data)
	{
		return Err(io::Error::new(
			io::ErrorKind::InvalidInput,
			"the secrets directory resolves inside the data directory",
		));
	}
	crate::storage::create_private_dir(dir, dir)
}
