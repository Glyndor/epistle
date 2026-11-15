//! Making a stored resource appear whole. A body is written to a staging
//! file in the destination's directory and then renamed onto its name, so a
//! `GET` or a `REPORT` that opens the name sees either the old file or the
//! complete new one, never a part of it. Staging files carry a reserved
//! suffix (see [`super::super::sync::is_internal`]), so listings skip them
//! and no request can name one.

use std::io;
use std::path::{Path, PathBuf};

use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncWriteExt;

use super::super::sync;

/// A fresh staging name next to `target`.
fn staging_for(target: &Path) -> PathBuf {
	target.with_file_name(format!(".{}{}", uuid::Uuid::now_v7(), sync::STAGING_SUFFIX))
}

/// Create the staging file: new, and never through a link at that name.
async fn create_staging(staging: &Path) -> io::Result<File> {
	OpenOptions::new()
		.write(true)
		.create_new(true)
		.custom_flags(libc::O_NOFOLLOW)
		.open(staging)
		.await
}

/// Rename `staging` onto `target`, removing it when that fails.
async fn publish(staging: &Path, target: &Path) -> io::Result<()> {
	let renamed = tokio::fs::rename(staging, target).await;
	if renamed.is_err() {
		let _ = tokio::fs::remove_file(staging).await;
	}
	renamed
}

/// Store `body` as `target`, replacing any file there in one step.
pub(super) async fn write(target: &Path, body: &[u8]) -> io::Result<()> {
	let staging = staging_for(target);
	let mut file = create_staging(&staging).await?;
	let written = async {
		file.write_all(body).await?;
		file.flush().await
	}
	.await;
	drop(file);
	if let Err(error) = written {
		let _ = tokio::fs::remove_file(&staging).await;
		return Err(error);
	}
	publish(&staging, target).await
}

/// Copy the file `source` to `target`, keeping its permissions and
/// replacing any file at `target` in one step. The source is opened without
/// following a link.
pub(super) async fn copy(source: &Path, target: &Path) -> io::Result<()> {
	let mut from = OpenOptions::new()
		.read(true)
		.custom_flags(libc::O_NOFOLLOW)
		.open(source)
		.await?;
	let permissions = from.metadata().await?.permissions();
	let staging = staging_for(target);
	let mut to = create_staging(&staging).await?;
	let copied = async {
		tokio::io::copy(&mut from, &mut to).await?;
		to.flush().await?;
		to.set_permissions(permissions).await
	}
	.await;
	drop(to);
	if let Err(error) = copied {
		let _ = tokio::fs::remove_file(&staging).await;
		return Err(error);
	}
	publish(&staging, target).await
}

/// Move the file `source` onto `target` with one rename, falling back to a
/// copy and a removal when the two are on different filesystems.
pub(super) async fn relocate(source: &Path, target: &Path) -> io::Result<()> {
	match tokio::fs::rename(source, target).await {
		Err(error) if error.kind() == io::ErrorKind::CrossesDevices => {
			copy(source, target).await?;
			tokio::fs::remove_file(source).await
		}
		other => other,
	}
}
