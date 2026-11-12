//! The hot-swappable directory handle.

use std::sync::{Arc, RwLock};

use crate::smtp::directory::Directory;

/// Hot-swappable view of the directory. Cheap to clone; readers snapshot.
#[derive(Clone)]
pub struct DirectoryHandle {
	inner: Arc<RwLock<Arc<Directory>>>,
}

impl std::fmt::Debug for DirectoryHandle {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("DirectoryHandle")
	}
}

impl DirectoryHandle {
	/// Wrap an initial directory.
	pub fn new(directory: Directory) -> Self {
		DirectoryHandle {
			inner: Arc::new(RwLock::new(Arc::new(directory))),
		}
	}

	/// The current directory snapshot.
	pub fn current(&self) -> Arc<Directory> {
		Arc::clone(&self.inner.read().expect("directory lock"))
	}

	/// Replace the directory.
	pub fn replace(&self, directory: Directory) {
		*self.inner.write().expect("directory lock") = Arc::new(directory);
	}
}
