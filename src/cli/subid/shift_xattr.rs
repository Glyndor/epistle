//! The two extended attribute calls the ownership shift needs, on the link
//! itself rather than its target.

use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

fn c_path(path: &Path) -> io::Result<CString> {
	CString::new(path.as_os_str().as_bytes())
		.map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

/// The value of attribute `name`, or `None` when the file has none or the
/// filesystem keeps no extended attributes.
pub(super) fn get(path: &Path, name: &str) -> io::Result<Option<Vec<u8>>> {
	let c_path = c_path(path)?;
	let c_name = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
	let mut buffer = vec![0u8; 256];
	loop {
		// SAFETY: both names are NUL-terminated and the buffer outlives the call
		// with its length passed alongside.
		let length = unsafe {
			libc::lgetxattr(
				c_path.as_ptr(),
				c_name.as_ptr(),
				buffer.as_mut_ptr().cast(),
				buffer.len(),
			)
		};
		if length >= 0 {
			buffer.truncate(length as usize);
			return Ok(Some(buffer));
		}
		let error = io::Error::last_os_error();
		match error.raw_os_error() {
			Some(libc::ENODATA) | Some(libc::ENOTSUP) => return Ok(None),
			Some(libc::ERANGE) if buffer.len() < 1 << 16 => buffer.resize(buffer.len() * 4, 0),
			_ => return Err(error),
		}
	}
}

/// Set attribute `name` to `value`.
pub(super) fn set(path: &Path, name: &str, value: &[u8]) -> io::Result<()> {
	let c_path = c_path(path)?;
	let c_name = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
	// SAFETY: both names are NUL-terminated and `value` is valid for its length.
	let rc = unsafe {
		libc::lsetxattr(
			c_path.as_ptr(),
			c_name.as_ptr(),
			value.as_ptr().cast(),
			value.len(),
			0,
		)
	};
	if rc == 0 {
		Ok(())
	} else {
		Err(io::Error::last_os_error())
	}
}
