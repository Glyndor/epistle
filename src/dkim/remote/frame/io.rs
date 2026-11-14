//! Reading one frame off a stream.

use tokio::io::{AsyncRead, AsyncReadExt};

/// Why a frame could not be read off the stream.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ReadError {
	/// The length prefix announces more than the cap. Nothing past the
	/// prefix was read or allocated.
	#[error("the frame announces {0} bytes, over the cap")]
	TooLarge(u32),
	/// The stream failed or closed before the whole frame arrived.
	#[error("{0}")]
	Io(#[from] std::io::Error),
}

/// Read one frame body of at most `cap` bytes: the 4-byte big-endian
/// length, checked against `cap` before the buffer is allocated, then
/// exactly that many bytes. The caller bounds the time it takes.
pub(crate) async fn read_frame<R: AsyncRead + Unpin>(
	reader: &mut R,
	cap: usize,
) -> Result<Vec<u8>, ReadError> {
	let mut prefix = [0u8; 4];
	reader.read_exact(&mut prefix).await?;
	let announced = u32::from_be_bytes(prefix);
	let len = usize::try_from(announced).map_err(|_| ReadError::TooLarge(announced))?;
	if len > cap {
		return Err(ReadError::TooLarge(announced));
	}
	let mut body = vec![0u8; len];
	reader.read_exact(&mut body).await?;
	Ok(body)
}
