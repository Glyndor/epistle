use tokio::io::{AsyncRead, AsyncWrite};

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub type Stream = Box<dyn Io>;

/// Opt-in only: this sandbox cannot bind sockets. TCP mode also keeps wall
/// time running, since Tokio's automatic virtual-time advance cannot see
/// packets queued in the OS. Set this before starting the test process.
pub fn tcp_mode() -> bool {
	std::env::var("EPISTLE_HOSTILE_HTTP_TCP").is_ok_and(|value| value == "1")
}
