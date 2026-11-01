//! The test executable also runs the isolated SMTP child used by SIGKILL cases.

use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, mpsc};

use epistle::smtp::server::Server;
use epistle::smtp::sink::MessageSink;
use epistle::storage::{FsSpool, LocalDelivery, MessageCrypto};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{crash_trace, support::*, wire};

const LINES: usize = 4096;

struct Process(Child);
impl Drop for Process {
	fn drop(&mut self) {
		let _ = self.0.kill();
		let _ = self.0.wait();
	}
}

fn child(root: &Path, mode: &str) -> (Process, SocketAddr, i32) {
	let process = Command::new(std::env::current_exe().expect("test executable"))
		.args([
			"--exact",
			"crash::child_server",
			"--ignored",
			"--nocapture",
			"--test-threads=1",
		])
		.env("EPISTLE_CC_CHILD_ROOT", root)
		.env("EPISTLE_CC_CHILD_MODE", mode)
		.stdout(Stdio::piped())
		.stderr(Stdio::inherit())
		.stdin(Stdio::null())
		.spawn()
		.expect("start real child process");
	let mut process = Process(process);
	let output = process.0.stdout.take().expect("child stdout");
	let (tx, rx) = mpsc::sync_channel(1);
	std::thread::spawn(move || {
		for line in std::io::BufReader::new(output).lines() {
			let line = line.expect("child output");
			if let Some((_, ready)) = line.split_once("CC_READY ") {
				let _ = tx.send(ready.to_string());
				return;
			}
		}
	});
	let ready = rx.recv_timeout(DEADLINE).expect("child readiness deadline");
	let (addr, tid) = ready.split_once(' ').expect("address and runtime tid");
	(
		process,
		addr.parse().expect("child address"),
		tid.parse().expect("child tid"),
	)
}

/// Run only when explicitly selected by the parent with a private store path.
#[test]
#[ignore = "subprocess entry point"]
fn child_server() {
	seed("sigkill-child");
	let Some(root) = std::env::var_os("EPISTLE_CC_CHILD_ROOT") else {
		return;
	};
	let root = std::path::PathBuf::from(root);
	let mode = std::env::var("EPISTLE_CC_CHILD_MODE").expect("child mode");
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.expect("child runtime");
	runtime.block_on(async {
		let directory = directory();
		let sink: Arc<dyn MessageSink> = match mode.as_str() {
			"spool" => {
				let spool =
					FsSpool::open_audited(&root, MessageCrypto::disabled()).expect("reopen spool");
				for staged in spool.leftovers(1024).expect("list staged entries") {
					spool
						.discard_leftover(staged.id)
						.expect("discard unacknowledged staging");
				}
				Arc::new(spool)
			}
			"mailbox" => {
				Arc::new(LocalDelivery::new(&root, directory.clone()).expect("reopen mailbox"))
			}
			_ => panic!("unknown child mode"),
		};
		let server = Arc::new(Server::new("mx.epistle.test", sink).with_directory(directory));
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
			.await
			.expect("child bind");
		// SAFETY: gettid has no arguments and only identifies this runtime thread.
		let tid = unsafe { libc::syscall(libc::SYS_gettid) };
		println!(
			"CC_READY {} {tid}",
			listener.local_addr().expect("child address")
		);
		std::io::stdout().flush().expect("flush readiness");
		server.serve(listener).await.expect("child SMTP server");
	});
}

/// The crashing connection tolerates only transport loss; a different SMTP
/// outcome is not evidence of a crash. The tracer independently proves SIGKILL.
async fn finish_during_kill(
	stream: &mut tokio::net::TcpStream,
	raw: &[u8],
) -> std::io::Result<Option<String>> {
	stream.write_all(raw).await?;
	stream.write_all(b".\r\n").await?;
	let mut reply = Vec::new();
	loop {
		let byte = stream.read_u8().await;
		match byte {
			Ok(byte) => reply.push(byte),
			Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof && reply.is_empty() => {
				return Ok(None);
			}
			Err(error) => return Err(error),
		}
		assert!(reply.len() <= 4096, "unbounded child reply");
		if reply.ends_with(b"\r\n") {
			return Ok(Some(String::from_utf8(reply).expect("SMTP ASCII")));
		}
	}
}

fn visible(root: &Path, mode: &str) -> Vec<Vec<u8>> {
	if mode == "mailbox" {
		return mailbox(root);
	}
	let spool =
		FsSpool::open_audited(root, MessageCrypto::disabled()).expect("open recovered spool");
	spool
		.list()
		.expect("list recovered queue")
		.into_iter()
		.map(|id| {
			let entry = spool
				.load(id)
				.expect("published envelope has complete body");
			assert_eq!(
				entry.envelope.id, id,
				"envelope identity matches its queue entry"
			);
			assert_eq!(entry.envelope.reverse_path, "sender@remote.test");
			assert_eq!(entry.envelope.recipients, ["tester@epistle.test"]);
			entry.data
		})
		.collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sigkill_during_spool_and_mailbox_writes_preserves_every_250() {
	seed("sigkill");
	let mut rng = SEED;
	for mode in ["spool", "mailbox"] {
		// Spool: body write/fsync, envelope write/fsync, two renames.
		// Mailbox: message write/fsync and publication rename.
		let mut cuts: Vec<usize> = (0..if mode == "spool" { 6 } else { 3 }).collect();
		for n in (1..cuts.len()).rev() {
			cuts.swap(n, next(&mut rng) as usize % (n + 1));
		}
		for cut in cuts {
			eprintln!("seed={SEED:#x} mode={mode} cut={cut}");
			let root = tempfile::tempdir().expect("crash store");
			let (mut process, addr, tid) = child(root.path(), mode);
			let mut stream = connect(addr).await;
			data(&mut stream, false).await;
			let mut baseline = message(0, LINES, false);
			baseline.extend_from_slice(b".\r\n");
			wire::send(&mut stream, &baseline).await;
			wire::expect(&mut stream, wire::OK).await;
			let mut accepted = BTreeMap::from([(0, 1)]);
			data(&mut stream, false).await;

			let temporary = root.path().join(if mode == "spool" {
				"spool/tmp"
			} else {
				"accounts/tester/tmp"
			});
			let pid = process.0.id() as i32;
			let (ready_tx, ready_rx) = mpsc::sync_channel(1);
			let tracer = std::thread::spawn(move || {
				crash_trace::kill_at(pid, tid, temporary, cut, ready_tx)
			});
			ready_rx
				.recv_timeout(DEADLINE)
				.expect("ptrace readiness; Linux ptrace permission required");
			let result = tokio::time::timeout(
				DEADLINE,
				finish_during_kill(&mut stream, &message(1, LINES, false)),
			)
			.await;
			let point = tracer
				.join()
				.expect("tracer thread")
				.expect("reach storage cut and SIGKILL");
			eprintln!("seed={SEED:#x} mode={mode} cut={cut} reached {point}");
			match result.expect("crash transport deadline") {
				Ok(Some(reply)) => {
					assert_eq!(reply, wire::OK, "seed={SEED:#x} unexpected child rejection");
					accepted.insert(1, 1);
				}
				Ok(None) => {}
				Err(error) => assert!(
					matches!(
						error.kind(),
						std::io::ErrorKind::ConnectionReset
							| std::io::ErrorKind::BrokenPipe
							| std::io::ErrorKind::UnexpectedEof
					),
					"unexpected crash transport error {error:?}"
				),
			}
			// Reap before reopening any storage. The tracer already checked SIGKILL
			// on the runtime thread; Child::wait reaps the process leader.
			let status = process.0.wait().expect("reap killed child");
			use std::os::unix::process::ExitStatusExt;
			assert_eq!(status.signal(), Some(libc::SIGKILL));

			let (restart, addr, _) = child(root.path(), mode);
			let mut fresh = connect(addr).await;
			data(&mut fresh, false).await;
			let mut recovery = message(2, LINES, false);
			recovery.extend_from_slice(b".\r\n");
			wire::send(&mut fresh, &recovery).await;
			wire::expect(&mut fresh, wire::OK).await;
			accepted.insert(2, 1);
			wire::quit(&mut fresh).await;
			let stored = inventory(visible(root.path(), mode), LINES, false);
			for (id, count) in &accepted {
				assert_eq!(
					stored.get(id),
					Some(count),
					"seed={SEED:#x} mode={mode} cut={cut} lost or duplicated 250 id={id}"
				);
			}
			for (id, count) in stored {
				assert!(
					id <= 2 && count == 1,
					"seed={SEED:#x} unknown or duplicate id={id}"
				);
			}
			drop(restart);
		}
	}
}
