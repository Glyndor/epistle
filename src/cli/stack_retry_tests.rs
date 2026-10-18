use super::*;
use std::cell::{Cell, RefCell};

fn failed(text: &str) -> std::io::Result<Run> {
	Ok(Run {
		success: false,
		tail: text.to_string(),
	})
}

fn ok() -> std::io::Result<Run> {
	Ok(Run {
		success: true,
		tail: String::new(),
	})
}

const DROPPED: &str =
	"podup: error: podman error: http error: connection closed before message completed";

#[test]
fn only_connection_errors_count_as_dropped() {
	assert!(is_dropped_connection(DROPPED));
	assert!(is_dropped_connection("Connection refused (os error 111)"));
	assert!(!is_dropped_connection("error: image not found"));
	assert!(!is_dropped_connection(
		"error: port 25 is already allocated"
	));
}

#[test]
fn a_dropped_connection_is_retried_after_the_api_answers() {
	let runs = Cell::new(0);
	let waits = Cell::new(0);
	let notes = RefCell::new(Vec::new());
	let result = with_retries(
		|| {
			runs.set(runs.get() + 1);
			if runs.get() < 3 {
				failed(DROPPED)
			} else {
				ok()
			}
		},
		|| {
			waits.set(waits.get() + 1);
			true
		},
		|line| notes.borrow_mut().push(line.to_string()),
	);
	assert_eq!(result, Ok(()));
	assert_eq!((runs.get(), waits.get()), (3, 2));
	assert_eq!(notes.borrow().len(), 2);
}

#[test]
fn a_real_failure_is_not_retried() {
	let runs = Cell::new(0);
	let result = with_retries(
		|| {
			runs.set(runs.get() + 1);
			failed("error: image not found")
		},
		|| panic!("must not wait for the API"),
		|_| {},
	);
	assert_eq!(
		result,
		Err("it exited with an error, shown above".to_string())
	);
	assert_eq!(runs.get(), 1);
}

#[test]
fn the_attempts_are_bounded_and_the_last_failure_says_so() {
	let runs = Cell::new(0);
	let result = with_retries(
		|| {
			runs.set(runs.get() + 1);
			failed(DROPPED)
		},
		|| true,
		|_| {},
	);
	assert_eq!(runs.get(), ATTEMPTS);
	assert!(result.unwrap_err().contains("4 times in a row"));
}

#[test]
fn an_api_that_never_answers_ends_the_retries() {
	let runs = Cell::new(0);
	let result = with_retries(
		|| {
			runs.set(runs.get() + 1);
			failed(DROPPED)
		},
		|| false,
		|_| {},
	);
	assert_eq!(runs.get(), 1);
	assert!(result.unwrap_err().contains("did not answer"));
}

#[test]
fn ping_reads_a_200_and_refuses_anything_else() {
	use std::os::unix::net::UnixListener;
	let dir = tempfile::tempdir().unwrap();
	let socket = dir.path().join("podman.sock");
	assert!(!ping(&socket, Duration::from_millis(200)), "no listener");
	let listener = UnixListener::bind(&socket).unwrap();
	let server = std::thread::spawn(move || {
		for reply in [
			&b"HTTP/1.1 200 OK\r\n\r\nOK"[..],
			&b"HTTP/1.1 500 Oops\r\n\r\n"[..],
		] {
			let (mut stream, _) = listener.accept().unwrap();
			let mut request = [0u8; 256];
			let _ = stream.read(&mut request);
			stream.write_all(reply).unwrap();
		}
	});
	assert!(ping(&socket, Duration::from_secs(2)));
	assert!(!ping(&socket, Duration::from_secs(2)));
	server.join().unwrap();
}

#[test]
fn wait_until_gives_up_at_the_deadline() {
	let polls = Cell::new(0);
	assert!(!wait_until(
		Duration::from_millis(60),
		Duration::from_millis(20),
		|| {
			polls.set(polls.get() + 1);
			false
		}
	));
	assert!(polls.get() >= 2);
	assert!(wait_until(
		Duration::from_secs(1),
		Duration::from_millis(10),
		|| true
	));
}
