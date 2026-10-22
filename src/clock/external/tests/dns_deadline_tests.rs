//! Measure process exit, including runtime shutdown, under a slow system resolver.

#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[test]
fn review_dns_deadline_bounds_process_exit() {
	use std::process::{Command, Stdio};
	use std::time::{Duration, Instant};
	const CHILD: &str = "EPISTLE_CLOCK_DNS_DEADLINE_CHILD";
	if std::env::var_os(CHILD).is_some() {
		let runtime = tokio::runtime::Runtime::new().unwrap();
		runtime.block_on(async {
			let source = crate::clock::external::Source::nts("clock-delay.invalid");
			let _ = super::ke_then_ntp(&source, Duration::from_millis(80)).await;
		});
		drop(runtime);
		return;
	}
	let dir = tempfile::tempdir().unwrap();
	let source = dir.path().join("delay.c");
	let library = dir.path().join("delay.so");
	std::fs::write(
		&source,
		r#"
#include <netdb.h>
#include <string.h>
#include <unistd.h>
int getaddrinfo(const char *name, const char *service,
                const struct addrinfo *hints, struct addrinfo **result) {
    (void)service; (void)hints; (void)result;
    if (name && strcmp(name, "clock-delay.invalid") == 0) usleep(1000000);
    return EAI_NONAME;
}
"#,
	)
	.unwrap();
	assert!(
		Command::new("cc")
			.args(["-shared", "-fPIC", "-o"])
			.arg(&library)
			.arg(&source)
			.status()
			.unwrap()
			.success()
	);
	let started = Instant::now();
	let mut child = Command::new(std::env::current_exe().unwrap())
		.args([
			"--exact",
			"clock::external::adapter::dns_deadline_tests::review_dns_deadline_bounds_process_exit",
		])
		.env(CHILD, "1")
		.env("LD_PRELOAD", &library)
		.stdout(Stdio::null())
		.spawn()
		.unwrap();
	let status = loop {
		if let Some(status) = child.try_wait().unwrap() {
			break status;
		}
		if started.elapsed() > Duration::from_secs(3) {
			child.kill().unwrap();
			child.wait().unwrap();
			panic!("DNS left the process running past its deadline");
		}
		std::thread::sleep(Duration::from_millis(10));
	};
	assert!(status.success());
	assert!(
		started.elapsed() < Duration::from_millis(600),
		"runtime shutdown waited for system DNS: {:?}",
		started.elapsed()
	);
}
