use std::net::{IpAddr, SocketAddr};

use super::check;

/// A resolver that answers every name with `ips` on the requested port.
fn fixed(
	ips: &'static [&'static str],
) -> impl FnOnce(String, u16) -> std::future::Ready<std::io::Result<Vec<SocketAddr>>> {
	move |_host, port| {
		std::future::ready(Ok(ips
			.iter()
			.map(|ip| SocketAddr::new(ip.parse::<IpAddr>().expect("ip"), port))
			.collect()))
	}
}

fn refused(result: Result<super::CheckedTarget, String>) -> String {
	match result {
		Ok(target) => panic!("target {} must be refused", target.host),
		Err(reason) => reason,
	}
}

#[tokio::test]
async fn a_name_resolving_only_to_global_addresses_is_accepted() {
	let target = check(
		"https://reports.example.net/v1/tlsrpt",
		fixed(&["192.0.2.1"]),
	)
	.await
	.map_err(|reason| reason.to_string());
	// 192.0.2.0/24 is documentation space, refused; use a real global one.
	assert!(
		target.is_err(),
		"documentation space is not a public destination"
	);
	let target = check(
		"https://reports.example.net/v1/tlsrpt",
		fixed(&["8.8.8.8", "2001:4860:4860::8888"]),
	)
	.await
	.expect("all addresses global");
	assert_eq!(target.host, "reports.example.net");
	assert_eq!(target.addrs.len(), 2, "every checked address is pinned");
	assert!(target.addrs.iter().all(|addr| addr.port() == 443));
}

#[tokio::test]
async fn internal_destinations_are_refused() {
	for ip in [
		"127.0.0.1",
		"10.0.0.5",
		"172.16.3.4",
		"192.168.1.10",
		"169.254.169.254",
		"100.64.0.1",
		"0.0.0.0",
		"::1",
		"fe80::1",
		"fd00::1",
		"::ffff:127.0.0.1",
	] {
		let resolver = move |_host: String, port: u16| {
			std::future::ready(Ok(vec![SocketAddr::new(
				ip.parse::<IpAddr>().expect("ip"),
				port,
			)]))
		};
		let reason = refused(check("https://reports.example.net/", resolver).await);
		assert!(
			reason.contains(ip.trim_start_matches("::ffff:")) || reason.contains(ip),
			"{ip}: the refusal names the address, got: {reason}"
		);
	}
}

#[tokio::test]
async fn one_internal_address_among_global_ones_is_refused() {
	let reason = refused(
		check(
			"https://reports.example.net/",
			fixed(&["8.8.8.8", "169.254.169.254"]),
		)
		.await,
	);
	assert!(reason.contains("169.254.169.254"), "{reason}");
}

#[tokio::test]
async fn ip_literals_are_checked_without_resolving() {
	let never = |_host: String, _port: u16| async {
		panic!("an IP literal must not be resolved");
		#[allow(unreachable_code)]
		Ok::<Vec<SocketAddr>, std::io::Error>(Vec::new())
	};
	refused(check("https://127.0.0.1:8443/", never).await);
	let never = |_host: String, _port: u16| async {
		panic!("an IP literal must not be resolved");
		#[allow(unreachable_code)]
		Ok::<Vec<SocketAddr>, std::io::Error>(Vec::new())
	};
	refused(check("https://[::1]/", never).await);
}

#[tokio::test]
async fn plain_http_and_unresolvable_names_are_refused() {
	refused(check("http://reports.example.net/", fixed(&["8.8.8.8"])).await);
	let reason = refused(check("https://reports.example.net/", fixed(&[])).await);
	assert!(reason.contains("no address"), "{reason}");
}

/// The production poster runs the check before any connection: a loopback
/// destination fails with the refusal, not with a connection error.
#[tokio::test]
async fn the_production_poster_refuses_before_connecting() {
	use crate::tlsrpt::send::{HttpsPoster, ReportPoster};
	let poster = HttpsPoster::new().expect("poster");
	let reason = poster
		.post("https://127.0.0.1:9/tlsrpt", b"report")
		.await
		.expect_err("loopback must be refused");
	assert!(
		reason.contains("127.0.0.1 resolves to 127.0.0.1"),
		"the poster must refuse through the target check, got: {reason}"
	);
}
