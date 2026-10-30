//! Tests for the source configuration: defaults, validation rules and
//! the effective resolution.

use crate::clock::external::source::{
	ClockExternal, DEFAULT_FAIL_SECONDS, DEFAULT_WARN_SECONDS, Source, SourceKind, default_sources,
};

#[test]
fn default_source_list_is_three_independent_providers() {
	let sources = default_sources();
	assert_eq!(sources.len(), 3);
	let hosts: Vec<&str> = sources.iter().map(|source| source.host.as_str()).collect();
	assert_eq!(hosts, ["nts.netnod.se", "nts.time.nl", "ptbtime2.ptb.de"]);
}

/// The shipped list is three NTS sources from three operators, so every
/// offset of a default run is authenticated. An operator can change the
/// protocol per source, so a list with plain entries is a valid choice too
/// and the defaults must not be the only shape that loads.
#[test]
fn default_source_list_is_all_authenticated() {
	let sources = default_sources();
	assert!(
		sources.iter().all(|source| source.kind == SourceKind::Nts),
		"the default list must not carry an unauthenticated source"
	);
	assert!(ClockExternal::default().validate().is_ok());
}

#[test]
fn default_thresholds_match_design() {
	assert!((DEFAULT_WARN_SECONDS - 1.0).abs() < f64::EPSILON);
	assert!((DEFAULT_FAIL_SECONDS - 5.0).abs() < f64::EPSILON);
}

#[test]
fn validate_rejects_zero_warn() {
	let external = ClockExternal {
		warn_seconds: 0.0,
		..ClockExternal::default()
	};
	assert!(external.validate().is_err());
}

#[test]
fn validate_rejects_warn_at_or_above_fail() {
	let external = ClockExternal {
		warn_seconds: 5.0,
		fail_seconds: 5.0,
		..ClockExternal::default()
	};
	assert!(external.validate().is_err());
	let external = ClockExternal {
		warn_seconds: 6.0,
		fail_seconds: 5.0,
		..ClockExternal::default()
	};
	assert!(external.validate().is_err());
}

#[test]
fn validate_rejects_non_finite_thresholds() {
	let external = ClockExternal {
		warn_seconds: f64::NAN,
		..ClockExternal::default()
	};
	assert!(external.validate().is_err());
	let external = ClockExternal {
		warn_seconds: 1.0,
		fail_seconds: f64::INFINITY,
		..ClockExternal::default()
	};
	assert!(external.validate().is_err());
}

#[test]
fn validate_rejects_wrong_source_count() {
	let mut sources = default_sources();
	sources.pop();
	let external = ClockExternal {
		sources,
		..ClockExternal::default()
	};
	assert!(external.validate().is_err());
}

#[test]
fn validate_rejects_a_list_without_an_authenticated_source() {
	let sources = vec![
		Source::ntp("time.cloudflare.com"),
		Source::ntp("time.google.com"),
		Source::ntp("pool.ntp.example"),
	];
	let external = ClockExternal {
		sources,
		..ClockExternal::default()
	};
	assert!(external.validate().is_err());
}

#[test]
fn validate_accepts_one_nts_and_two_ntp() {
	let sources = vec![
		Source::ntp("time.cloudflare.com"),
		Source::nts("nts.netnod.se"),
		Source::ntp("time.google.com"),
	];
	let external = ClockExternal {
		sources,
		..ClockExternal::default()
	};
	assert!(
		external.validate().is_ok(),
		"the operator picks the protocol per source; one NTS with two plain \
		 sources must load; got {:?}",
		external.validate()
	);
}

#[test]
fn validate_accepts_three_nts_sources() {
	let sources = vec![
		Source::nts("nts.netnod.se"),
		Source::nts("nts.time.nl"),
		Source::nts("ntp.3eck.net"),
	];
	let external = ClockExternal {
		sources,
		..ClockExternal::default()
	};
	assert!(
		external.validate().is_ok(),
		"an all-authenticated list is a legitimate choice; got {:?}",
		external.validate()
	);
}

#[test]
fn validate_rejects_duplicate_hosts_case_insensitively() {
	let sources = vec![
		Source::nts("time.cloudflare.com"),
		Source::nts("Time.Cloudflare.com"),
		Source::ntp("time.google.com"),
	];
	let external = ClockExternal {
		sources,
		..ClockExternal::default()
	};
	assert!(external.validate().is_err());
}

#[test]
fn validate_rejects_empty_host() {
	let sources = vec![
		Source::nts(""),
		Source::nts("nts.netnod.se"),
		Source::ntp("time.google.com"),
	];
	let external = ClockExternal {
		sources,
		..ClockExternal::default()
	};
	assert!(external.validate().is_err());
}

#[test]
fn validate_accepts_a_well_formed_list() {
	let external = ClockExternal::default();
	assert!(external.validate().is_ok());
}

#[test]
fn dial_port_returns_the_default_when_unset() {
	let nts = Source::nts("a.example");
	let ntp = Source::ntp("a.example");
	assert_eq!(nts.dial_port(), 4460);
	assert_eq!(ntp.dial_port(), 123);
}

#[test]
fn dial_port_returns_the_override_when_set() {
	let nts = Source {
		port: Some(12345),
		..Source::nts("a.example")
	};
	assert_eq!(nts.dial_port(), 12345);
}

#[test]
fn effective_falls_back_to_defaults_when_zero() {
	let external = ClockExternal {
		warn_seconds: 0.0,
		fail_seconds: 0.0,
		sources: vec![],
		..ClockExternal::default()
	};
	let resolved = external.effective_sources();
	assert_eq!(resolved.len(), 3);
	assert!((external.effective_warn() - DEFAULT_WARN_SECONDS).abs() < f64::EPSILON);
	assert!((external.effective_fail() - DEFAULT_FAIL_SECONDS).abs() < f64::EPSILON);
}

#[test]
fn sabotage_warn_equals_fail_still_fails() {
	let external = ClockExternal {
		warn_seconds: 5.0,
		fail_seconds: 5.0,
		..ClockExternal::default()
	};
	assert!(external.validate().is_err());
}

#[test]
fn review_rejects_internal_and_non_unicast_sources_by_default() {
	for host in [
		"localhost",
		"LOCALHOST.",
		"127.0.0.1",
		"10.0.0.1",
		"172.16.0.1",
		"192.168.0.1",
		"169.254.169.254",
		"224.0.0.1",
		"255.255.255.255",
		"0.0.0.0",
		"::",
		"::1",
		"fc00::1",
		"fe80::1",
		"ff02::1",
		"::ffff:127.0.0.1",
	] {
		let mut config = ClockExternal::default();
		config.sources[0] = Source::ntp(host);
		assert!(config.validate().is_err(), "accepted {host}");
	}
}

#[test]
fn review_rejects_arbitrary_and_zero_ports_by_default() {
	for (kind, port) in [
		(SourceKind::Ntp, 0),
		(SourceKind::Ntp, 6379),
		(SourceKind::Nts, 123),
	] {
		let mut config = ClockExternal::default();
		config.sources[0] = Source {
			host: "time.example".into(),
			kind,
			port: Some(port),
		};
		assert!(config.validate().is_err(), "accepted {kind}:{port}");
	}
}

#[test]
fn review_private_networks_require_explicit_operator_consent() {
	let mut config: ClockExternal =
		toml::from_str("allow_private_networks = true\nallowed_ports = [6379]").unwrap();
	for host in [
		"localhost",
		"127.0.0.1",
		"10.0.0.1",
		"169.254.0.1",
		"::1",
		"fc00::1",
		"fe80::1",
	] {
		config.sources[0] = Source {
			port: Some(6379),
			..Source::ntp(host)
		};
		assert!(config.validate().is_ok(), "{host}");
	}
	for host in ["224.0.0.1", "255.255.255.255", "0.0.0.0", "ff02::1", "::"] {
		config.sources[0] = Source::ntp(host);
		assert!(config.validate().is_err(), "{host}");
	}
	config.sources[0] = Source {
		port: Some(0),
		..Source::ntp("127.0.0.1")
	};
	assert!(config.validate().is_err());
}

/// A public NTS-KE that hands out a port other than the standard one, or a
/// plain NTP source on a port of its own, needs the port named. Allowing
/// internal addresses is a different decision and does not carry it.
#[test]
fn review_a_custom_port_needs_its_own_opt_in() {
	let mut config = ClockExternal::default();
	config.sources[0] = Source {
		host: "time.example".into(),
		kind: SourceKind::Ntp,
		port: Some(6379),
	};
	assert!(config.validate().is_err(), "a custom port needs a name");
	config.allow_private_networks = true;
	assert!(
		config.validate().is_err(),
		"the internal-address opt-in must not open ports"
	);
	config.allowed_ports = vec![6379];
	assert!(config.validate().is_ok(), "the listed port is allowed");
	// The list names ports, not addresses: an internal destination still
	// needs its own opt-in.
	config.sources[0] = Source {
		host: "10.0.0.1".into(),
		kind: SourceKind::Ntp,
		port: Some(6379),
	};
	config.allow_private_networks = false;
	assert!(
		config.validate().is_err(),
		"an internal address stays refused"
	);
	config.allow_private_networks = true;
	assert!(config.validate().is_ok());
}

#[test]
fn review_the_allowed_port_list_refuses_zero_and_repeats() {
	for ports in [vec![0], vec![123, 123], vec![4460, 0]] {
		let config = ClockExternal {
			allowed_ports: ports.clone(),
			..ClockExternal::default()
		};
		assert!(
			config.validate().is_err(),
			"allowed_ports = {ports:?} must be refused"
		);
	}
}
