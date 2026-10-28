	use super::*;

	fn validate(settings: &str) -> Result<(), String> {
		let config: Config = toml::from_str(&format!(
			"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n{settings}"
		))
		.expect("parse");
		config.validate().map_err(|error| error.to_string())
	}

	#[test]
	fn excessive_listener_caps_are_rejected_by_configuration_validation() {
		for key in ["max_connections_per_listener", "max_http_connections"] {
			for value in [1_000_001_u64, 9_223_372_036_854_775_807] {
				let error = validate(&format!("{key} = {value}")).expect_err("excessive cap");
				assert!(error.contains(key) && error.contains("1000000"), "{error}");
			}
			for value in [0, 1, 1_000_000] {
				assert_eq!(validate(&format!("{key} = {value}")), Ok(()));
			}
		}
	}

	#[test]
	fn a_budget_smaller_than_the_largest_message_is_refused() {
		let error = validate("max_message_size = 26214400\nmessage_memory_budget = 10485760")
			.expect_err("refused");
		assert!(
			error.contains("message_memory_budget") && error.contains("max_message_size"),
			"the refusal names both keys: {error}"
		);
	}

	#[test]
	fn a_derived_budget_holds_any_message_up_to_its_ceiling() {
		assert_eq!(
			validate("max_message_size = 314572800"),
			Ok(()),
			"the derived budget rises to one 300 MiB message"
		);
		assert_eq!(validate("max_message_size = 1073741824"), Ok(()));
		assert_eq!(
			validate("max_message_size = 1073741825"),
			Err(
				"invalid configuration: max_message_size (1073741825 bytes) is larger than \
				 the 1073741824 bytes a derived message_memory_budget can reach; set \
				 message_memory_budget to at least max_message_size, or to 0 to turn the \
				 budget off"
					.to_string()
			)
		);
	}

	#[test]
	fn caps_that_fit_together_are_accepted() {
		assert_eq!(validate(""), Ok(()));
		assert_eq!(
			validate("max_message_size = 10485760\nmessage_memory_budget = 10485760"),
			Ok(())
		);
		assert_eq!(
			validate("max_message_size = 314572800\nmessage_memory_budget = 0"),
			Ok(()),
			"a budget turned off holds any size"
		);
		assert_eq!(
			validate("max_message_size = 0"),
			Ok(()),
			"0 is the default size"
		);
	}

	#[test]
	fn a_rate_floor_and_grace_in_range_are_accepted() {
		for settings in [
			"min_data_rate = 0",
			"min_data_rate = 20480\ndata_rate_grace = 300",
			"min_data_rate = 1073741824",
			"data_rate_grace = 1",
			"data_rate_grace = 3600",
		] {
			assert_eq!(validate(settings), Ok(()), "{settings}");
		}
	}

	#[test]
	fn a_grace_outside_one_second_to_an_hour_is_refused() {
		// No grace cuts every client before its first octet arrives; a
		// grace longer than an hour gives a slow client its reservation
		// back for that long.
		for settings in ["data_rate_grace = 0", "data_rate_grace = 3601"] {
			assert_eq!(
				validate(settings),
				Err(
					"invalid configuration: data_rate_grace must be between 1 and 3600 seconds"
						.to_string()
				),
				"{settings}"
			);
		}
	}

	#[test]
	fn session_limits_in_range_are_accepted() {
		for settings in [
			"junk_command_limit = 0",
			"junk_command_limit = 10",
			"junk_command_limit = 10000",
			"max_session_time = 0",
			"max_session_time = 60",
			"max_session_time = 86400",
		] {
			assert_eq!(validate(settings), Ok(()), "{settings}");
		}
	}

	#[test]
	fn a_junk_command_limit_outside_ten_to_ten_thousand_is_refused() {
		// Under ten a client that sends RSET before each message is cut
		// after a handful; past ten thousand the limit no longer bounds
		// anything.
		for settings in ["junk_command_limit = 9", "junk_command_limit = 10001"] {
			assert_eq!(
				validate(settings),
				Err("invalid configuration: junk_command_limit must be 0 (off) or between 10 and 10000"
					.to_string()),
				"{settings}"
			);
		}
	}

	#[test]
	fn a_session_time_outside_a_minute_to_a_day_is_refused() {
		for settings in ["max_session_time = 59", "max_session_time = 86401"] {
			assert_eq!(
				validate(settings),
				Err("invalid configuration: max_session_time must be 0 (off) or between 60 and 86400 seconds"
					.to_string()),
				"{settings}"
			);
		}
	}

	#[test]
	fn a_preauth_timeout_outside_five_seconds_to_an_hour_is_refused() {
		for settings in [
			"preauth_timeout = 0",
			"preauth_timeout = 4",
			"preauth_timeout = 3601",
		] {
			assert_eq!(
				validate(settings),
				Err(
					"invalid configuration: preauth_timeout must be between 5 and 3600 seconds"
						.to_string()
				),
				"{settings}"
			);
		}
		for settings in ["preauth_timeout = 5", "preauth_timeout = 3600"] {
			assert_eq!(validate(settings), Ok(()), "{settings}");
		}
	}

	#[test]
	fn a_floor_above_one_gib_per_second_is_refused() {
		assert_eq!(
			validate("min_data_rate = 1073741825"),
			Err("invalid configuration: min_data_rate must be at most 1073741824 bytes per second (0 turns it off)"
				.to_string())
		);
	}
	#[test]
	fn a_recipient_cap_below_one_hundred_is_refused_with_the_standard() {
		for count in [0, 1, 99] {
			assert_eq!(
				validate(&format!("max_recipients = {count}")),
				Err(format!(
					"invalid configuration: max_recipients ({count}) is below 100: RFC 5321 \
					 §4.5.3.1.8 requires accepting at least 100 recipients"
				)),
				"{count}"
			);
		}
	}

	#[test]
	fn a_recipient_cap_from_one_hundred_to_ten_thousand_is_accepted() {
		for settings in [
			"",
			"max_recipients = 100",
			"max_recipients = 500",
			"max_recipients = 10000",
		] {
			assert_eq!(validate(settings), Ok(()), "{settings}");
		}
		assert_eq!(
			validate("max_recipients = 10001"),
			Err(
				"invalid configuration: max_recipients (10001) is above 10000, the most one \
				 message may name"
					.to_string()
			)
		);
	}

	#[test]
	fn the_singular_max_connections_per_account_is_rejected() {
		// The implementation has only `_per_ip` and `_total`. The singular
		// `max_connections_per_account` is accepted by the TOML parser
		// but never read by `MailboxLimits::from_config`, so an operator
		// who set `max_connections_per_account = 1` would see no effect
		// at all: the second connection from alice on the same IP is
		// admitted with the cap at 50 per `default`. The key is rejected
		// up front so the failure is loud.
		assert_eq!(
			validate("max_connections_per_account = 1"),
			Err(
				"invalid configuration: max_connections_per_account is not configurable; \
				 use max_connections_per_account_per_ip (per (account, client IP)) and \
				 max_connections_per_account_total (per account)"
					.to_string()
			)
		);
	}
