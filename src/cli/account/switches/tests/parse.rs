//! The command line of `account set`.

use clap::Parser;

use crate::cli::Cli;

fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
	Cli::try_parse_from(
		["epistle", "account", "set"]
			.into_iter()
			.chain(args.iter().copied()),
	)
}

#[test]
fn send_and_receive_are_accepted_together() {
	assert!(parse(&["app", "--send", "off", "--receive", "off"]).is_ok());
}

#[test]
fn the_equals_form_is_accepted() {
	assert!(parse(&["app", "--send=on"]).is_ok());
}

#[test]
fn a_set_with_no_setting_is_refused() {
	assert!(parse(&["app"]).is_err());
}

#[test]
fn the_default_class_does_not_combine_with_a_switch() {
	assert!(parse(&["app", "--default-class", "marketing", "--send", "off"]).is_err());
}

#[test]
fn the_default_class_alone_still_parses() {
	assert!(parse(&["app", "--default-class", "marketing"]).is_ok());
}

#[test]
fn a_value_that_is_not_on_or_off_is_refused_before_the_store_opens() {
	use std::process::ExitCode;
	let refused = super::super::parse("app", "send", Some("maybe"));
	assert!(matches!(refused, Err(code) if code == ExitCode::from(crate::cli::exit::REFUSED)));
	assert!(matches!(
		super::super::parse("app", "send", Some("OFF")),
		Ok(Some(false))
	));
	assert!(matches!(super::super::parse("app", "send", None), Ok(None)));
}
