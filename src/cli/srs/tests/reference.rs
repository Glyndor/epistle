//! A secret the file spells as a `${VAR}` reference stays a reference when it
//! is rotated: the secret it names is never written into the file.

use super::*;

/// `PATH` is set wherever the tests run and is longer than the minimum
/// secret, so it stands for a secret that lives in the environment.
fn expanded() -> String {
	std::env::var("PATH").expect("PATH is set")
}

#[test]
fn rotating_a_secret_given_by_reference_keeps_the_reference_as_the_previous() {
	let body = format!(
		"domains = ['a.example', 'b.example']\nsrs_secret = '{}'\n\
		 [[srs_domain]]\nname = 'a.example'\nsecret = '${{PATH}}'\n",
		fresh()
	);
	let run = run_srs(&body, &["rotate", "a.example"], false);
	assert_eq!(run.result.as_ref().unwrap(), &ExitCode::SUCCESS);
	assert!(
		run.after.contains("previous_secret = '${PATH}'"),
		"the reference was not kept: {}",
		run.after.replace(&expanded(), "<expanded>")
	);
	assert!(
		!run.after.contains(&expanded()),
		"the rotation wrote the environment's secret into the file"
	);
	assert!(!run.out.contains(&expanded()) && !run.status.contains(&expanded()));
}

#[test]
fn rotating_a_literal_secret_still_keeps_it_as_the_previous() {
	let (global, own) = (fresh(), fresh());
	let body = format!(
		"{}[[srs_domain]]\nname = 'a.example'\nsecret = '{own}'\n",
		two_domains_on(&global)
	);
	let run = run_srs(&body, &["rotate", "a.example"], false);
	assert_eq!(run.result.as_ref().unwrap(), &ExitCode::SUCCESS);
	assert!(run.after.contains(&format!("previous_secret = '{own}'")));
}
