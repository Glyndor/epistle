use super::*;
use crate::cli::resource::ResourceError;

#[test]
fn split_gives_every_domain_its_own_secret_and_keeps_the_global_one() {
	let global = fresh();
	let run = run_srs(&two_domains_on(&global), &["split"], false);
	assert_eq!(run.result.as_ref().unwrap(), &ExitCode::SUCCESS);
	let config = loaded(&run);
	let a = config.srs_domain("a.example").expect("a.example split");
	let b = config.srs_domain("b.example").expect("b.example split");
	assert_ne!(a.secret, b.secret, "two domains were given one secret");
	assert!(a.secret != global && b.secret != global);
	assert_eq!(config.srs_secret.as_deref(), Some(global.as_str()));
	assert!(
		config.srs_notices().is_empty(),
		"the sharing warning must clear once every domain has its own"
	);
	assert!(!run.status.contains(&a.secret) && !run.out.contains(&a.secret));
}

#[test]
fn split_leaves_a_domain_that_already_has_its_own_secret_alone() {
	let (global, own) = (fresh(), fresh());
	let body = format!(
		"{}[[srs_domain]]\nname = 'a.example'\nsecret = '{own}'\n",
		two_domains_on(&global)
	);
	let run = run_srs(&body, &["split"], false);
	assert_eq!(run.result.as_ref().unwrap(), &ExitCode::SUCCESS);
	let config = loaded(&run);
	assert_eq!(config.srs_domain("a.example").unwrap().secret, own);
	assert!(config.srs_domain("b.example").is_some());
	// Past the two header lines `run_srs` adds.
	let edited = run.after.splitn(3, '\n').nth(2).expect("the body");
	let again = run_srs(edited, &["split"], false);
	assert_eq!(again.result.as_ref().unwrap(), &ExitCode::SUCCESS);
	assert_eq!(again.after, again.before, "a second split changes nothing");
}

#[test]
fn a_dry_run_writes_nothing_and_shows_no_secret() {
	let global = fresh();
	let run = run_srs(&two_domains_on(&global), &["split"], true);
	assert_eq!(run.result.as_ref().unwrap(), &ExitCode::SUCCESS);
	assert_eq!(run.after, run.before, "a dry run wrote the file");
	assert!(run.out.contains("srs_domain"), "{}", run.out);
	assert!(run.out.contains("<redacted>"), "{}", run.out);
	let config = loaded(&run);
	assert!(config.srs_domain("a.example").is_none());
}

#[test]
fn rotate_keeps_the_old_secret_to_verify_with() {
	let (global, own) = (fresh(), fresh());
	let body = format!(
		"{}[[srs_domain]]\nname = 'a.example'\nsecret = '{own}'\n",
		two_domains_on(&global)
	);
	let run = run_srs(&body, &["rotate", "A.Example"], false);
	assert_eq!(run.result.as_ref().unwrap(), &ExitCode::SUCCESS);
	let entry = loaded(&run).srs_domain("a.example").unwrap().clone();
	assert_ne!(entry.secret, own, "the secret was not replaced");
	assert_eq!(entry.previous_secret.as_deref(), Some(own.as_str()));
}

#[test]
fn rotate_refuses_a_domain_without_a_secret_of_its_own() {
	let run = run_srs(&two_domains_on(&fresh()), &["rotate", "a.example"], false);
	match run.result {
		Err(ResourceError::Refusal(message)) => {
			assert!(message.contains("epistle srs split"), "{message}");
		}
		other => panic!("expected a refusal, got {other:?}"),
	}
	assert_eq!(run.after, run.before);
}

#[test]
fn show_names_who_shares_and_never_prints_a_secret() {
	let (global, own) = (fresh(), fresh());
	let body = format!(
		"{}[[srs_domain]]\nname = 'a.example'\nsecret = '{own}'\n",
		two_domains_on(&global)
	);
	let run = run_srs(&body, &["show"], false);
	assert_eq!(run.result.as_ref().unwrap(), &ExitCode::SUCCESS);
	assert_eq!(
		run.out,
		"server-wide\tset\na.example\town\nb.example\tshared\n"
	);
	assert!(!run.out.contains(&own) && !run.out.contains(&global));
}
