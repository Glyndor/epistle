//! `epistle init` offers the IP warm-up to a new install.

#[test]
fn a_new_install_is_offered_the_warm_up_and_an_existing_one_is_not() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut out = Vec::new();
	super::offer_warmup(dir.path(), &mut out);
	assert_eq!(
		String::from_utf8(out).expect("utf8"),
		"warm-up: a new sending address has no reputation yet, and large receivers defer or \
		 junk its mail when the volume jumps. To ramp it up per receiver group, run\n  \
		 epistle warmup plan --ip-age 0d --daily-volume <recipients a day>\n\
		 and then the same with `start`.\n"
	);
	crate::queue::warmup::settings::save(dir.path(), &Default::default()).expect("save");
	let mut out = Vec::new();
	super::offer_warmup(dir.path(), &mut out);
	assert!(out.is_empty());
}
