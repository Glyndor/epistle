use super::*;

fn identity() -> Identity {
	Identity::new(987, 986, vec![986, 44])
}

#[test]
fn the_groups_and_the_gid_change_before_the_uid() {
	let mut seen = Vec::new();
	identity()
		.switch(|step, _| {
			seen.push(step);
			0
		})
		.unwrap();
	assert_eq!(
		seen,
		[Step::Groups, Step::Gid, Step::Uid],
		"giving up root before the groups and the gid would leave them unchangeable"
	);
}

#[test]
fn a_step_that_fails_stops_the_ones_after_it() {
	for failing in [Step::Groups, Step::Gid, Step::Uid] {
		let mut seen = Vec::new();
		let result = identity().switch(|step, _| {
			seen.push(step);
			if step == failing { -1 } else { 0 }
		});
		assert!(result.is_err(), "{failing:?} failing must fail the switch");
		assert_eq!(
			seen.last(),
			Some(&failing),
			"nothing may run after {failing:?} failed: {seen:?}"
		);
	}
}

#[test]
fn the_error_of_a_failed_step_is_the_one_the_system_gave() {
	let result = identity().switch(|_, _| {
		// SAFETY: errno is thread-local and this thread owns it.
		unsafe { *libc::__errno_location() = libc::EPERM };
		-1
	});
	assert_eq!(
		result.err().and_then(|error| error.raw_os_error()),
		Some(libc::EPERM)
	);
}

#[test]
fn the_groups_listed_for_an_account_hold_its_gid() {
	let groups = groups_of("root", 0).unwrap();
	assert!(groups.contains(&0), "{groups:?}");
	let groups = groups_of("no-such-account-for-epistle", 4242).unwrap();
	assert!(
		groups.contains(&4242),
		"the primary gid is always among them: {groups:?}"
	);
}
