//! Which actions check the boot unit once they succeed.

use super::*;

#[test]
fn the_actions_that_leave_the_stack_running_check_the_unit() {
	let running = [
		StackAction::Update,
		StackAction::Apply,
		StackAction::Restart { service: None },
		StackAction::Restart {
			service: Some("mail".into()),
		},
		StackAction::Passthrough {
			verb: "start",
			service: None,
		},
		StackAction::Certs {
			on: true,
			yes: true,
		},
		StackAction::Certs {
			on: false,
			yes: true,
		},
		StackAction::Recreate {
			service: "mail".into(),
		},
		StackAction::RecreateServices {
			services: vec!["mail".into(), "certs".into()],
		},
	];
	for action in running {
		assert!(action.leaves_running(), "{action:?} must check the unit");
	}
}

#[test]
fn stop_and_down_and_the_reads_never_check_the_unit() {
	// `up` installs the unit itself, so it is not checked a second time.
	let quiet = [
		StackAction::Down,
		StackAction::Up,
		StackAction::Passthrough {
			verb: "stop",
			service: None,
		},
		StackAction::Passthrough {
			verb: "stop",
			service: Some("mail".into()),
		},
		StackAction::Ps { as_json: false },
		StackAction::Logs(logs::LogsArgs::default()),
		StackAction::Rollback,
		StackAction::RollbackDb,
	];
	for action in quiet {
		assert!(
			!action.leaves_running(),
			"{action:?} must not check the unit"
		);
	}
}
