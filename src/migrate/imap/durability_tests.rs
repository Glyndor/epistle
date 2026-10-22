use std::cell::RefCell;

#[derive(Default)]
struct Hooks {
	events: Vec<&'static str>,
	fail: Option<&'static str>,
}

thread_local! {
	static HOOKS: RefCell<Option<Hooks>> = const { RefCell::new(None) };
}

pub(crate) struct Guard;

impl Drop for Guard {
	fn drop(&mut self) {
		HOOKS.with(|hooks| *hooks.borrow_mut() = None);
	}
}

pub(crate) fn begin(fail: Option<&'static str>) -> Guard {
	HOOKS.with(|hooks| {
		*hooks.borrow_mut() = Some(Hooks {
			events: Vec::new(),
			fail,
		})
	});
	Guard
}

pub(crate) fn before_sync(kind: &'static str) -> std::io::Result<()> {
	HOOKS.with(|hooks| {
		if hooks
			.borrow()
			.as_ref()
			.is_some_and(|hooks| hooks.fail == Some(kind))
		{
			Err(std::io::Error::other("injected migration sync failure"))
		} else {
			Ok(())
		}
	})
}

pub(crate) fn record(kind: &'static str) {
	HOOKS.with(|hooks| {
		if let Some(hooks) = hooks.borrow_mut().as_mut() {
			hooks.events.push(kind);
		}
	});
}

pub(crate) fn events() -> Vec<&'static str> {
	HOOKS.with(|hooks| {
		hooks
			.borrow()
			.as_ref()
			.expect("active hooks")
			.events
			.clone()
	})
}
