use std::cell::RefCell;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Once};

thread_local! {
	static ACTIVE: RefCell<Option<Arc<AtomicBool>>> = const { RefCell::new(None) };
}

/// Production detaches some connection tasks, and TLS JoinSets discard their
/// JoinErrors. A transport Drop cannot detect a panic after its destruction.
/// Install one chaining hook, but attribute panics only to the current test's
/// thread. Every public-HTTP test uses Tokio's current-thread runtime, so its
/// listener and connection tasks share that thread; unrelated tests do not.
pub struct PanicWatch {
	pub panicked: Arc<AtomicBool>,
	previous: Option<Arc<AtomicBool>>,
	_thread: PhantomData<Rc<()>>,
}

impl PanicWatch {
	pub fn new() -> Self {
		assert_eq!(
			tokio::runtime::Handle::current().runtime_flavor(),
			tokio::runtime::RuntimeFlavor::CurrentThread,
			"panic supervision requires a current-thread runtime"
		);
		static INSTALL: Once = Once::new();
		INSTALL.call_once(|| {
			let previous = std::panic::take_hook();
			std::panic::set_hook(Box::new(move |info| {
				let _ = ACTIVE.try_with(|active| {
					if let Ok(active) = active.try_borrow()
						&& let Some(flag) = active.as_ref()
					{
						flag.store(true, std::sync::atomic::Ordering::SeqCst);
					}
				});
				previous(info);
			}));
		});
		let panicked = Arc::new(AtomicBool::new(false));
		let previous = ACTIVE.with(|active| active.replace(Some(panicked.clone())));
		Self {
			panicked,
			previous,
			_thread: PhantomData,
		}
	}
}

impl Drop for PanicWatch {
	fn drop(&mut self) {
		ACTIVE.with(|active| active.replace(self.previous.take()));
	}
}
