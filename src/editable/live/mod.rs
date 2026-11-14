//! The configuration a running server applies, with its state files laid
//! over it, replaced when one of them changes.
//!
//! `serve` builds one [`LiveConfig`] from the configuration it loaded, names
//! the state files it follows ([`LiveConfig::track`]) and hands it to the file
//! watcher. Each part of the server that reads that state while it runs
//! registers a listener, and every reload calls each listener with the new
//! configuration. A state file the server would refuse at start is refused
//! here too, and the running configuration stays.

use std::sync::{Arc, Mutex, RwLock};

use crate::config::Config;

use super::StateFile;

type Listener = Box<dyn Fn(&Config) + Send + Sync>;
type Reload = fn(&LiveConfig, &str) -> Result<(), String>;

/// The configuration of a running server.
pub struct LiveConfig {
	current: RwLock<Arc<Config>>,
	listeners: Mutex<Vec<Listener>>,
	files: Mutex<Vec<(&'static str, Reload)>>,
}

impl std::fmt::Debug for LiveConfig {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		formatter
			.debug_struct("LiveConfig")
			.field("files", &self.tracked())
			.finish_non_exhaustive()
	}
}

impl LiveConfig {
	/// The live configuration of `config`, as loaded at start.
	pub fn new(config: Config) -> Arc<Self> {
		Arc::new(LiveConfig {
			current: RwLock::new(Arc::new(config)),
			listeners: Mutex::new(Vec::new()),
			files: Mutex::new(Vec::new()),
		})
	}

	/// Follow the state file `S`: the file watcher reloads it.
	pub fn track<S: StateFile>(&self) {
		let mut files = self.files.lock().expect("live config files");
		if !files.iter().any(|(name, _)| *name == S::FILE_NAME) {
			files.push((S::FILE_NAME, Self::reload::<S>));
		}
	}

	/// The names of the state files this configuration follows.
	pub fn tracked(&self) -> Vec<&'static str> {
		self.files
			.lock()
			.expect("live config files")
			.iter()
			.map(|(name, _)| *name)
			.collect()
	}

	/// The configuration in effect now.
	pub fn current(&self) -> Arc<Config> {
		Arc::clone(&self.current.read().expect("live config lock"))
	}

	/// Call `listener` with the new configuration after every reload.
	pub fn on_change(&self, listener: impl Fn(&Config) + Send + Sync + 'static) {
		self.listeners
			.lock()
			.expect("live config listeners")
			.push(Box::new(listener));
	}

	/// Apply `text` as the contents of the state file `S`. Empty text is a
	/// missing file: what the configuration file declares applies again. The
	/// state is refused, and the running configuration kept, when it does not
	/// parse or when the configuration it gives is not one the server would
	/// start with.
	pub fn reload<S: StateFile>(&self, text: &str) -> Result<(), String> {
		let base = self.current();
		let state = if text.trim().is_empty() {
			S::seed(&base)
		} else {
			S::parse(text).map_err(|error| error.to_string())?
		};
		let next = S::apply(&base, &state);
		next.validate().map_err(|error| error.to_string())?;
		self.publish(next);
		Ok(())
	}

	/// Make `config` the configuration in effect and tell every listener. A
	/// write made inside the server calls this at once, without waiting for
	/// the file watcher.
	pub fn publish(&self, config: Config) {
		let config = Arc::new(config);
		// The listeners' lock is held across the swap, so two reloads reach
		// every listener in the order they replaced the configuration.
		let listeners = self.listeners.lock().expect("live config listeners");
		*self.current.write().expect("live config lock") = Arc::clone(&config);
		for listener in listeners.iter() {
			listener(&config);
		}
	}
}

impl crate::directory_store::file_watcher::StateReloader for LiveConfig {
	fn files(&self) -> Vec<&'static str> {
		self.tracked()
	}

	fn reload_state(&self, file: &str, text: &str) -> std::io::Result<()> {
		let reload = self
			.files
			.lock()
			.expect("live config files")
			.iter()
			.find(|(name, _)| *name == file)
			.map(|(_, reload)| *reload)
			.ok_or_else(|| std::io::Error::other(format!("{file} is not followed")))?;
		reload(self, text)
			.map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
	}
}
