//! The cost of the password hashes the server writes: argon2id parameters for
//! the account password (`[auth] argon2_memory_kib`, `argon2_iterations`,
//! `argon2_parallelism`), process-wide.
//!
//! A hash records its own parameters, so changing them never invalidates a
//! stored password: only new hashes carry the new cost. The defaults are the
//! crate's, which are also the minimum of the OWASP Password Storage Cheat
//! Sheet (19 MiB, 2 iterations, 1 lane). The loader refuses anything below
//! them, so the cost can be raised and never lowered under that bar.

use std::sync::RwLock;

use argon2::password_hash::phc::PasswordHash;
use argon2::{Algorithm, Argon2, Params, Version};

/// Memory, in KiB, the loader requires at least: 19 MiB, the OWASP minimum.
pub const MEMORY_FLOOR_KIB: u32 = Params::DEFAULT_M_COST;
/// The most memory, in KiB, the loader accepts: 1 GiB for one hash.
pub const MEMORY_CEILING_KIB: u32 = 1024 * 1024;
/// Iterations the loader requires at least: the OWASP minimum at 19 MiB.
pub const PASSES_FLOOR: u32 = Params::DEFAULT_T_COST;
/// The most iterations the loader accepts.
pub const PASSES_CEILING: u32 = 20;
/// Lanes the loader requires at least.
pub const PARALLELISM_FLOOR: u32 = Params::DEFAULT_P_COST;
/// The most lanes the loader accepts.
pub const PARALLELISM_CEILING: u32 = 16;

/// The argon2id cost of a new password hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Cost {
	/// Memory in KiB.
	pub memory_kib: u32,
	/// Passes over the memory.
	pub iterations: u32,
	/// Lanes.
	pub parallelism: u32,
}

impl Default for Argon2Cost {
	fn default() -> Self {
		Self {
			memory_kib: MEMORY_FLOOR_KIB,
			iterations: PASSES_FLOOR,
			parallelism: PARALLELISM_FLOOR,
		}
	}
}

impl Argon2Cost {
	/// Refuse a cost below the floors or above the ceilings.
	pub fn validate(self) -> Result<(), String> {
		check(
			"argon2_memory_kib",
			self.memory_kib,
			MEMORY_FLOOR_KIB,
			MEMORY_CEILING_KIB,
		)?;
		check(
			"argon2_iterations",
			self.iterations,
			PASSES_FLOOR,
			PASSES_CEILING,
		)?;
		check(
			"argon2_parallelism",
			self.parallelism,
			PARALLELISM_FLOOR,
			PARALLELISM_CEILING,
		)
	}

	/// The hasher for this cost, or why its parameters are unusable.
	pub fn hasher(self) -> Result<Argon2<'static>, String> {
		let params = Params::new(self.memory_kib, self.iterations, self.parallelism, None)
			.map_err(|error| error.to_string())?;
		Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
	}
}

fn check(key: &str, value: u32, floor: u32, ceiling: u32) -> Result<(), String> {
	if value < floor {
		return Err(format!(
			"[auth] {key} ({value}) must be at least {floor}: the OWASP minimum for argon2id"
		));
	}
	if value > ceiling {
		return Err(format!("[auth] {key} ({value}) must be at most {ceiling}"));
	}
	Ok(())
}

static CURRENT: RwLock<Argon2Cost> = RwLock::new(Argon2Cost {
	memory_kib: MEMORY_FLOOR_KIB,
	iterations: PASSES_FLOOR,
	parallelism: PARALLELISM_FLOOR,
});

#[cfg(test)]
thread_local! {
	static SCOPED: std::cell::Cell<Option<Argon2Cost>> = const { std::cell::Cell::new(None) };
}

/// The cost new password hashes are written with.
pub fn current() -> Argon2Cost {
	#[cfg(test)]
	if let Some(scoped) = SCOPED.with(|cell| cell.get()) {
		return scoped;
	}
	*CURRENT.read().unwrap_or_else(|p| p.into_inner())
}

/// Run `body` with `cost` in force on this thread only, so a test of a
/// non-default cost cannot reach the tests that run beside it.
#[cfg(test)]
pub(crate) fn scoped<R>(cost: Argon2Cost, body: impl FnOnce() -> R) -> R {
	struct Restore(Option<Argon2Cost>);
	impl Drop for Restore {
		fn drop(&mut self) {
			SCOPED.with(|cell| cell.set(self.0));
		}
	}
	let _restore = Restore(SCOPED.with(|cell| cell.replace(Some(cost))));
	body()
}

/// The cost a stored hash should be rewritten at, or `None` when it needs no
/// rewrite.
///
/// A hash is rewritten when it is not argon2id at version 19, or when its
/// memory, passes or lanes are below `cost`. The new cost takes the larger
/// of the stored and the configured value of each, so a hash that is
/// stronger than `cost` in one respect never loses that strength. A string
/// that is not a readable argon2 hash is left alone: it could not have
/// verified.
pub fn rewrite_cost(phc: &str, cost: Argon2Cost) -> Option<Argon2Cost> {
	let hash = PasswordHash::new(phc).ok()?;
	let params = Params::try_from(&hash).ok()?;
	let target = Argon2Cost {
		memory_kib: params.m_cost().max(cost.memory_kib),
		iterations: params.t_cost().max(cost.iterations),
		parallelism: params.p_cost().max(cost.parallelism),
	};
	let stored = Argon2Cost {
		memory_kib: params.m_cost(),
		iterations: params.t_cost(),
		parallelism: params.p_cost(),
	};
	let current_algorithm =
		hash.algorithm.as_str() == "argon2id" && hash.version == Some(u32::from(Version::V0x13));
	(!current_algorithm || target != stored).then_some(target)
}

/// Put `cost` in force for the hashes written from now on.
pub fn install(cost: Argon2Cost) {
	*CURRENT.write().unwrap_or_else(|p| p.into_inner()) = cost;
}
