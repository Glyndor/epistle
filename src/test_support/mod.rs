//! Helpers shared by the unit tests of the crate: runtime credentials and the
//! test-process stubs the integration suite also includes by path.

pub(crate) mod accounts;
#[path = "../../tests/common/executable.rs"]
pub(crate) mod executable;
pub(crate) mod fixtures;
#[path = "../../tests/common/reaped_group.rs"]
pub(crate) mod reaped_group;
#[cfg(test)]
mod tests;
