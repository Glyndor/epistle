//! Test fixtures shared by the directory tests and by tests elsewhere in the
//! crate; `directory` re-exports them under their old paths.

pub(crate) mod gate_fixture;
pub(crate) mod send_as_fixture;
pub(in crate::smtp::directory) mod test_support;
