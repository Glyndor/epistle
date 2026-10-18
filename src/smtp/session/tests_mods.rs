//! The test-module declarations for the SMTP session. The list lives
//! in its own file so the state-machine implementation does not have
//! to grow past the 500-code-line limit just to declare every
//! sibling test module. The `pub use super::*;` re-exports the
//! parent module's items (which are now `pub use` so the test files'
//! `use super::*;` still picks them up).

pub use super::*;

#[cfg(test)]
#[path = "../session_tests_basic.rs"]
mod tests_basic;

#[cfg(test)]
#[path = "../session_tests_enhanced.rs"]
mod tests_enhanced;

#[cfg(test)]
#[path = "../session_tests_quota.rs"]
mod tests_quota;

#[cfg(test)]
#[path = "../session_tests_auth.rs"]
mod tests_auth;

#[cfg(test)]
#[path = "../session_tests_author.rs"]
mod tests_author;
#[cfg(test)]
#[path = "../session_tests_bdat_framing.rs"]
mod tests_bdat_framing;
#[cfg(test)]
#[path = "../session_tests_budget_leaks.rs"]
mod tests_budget_leaks;
#[cfg(test)]
#[path = "../session_tests_diskspace.rs"]
mod tests_diskspace;
#[cfg(test)]
#[path = "../session_tests_junk.rs"]
mod tests_junk;
#[cfg(test)]
#[path = "../session_tests_junk_progress.rs"]
mod tests_junk_progress;
#[cfg(test)]
#[path = "../session_tests_login_gate.rs"]
mod tests_login_gate;
#[cfg(test)]
#[path = "../session_tests_memory_budget.rs"]
mod tests_memory_budget;
#[cfg(test)]
#[path = "../session_tests_newrecipients.rs"]
mod tests_newrecipients;
#[cfg(test)]
#[path = "../session_tests_oauth.rs"]
mod tests_oauth;
#[cfg(test)]
#[path = "../session_tests_ratelimit.rs"]
mod tests_ratelimit;
#[cfg(test)]
#[path = "../session_tests_scram.rs"]
mod tests_scram;
#[cfg(test)]
#[path = "../session_tests_scram_ban_lifecycle.rs"]
mod tests_scram_ban_lifecycle;
#[cfg(test)]
#[path = "../session_tests_scram_bans.rs"]
mod tests_scram_bans;
#[cfg(test)]
#[path = "../session_tests_scram_decoy.rs"]
mod tests_scram_decoy;
#[cfg(test)]
#[path = "../session_tests_scram_off.rs"]
mod tests_scram_off;
#[cfg(test)]
#[path = "../session_tests_send_as.rs"]
mod tests_send_as;
