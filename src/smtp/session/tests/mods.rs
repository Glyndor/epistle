//! The test-module declarations for the SMTP session. The list lives
//! in its own file so the state-machine implementation does not have
//! to grow past the 500-code-line limit just to declare every
//! sibling test module. The `pub use super::*;` re-exports the
//! parent module's items (which are now `pub use` so the test files'
//! `use super::*;` still picks them up).

pub use super::*;

#[cfg(test)]
mod tests_basic;

#[cfg(test)]
mod tests_enhanced;

#[cfg(test)]
mod tests_quota;

#[cfg(test)]
mod tests_auth;

#[cfg(test)]
mod tests_author;
#[cfg(test)]
mod tests_bdat_framing;
#[cfg(test)]
mod tests_budget_leaks;
#[cfg(test)]
mod tests_diskspace;
#[cfg(test)]
mod tests_gate_busy;
#[cfg(test)]
mod tests_junk;
#[cfg(test)]
mod tests_junk_progress;
#[cfg(test)]
mod tests_login_gate;
#[cfg(test)]
mod tests_memory_budget;
#[cfg(test)]
mod tests_newrecipients;
#[cfg(test)]
mod tests_oauth;
#[cfg(test)]
mod tests_ratelimit;
#[cfg(test)]
mod tests_recipients;
#[cfg(test)]
mod tests_scram;
#[cfg(test)]
mod tests_scram_ban_lifecycle;

#[cfg(test)]
mod tests_scram_ban_owner_known_network;
#[cfg(test)]
mod tests_scram_ban_toctou;
#[cfg(test)]
mod tests_scram_bans;
#[cfg(test)]
mod tests_scram_decoy;
#[cfg(test)]
mod tests_scram_final;
#[cfg(test)]
mod tests_scram_off;
#[cfg(test)]
mod tests_send_as;

#[cfg(test)]
mod tests_single_label;

#[cfg(test)]
mod tests_auth_log;
