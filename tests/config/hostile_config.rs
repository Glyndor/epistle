//! Hostile configuration files against the real loader: nesting, sizes,
//! control characters, `${VAR}` references and files that are not files.
//! Each case must end in a clean error, in bounded time, with an error
//! message that does not grow with the hostile input.

#[path = "hostile_config/files.rs"]
mod files;
#[path = "hostile_config/harness.rs"]
mod harness;
#[path = "hostile_config/nesting.rs"]
mod nesting;
#[path = "hostile_config/references.rs"]
mod references;
#[path = "hostile_config/sizes.rs"]
mod sizes;
