//! IP warm-up: ramping a new sending address up per receiver group.
//!
//! A sending address with no history is distrusted by the large receivers,
//! who defer or junk mail when its volume jumps. The warm-up gives each
//! receiver group ([`Group`], read from the exchanger that answers) a daily
//! cap that starts small and grows after each good day, holds after a bad
//! one and goes back a step after a very bad one ([`policy`]), judged from
//! the delivery log ([`health`]). The cap is spread across the day, not
//! sent at midnight ([`pacing`]).
//!
//! A recipient over the cap is not a failure and not a deferral: it waits
//! in the queue, with no attempt counted and none of its give-up window
//! used, and goes out as the cap allows (see `crate::queue::Worker`).
//!
//! Days are UTC days. The operator turns the warm-up on and off, pauses its
//! schedule, and raises, skips ahead or resets a group's cap with
//! `epistle warmup`; a raise is judged on its first full day and kept or
//! reverted ([`schedule`]). Each judged day is logged, counted for
//! `[[alerts]]` and sent as a `warmup.*` webhook event ([`events`]).

mod controller;
pub mod events;
mod group;
pub mod health;
pub mod pacing;
pub mod policy;
pub mod schedule;
pub mod settings;
pub mod stages;
pub mod state;

pub use controller::{Grant, Warmup, day_of, sender_share};
pub use events::WarmupReport;
pub use group::Group;
