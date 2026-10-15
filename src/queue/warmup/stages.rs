//! Where a group's cap starts, from what the operator says about the
//! sending address: how long it has sent mail and how much it sends a day.
//!
//! One table decides it ([`STAGES`]); tune it there. Each row applies from
//! its age on, and starts the cap at a share of the daily volume, never
//! under [`START_CAP`]:
//!
//! | IP age          | Stage         | Starting cap                |
//! |-----------------|---------------|-----------------------------|
//! | under 1 week    | `new`         | [`START_CAP`]               |
//! | 1 to 4 weeks    | `weeks`       | a quarter of the volume     |
//! | 4 weeks to 3 m. | `months`      | half of the volume          |
//! | 3 months or more| `established` | the volume                  |
//!
//! A starting cap past [`UNCAPPED_AT`] is no cap at all: an address with
//! three months of history that already sends that much is warmed up.
//! Without a volume, the stage starts at [`START_CAP`].

use super::policy::{START_CAP, UNCAPPED_AT, grown};

/// One row of the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stage {
	/// The stage's name in reports.
	pub name: &'static str,
	/// The age, in days, from which the row applies.
	pub from_days: u64,
	/// The starting cap, in percent of the daily volume.
	pub percent_of_volume: u64,
}

/// The table, youngest first.
pub const STAGES: [Stage; 4] = [
	Stage {
		name: "new",
		from_days: 0,
		percent_of_volume: 0,
	},
	Stage {
		name: "weeks",
		from_days: 7,
		percent_of_volume: 25,
	},
	Stage {
		name: "months",
		from_days: 28,
		percent_of_volume: 50,
	},
	Stage {
		name: "established",
		from_days: 90,
		percent_of_volume: 100,
	},
];

/// The stage of an address `age_days` old.
pub fn stage(age_days: u64) -> Stage {
	STAGES
		.iter()
		.rev()
		.find(|stage| age_days >= stage.from_days)
		.copied()
		.unwrap_or(STAGES[0])
}

/// The starting cap of an address `age_days` old that sends `volume` a
/// day; `None` means no cap.
pub fn starting_cap(age_days: u64, volume: Option<u32>) -> Option<u32> {
	let share = volume.map_or(0, |volume| {
		u64::from(volume) * stage(age_days).percent_of_volume / 100
	});
	let cap = share.max(u64::from(START_CAP));
	match cap > u64::from(UNCAPPED_AT) {
		true => None,
		false => Some(u32::try_from(cap).unwrap_or(UNCAPPED_AT)),
	}
}

/// Good full days for a cap starting at `start` to reach `volume` a day
/// (or, without one, to be lifted), growing as [`grown`] does.
pub fn days_to_reach(start: Option<u32>, volume: Option<u32>) -> u32 {
	let mut cap = start;
	let mut days = 0;
	while let Some(current) = cap {
		if volume.is_some_and(|volume| current >= volume) {
			break;
		}
		cap = grown(current);
		days += 1;
	}
	days
}

#[cfg(test)]
#[path = "stages_tests.rs"]
mod tests;
