//! The driver-driven wait ceilings, named in ONE place (issue #229).
//!
//! A wait that asserts a frontier or a recorded-state advance is never a
//! fixed wall-clock bound: the run's driver wakes semantically on each
//! committed step and otherwise re-checks on its bounded timer fallback
//! (`canter::supervision::DEFAULT_CHECK_INTERVAL_SECS`), so a starved wake on
//! a loaded host legitimately leaves the recorded cursor unchanged for a
//! little over one tick. The zero-slack shape - a bound EQUAL to the cadence
//! it races - turned a correct mechanism red by a margin of a second (measured
//! `61.17s` against the old `60s` bound), and a recorded red holds a delivery's
//! merge tail. Every ceiling below is therefore a whole number of ticks,
//! DERIVED from the product's own cadence, so the slack can never silently
//! become zero if that cadence moves: the interval and the deadlines are named
//! in one place, here.

/// The product's bounded timer fallback cadence, in seconds
/// (`canter::supervision::DEFAULT_CHECK_INTERVAL_SECS`).
pub const CHECK_INTERVAL_SECS: u64 = canter::supervision::DEFAULT_CHECK_INTERVAL_SECS as u64;

/// Ticks a FRONTIER wait tolerates with no durable progress: four, so one (or
/// three) starved wakes can never fail the witness, while a genuinely stuck
/// frontier still reports itself inside the CI test driver's per-suite budget
/// (`scripts/ci-test-driver.py`, `PER_SUITE_SECONDS = 300`) instead of being
/// killed by the driver.
pub const FRONTIER_NO_PROGRESS_TICKS: u64 = 4;

/// Ticks a RECORDED-STATE wait (step dispatch, committed check) tolerates with
/// no new recorded state: two, enough for a starved wake while a stalled
/// driver still reports itself.
pub const STATE_NO_PROGRESS_TICKS: u64 = 2;

/// No-progress ceiling of a frontier wait, in seconds (issue #229).
pub const FRONTIER_NO_PROGRESS_SECS: u64 = FRONTIER_NO_PROGRESS_TICKS * CHECK_INTERVAL_SECS;

/// No-progress ceiling of a recorded-state wait, in seconds (issue #229).
pub const STATE_NO_PROGRESS_SECS: u64 = STATE_NO_PROGRESS_TICKS * CHECK_INTERVAL_SECS;
