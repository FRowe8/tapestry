//! Per-command logic, one module per CLI command group. `main.rs` keeps the
//! `clap` `Command` enum and the top-level dispatch `match`; the actual work
//! for each command lives here.

pub(crate) mod approve;
pub(crate) mod capture;
pub(crate) mod diagnose;
pub(crate) mod doctor;
pub(crate) mod review;
