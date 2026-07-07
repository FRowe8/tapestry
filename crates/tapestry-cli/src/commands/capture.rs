//! `tapestry import` / `record` / `generate` — capture summaries, the
//! post-capture "run generate next" nudge, and low-signal-capture rejection.

use crate::support::*;
use anyhow::{Context, Result};
use std::fs;
use tracing::info;

pub(crate) fn format_record_summary(
    site: &str,
    observations: &[tapestry_core::Observation],
) -> String {
    let summary = tapestry_input::CaptureSummary::from_observations(observations);
    let coverage = round2(summary.response_body_coverage() * 100.0);

    format!(
        "Recorded {} observations\nCapture quality: {}\nAPI observations: {}\nResponse body coverage: {:.0}%\nReplayable tools (estimate): {}\nMissing response bodies: {}\nJSON responses: {}\nGraphQL requests: {}\nRecommended next action: {}\nSaved to {}",
        summary.total_observations,
        summary.quality_grade(),
        summary.candidate_api_observations,
        coverage,
        summary.replayable_tool_hint(),
        summary
            .total_observations
            .saturating_sub(summary.observations_with_response_bodies),
        summary.json_responses,
        summary.graphql_requests,
        summary.recommended_next_action(),
        site_dir(site).join("observations.json").display(),
    )
}

/// Run `generate` for a site: analyze stored observations into a ToolSpec,
/// write it to disk, and prune approvals that no longer match. Shared by the
/// standalone `generate` command and the `--generate` chaining flag on
/// `import`/`record`.
pub(crate) fn run_generate(site: &str) -> Result<()> {
    validate_site_name(site)?;
    info!(command = "generate", site, "starting ToolSpec generation");
    let dir = site_dir(site);
    let raw = fs::read_to_string(dir.join("observations.json")).context("run import first")?;
    let observations: Vec<tapestry_core::Observation> = serde_json::from_str(&raw)?;
    let spec = tapestry_analyzer::analyze(site, &observations);
    write_protected(
        &dir.join("toolspec.json"),
        &serde_json::to_string_pretty(&spec)?,
    )?;
    println!("Generated {} tools for site '{}'", spec.tools.len(), site);
    prune_stale_approvals(site, &spec)?;
    Ok(())
}

/// Print an unmissable next-step line after a capture (`import`/`record`)
/// that was not immediately followed by generation. Field testing showed
/// users routinely stop after capturing and never run `generate`, leaving
/// captured sessions un-generated; this banner (and the `--generate` flag
/// that skips it) close that gap.
pub(crate) fn print_generate_nudge(site: &str) {
    println!(
        "\n============================================================\n>>> NEXT STEP REQUIRED: run `tapestry generate {site}`\n    (or re-run this command with --generate to do it now)\n============================================================"
    );
}

pub(crate) fn print_record_guidance() {
    eprintln!("{}", record_guidance_text());
}

pub(crate) fn record_guidance_text() -> &'static str {
    "Recording started.\n\nNow interact with the site:\n- search/list something\n- open a detail page\n- perform a relevant workflow step\n- wait for results to load\n\nPress Enter when finished."
}

pub(crate) fn record_low_signal_failure(
    summary: &tapestry_input::CaptureSummary,
    min_api_observations: usize,
    allow_low_signal: bool,
) -> Option<String> {
    if allow_low_signal {
        return None;
    }

    summary.minimum_api_failure_message(min_api_observations)
}
