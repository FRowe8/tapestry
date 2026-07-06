//! `tapestry approve` — list, grant, or revoke tool approvals.

use crate::support::*;
use anyhow::Result;

pub(crate) fn run_approve(
    site: &str,
    tool_id: Option<&str>,
    list: bool,
    revoke: bool,
    note: Option<String>,
) -> Result<()> {
    let approvals_path = site_dir(site).join("approvals.json");
    let spec = load_site_spec(site)?;
    let mut approvals = tapestry_runtime::load_approvals(&approvals_path)?;

    if list || tool_id.is_none() {
        if revoke {
            anyhow::bail!(
                "--revoke requires a tool id: tapestry approve {site} <tool_id> --revoke"
            );
        }
        println!("{}", format_approval_status(site, &spec, &approvals));
        return Ok(());
    }

    let tool_id = tool_id.expect("checked above");
    let Some(tool) = spec
        .tools
        .iter()
        .find(|tool| tool.id == tool_id || tool.name == tool_id)
    else {
        anyhow::bail!(
            "Tool '{}' not found for site '{}'. Run `tapestry approve {} --list` to see tools.",
            tool_id,
            site,
            site
        );
    };

    if revoke {
        if approvals.remove(&tool.id).is_some() {
            write_protected(&approvals_path, &serde_json::to_string_pretty(&approvals)?)?;
            println!("Revoked approval for '{}' on site '{}'.", tool.id, site);
        } else {
            println!("No stored approval for '{}' on site '{}'.", tool.id, site);
        }
        return Ok(());
    }

    let required = approval_requirement(tool);
    approvals.insert(
        tool.id.clone(),
        tapestry_runtime::ApprovalRecord {
            fingerprint: tapestry_runtime::tool_fingerprint(tool),
            approved_at: current_timestamp_cli(),
            note,
        },
    );
    write_protected(&approvals_path, &serde_json::to_string_pretty(&approvals)?)?;
    println!(
        "Approved '{}' ({} {}, safety {}, confidence {:.2}) for site '{}'.",
        tool.id,
        tool.method,
        tool.path,
        safety_label(&tool.safety.classification),
        tool.confidence.overall,
        site
    );
    if required.is_none() {
        println!("Note: this tool is read-safe above the confidence threshold and did not require approval.");
    }
    println!("The approval is pinned to the tool's current request shape; if `generate` changes the tool, re-approve it.");
    Ok(())
}
/// Why a tool needs approval before `call_tool` will execute it, if it does.
pub(crate) fn approval_requirement(tool: &tapestry_core::ToolDefinition) -> Option<&'static str> {
    if tool.safety.classification == tapestry_core::SafetyClassification::Unknown {
        return Some("unknown safety");
    }
    if tool.safety.classification != tapestry_core::SafetyClassification::Read {
        return Some("write tool");
    }
    if tool.confidence.overall < tapestry_runtime::DEFAULT_CONFIDENCE_THRESHOLD {
        return Some("low confidence");
    }
    None
}

pub(crate) fn safety_label(classification: &tapestry_core::SafetyClassification) -> &'static str {
    match classification {
        tapestry_core::SafetyClassification::Read => "read",
        tapestry_core::SafetyClassification::Write => "write",
        tapestry_core::SafetyClassification::Unknown => "unknown",
    }
}

pub(crate) fn format_approval_status(
    site: &str,
    spec: &tapestry_core::ToolSpec,
    approvals: &std::collections::BTreeMap<String, tapestry_runtime::ApprovalRecord>,
) -> String {
    let mut out = format!(
        "Approval status for site '{}' ({} tools):\n\n",
        site,
        spec.tools.len()
    );
    let mut pending = 0usize;
    for tool in &spec.tools {
        let requirement = approval_requirement(tool);
        let (status, reason) = match (requirement, tool.approved) {
            (None, _) => ("-", "  no approval needed".to_string()),
            (Some(_), true) => ("approved", String::new()),
            (Some(reason), false) => {
                pending += 1;
                ("PENDING", format!("  needs approval: {reason}"))
            }
        };
        let evidence_count: usize = tool.evidence.iter().map(|e| e.count).sum();
        out.push_str(&format!(
            "  {:<9} {:<28} {:<7} confidence {:.2}  {} {}  ({} observation{}){}\n",
            status,
            tool.id,
            safety_label(&tool.safety.classification),
            tool.confidence.overall,
            tool.method,
            tool.path,
            evidence_count,
            if evidence_count == 1 { "" } else { "s" },
            reason
        ));
    }
    for (tool_id, record) in approvals {
        if !spec.tools.iter().any(|tool| tool.id == *tool_id) {
            out.push_str(&format!(
                "  orphaned  {:<28} approval stored {} but tool no longer exists\n",
                tool_id, record.approved_at
            ));
        }
    }
    if pending > 0 {
        out.push_str(&format!(
            "\nApprove with: tapestry approve {site} <tool_id>\nInspect first: tapestry tools evidence {site} <tool_id>"
        ));
    } else {
        out.push_str("\nNo tools are pending approval.");
    }
    out
}
