//! `tapestry doctor` — environment and site-data sanity checks.

use crate::support::*;
use std::fs;

/// Environment and site-data checks for `tapestry doctor`.
pub(crate) fn run_doctor() -> String {
    let mut out = vec!["Tapestry doctor".to_string(), String::new()];

    match tapestry_input::resolve_browser(None) {
        Ok(path) => out.push(format!("[ok]   browser: {}", path.display())),
        Err(error) => out.push(format!(
            "[FAIL] browser: {error}\n       Live recording and reauth need Chrome/Chromium/Edge. HAR import still works."
        )),
    }

    let root = sites_root();
    match fs::create_dir_all(&root).and_then(|_| {
        let probe = root.join(".doctor-probe");
        fs::write(&probe, "probe")?;
        fs::remove_file(&probe)
    }) {
        Ok(()) => out.push(format!("[ok]   storage: {} is writable", root.display())),
        Err(error) => out.push(format!(
            "[FAIL] storage: cannot write {} — {error}",
            root.display()
        )),
    }

    let mut site_lines = Vec::new();
    let mut total = 0usize;
    let mut ready = 0usize;
    if let Ok(entries) = fs::read_dir(&root) {
        let mut names: Vec<String> = entries
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.path().is_dir())
            .filter_map(|entry| entry.file_name().into_string().ok())
            .collect();
        names.sort();
        for name in names {
            total += 1;
            let dir = site_dir(&name);
            let observations = load_existing_observations(&name).len();
            let has_spec = dir.join("toolspec.json").exists();
            if observations == 0 {
                site_lines.push(format!(
                    "[warn] site '{name}': no observations — record or import a capture"
                ));
            } else if !has_spec {
                site_lines.push(format!(
                    "[warn] site '{name}': {observations} observation(s) but no ToolSpec — run `tapestry generate {name}`"
                ));
            } else {
                ready += 1;
            }
            let meta = load_site_meta(&name);
            if let (Some(failure), success) =
                (&meta.auth.last_auth_failure, &meta.auth.last_success)
            {
                let stale = success
                    .as_ref()
                    .map(|success| failure.as_str() > success.as_str())
                    .unwrap_or(true);
                if stale {
                    site_lines.push(format!(
                        "[warn] site '{name}': credentials look stale (last auth failure {failure}) — run `tapestry reauth {name}`"
                    ));
                }
            }
            let unhealthy: Vec<&String> = meta
                .tool_health
                .iter()
                .filter(|(_, health)| health.status != "healthy")
                .map(|(tool_id, _)| tool_id)
                .collect();
            if !unhealthy.is_empty() {
                site_lines.push(format!(
                    "[warn] site '{name}': {} tool(s) degraded/broken — run `tapestry review {name}`",
                    unhealthy.len()
                ));
            }
        }
    }
    out.push(format!(
        "[ok]   sites: {total} total, {ready} ready (observations + ToolSpec)"
    ));
    out.extend(site_lines);

    out.push(String::new());
    out.push("Done. [FAIL] items block core workflows; [warn] items affect one site.".to_string());
    out.join("\n")
}
