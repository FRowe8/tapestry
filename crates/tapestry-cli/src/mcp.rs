//! MCP stdio server exposing the native runtime's four methods as MCP tools.
//!
//! Generated tools are never exposed individually: agents always go through
//! `search_tools -> get_tool_schema -> call_tool`, keeping context small no
//! matter how many tools a site has. Transport is newline-delimited JSON-RPC
//! 2.0 over stdin/stdout; logs go to stderr so stdout stays protocol-clean.

use anyhow::Result;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::time::SystemTime;

const PROTOCOL_VERSION: &str = "2025-03-26";

/// Per-site cache of the overlaid ToolSpec for the lifetime of a serve
/// session. The files backing a site do not change across most calls, so
/// re-reading and re-parsing them on every JSON-RPC request is wasted work.
/// Cached entries are invalidated when any backing file's mtime changes —
/// including meta.json, which call_tool rewrites, so health/approval overlays
/// stay fresh while read-only calls (the bulk of traffic) hit the cache.
#[derive(Default)]
pub(crate) struct SpecCache {
    entries: HashMap<String, (Vec<Option<SystemTime>>, tapestry_core::ToolSpec)>,
}

impl SpecCache {
    fn load(&mut self, site: &str) -> Result<tapestry_core::ToolSpec> {
        let signature = site_signature(site);
        if let Some((cached, spec)) = self.entries.get(site) {
            if *cached == signature {
                return Ok(spec.clone());
            }
        }
        let spec = crate::load_site_spec(site)?;
        self.entries
            .insert(site.to_string(), (signature, spec.clone()));
        Ok(spec)
    }
}

fn site_signature(site: &str) -> Vec<Option<SystemTime>> {
    ["toolspec.json", "approvals.json", "meta.json"]
        .iter()
        .map(|name| {
            std::fs::metadata(crate::site_dir(site).join(name))
                .and_then(|meta| meta.modified())
                .ok()
        })
        .collect()
}

#[derive(Debug, Clone)]
pub struct McpServerConfig {
    pub default_site: Option<String>,
    pub live: bool,
    pub offline: bool,
    pub max_pages: usize,
}

pub fn serve(config: McpServerConfig) -> Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut cache = SpecCache::default();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Some(response) = handle_line(&config, &mut cache, &line) {
            let mut encoded = serde_json::to_string(&response)?;
            encoded.push('\n');
            out.write_all(encoded.as_bytes())?;
            out.flush()?;
        }
    }
    Ok(())
}

fn handle_line(config: &McpServerConfig, cache: &mut SpecCache, line: &str) -> Option<Value> {
    match serde_json::from_str::<Value>(line) {
        Ok(message) => handle_message(config, cache, &message),
        Err(_) => Some(jsonrpc_error(Value::Null, -32700, "Parse error")),
    }
}

fn handle_message(
    config: &McpServerConfig,
    cache: &mut SpecCache,
    message: &Value,
) -> Option<Value> {
    let id = message.get("id").cloned();
    let method = message.get("method").and_then(Value::as_str).unwrap_or("");
    let params = message.get("params").cloned().unwrap_or(Value::Null);
    let is_notification = id.is_none() || id == Some(Value::Null);

    let outcome = match method {
        "initialize" => Ok(initialize_result(config, &params)),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tool_definitions(config) })),
        "tools/call" => tools_call(config, cache, &params),
        _ => Err((-32601, format!("Method not found: {method}"))),
    };

    if is_notification {
        return None;
    }
    let id = id.unwrap_or(Value::Null);
    Some(match outcome {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err((code, message)) => jsonrpc_error(id, code, &message),
    })
}

fn jsonrpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message }
    })
}

fn initialize_result(config: &McpServerConfig, params: &Value) -> Value {
    let requested = params
        .get("protocolVersion")
        .and_then(Value::as_str)
        .unwrap_or(PROTOCOL_VERSION);
    let site_hint = match &config.default_site {
        Some(site) => format!("This server is bound to site '{site}'."),
        None => "No default site is configured; pass `site` on every tool call.".to_string(),
    };
    json!({
        "protocolVersion": requested,
        "capabilities": { "tools": {} },
        "serverInfo": {
            "name": "tapestry",
            "version": env!("CARGO_PKG_VERSION")
        },
        "instructions": format!(
            "Tapestry exposes tools generated from captured web traffic. Workflow: \
             search_tools to find a tool for the task, get_tool_schema to see its \
             arguments, then call_tool to execute. Use get_evidence to inspect how a \
             tool was inferred before trusting or approving it. Tool results are JSON; \
             a result with status \"error\" is structured and actionable: \
             approval_required means the user must run `tapestry approve <site> <tool_id>`; \
             auth_expired means stored credentials went stale and the user must refresh \
             them (e.g. `tapestry credentials <site> set ...`). Relay those instructions \
             to the user instead of retrying. {site_hint}"
        )
    })
}

pub(crate) fn tool_definitions(config: &McpServerConfig) -> Value {
    let bound = config.default_site.is_some();
    let site_desc = if bound {
        "Site to operate on. Defaults to the server's configured site."
    } else {
        "Site to operate on. Required because this server has no default site."
    };
    let site_schema = json!({ "type": "string", "description": site_desc });
    let require = |mut fields: Vec<&str>| -> Value {
        if !bound {
            fields.push("site");
        }
        json!(fields)
    };

    json!([
        {
            "name": "search_tools",
            "description": "Search a site's generated tools by task keywords. Returns ranked matches with tool id, summary, safety (read/write/unknown), and confidence. Always start here.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "Task or keywords, e.g. 'list recent orders'" },
                    "limit": { "type": "integer", "description": "Maximum results (default 5)" },
                    "site": site_schema
                },
                "required": require(vec!["query"])
            }
        },
        {
            "name": "get_tool_schema",
            "description": "Fetch one tool's full definition: input schema, path parameters, auth requirement, safety classification, and example input/response. Call before call_tool.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "tool_id": { "type": "string", "description": "Tool id or name from search_tools" },
                    "site": site_schema
                },
                "required": require(vec!["tool_id"])
            }
        },
        {
            "name": "call_tool",
            "description": "Execute a generated tool with JSON arguments matching its input schema. Errors are structured JSON: on approval_required ask the user to run `tapestry approve <site> <tool_id>`; on auth_expired ask the user to refresh stored credentials. Do not retry those without user action.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "tool_id": { "type": "string", "description": "Tool id or name from search_tools" },
                    "arguments": { "type": "object", "description": "Arguments matching the tool's input schema" },
                    "site": site_schema
                },
                "required": require(vec!["tool_id"])
            }
        },
        {
            "name": "get_evidence",
            "description": "Inspect the observed evidence, warnings, and per-field confidence behind a generated tool. Useful before approving or trusting a low-confidence tool.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "tool_id": { "type": "string", "description": "Tool id or name from search_tools" },
                    "site": site_schema
                },
                "required": require(vec!["tool_id"])
            }
        }
    ])
}

/// Handle `tools/call`. Protocol-level problems (unknown tool, malformed
/// params) become JSON-RPC errors; anything from the runtime — including
/// structured runtime errors — is returned as tool content so the agent can
/// read and act on it.
fn tools_call(
    config: &McpServerConfig,
    cache: &mut SpecCache,
    params: &Value,
) -> Result<Value, (i64, String)> {
    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return Err((-32602, "Missing tool name".to_string()));
    };
    let empty = Map::new();
    let args = params
        .get("arguments")
        .and_then(Value::as_object)
        .unwrap_or(&empty);

    if ![
        "search_tools",
        "get_tool_schema",
        "call_tool",
        "get_evidence",
    ]
    .contains(&name)
    {
        return Err((-32602, format!("Unknown tool: {name}")));
    }

    // Reject unrecognized keys instead of silently ignoring them: a model
    // that sends `args` instead of `arguments` would otherwise execute the
    // call with defaults it never chose, and the resulting "missing required
    // argument" error points at the wrong problem.
    let allowed: &[&str] = match name {
        "search_tools" => &["site", "query", "limit"],
        "call_tool" => &["site", "tool_id", "arguments"],
        _ => &["site", "tool_id"],
    };
    let unknown: Vec<&str> = args
        .keys()
        .map(String::as_str)
        .filter(|key| !allowed.contains(key))
        .collect();
    if !unknown.is_empty() {
        return Err((
            -32602,
            format!(
                "Unknown parameter(s) for {name}: {}. Expected only: {}.",
                unknown.join(", "),
                allowed.join(", ")
            ),
        ));
    }

    let site = match resolve_site(config, args) {
        Ok(site) => site,
        Err(error) => return Ok(tool_result(error)),
    };
    let spec = match cache.load(&site) {
        Ok(spec) => spec,
        Err(_) => {
            return Ok(tool_result(json!({
                "status": "error",
                "error_type": "site_not_ready",
                "retryable": false,
                "message": format!(
                    "Site '{site}' has no generated ToolSpec. The user must run `tapestry import <har> --site {site}` (or `tapestry record`) and `tapestry generate {site}` first."
                ),
                "available_sites": available_sites()
            })));
        }
    };

    let value = match name {
        "search_tools" => {
            let Some(query) = args.get("query").and_then(Value::as_str) else {
                return Err((-32602, "search_tools requires a string `query`".to_string()));
            };
            let limit = args
                .get("limit")
                .and_then(Value::as_u64)
                .map(|v| v.clamp(1, 50) as usize)
                .unwrap_or(5);
            let results = tapestry_runtime::search_tools(&spec, query, limit);
            if results.is_empty() {
                json!({
                    "status": "success",
                    "tools": [],
                    "note": "No tools matched. Try different keywords, or the site's capture may not cover this task."
                })
            } else {
                json!({ "status": "success", "tools": results })
            }
        }
        "get_tool_schema" => {
            let tool_id = required_tool_id(args)?;
            match tapestry_runtime::get_tool_schema(&spec, tool_id) {
                Some(schema) => schema,
                None => tool_not_found(tool_id),
            }
        }
        "call_tool" => {
            let tool_id = required_tool_id(args)?;
            let arguments = args.get("arguments").cloned().unwrap_or_else(|| json!({}));
            let mut options =
                crate::runtime_options_for(&spec, config.max_pages, config.live, config.offline);
            options.credentials = crate::load_site_credentials(&site)
                .map_err(|error| (-32603, format!("failed to load credentials: {error}")))?;
            let value =
                tapestry_runtime::call_tool_with_options(&spec, tool_id, arguments, &options);
            crate::record_tool_health(&site, &spec, tool_id, &value);
            value
        }
        "get_evidence" => {
            let tool_id = required_tool_id(args)?;
            tapestry_runtime::get_evidence(&spec, tool_id)
        }
        _ => unreachable!("tool name validated above"),
    };

    Ok(tool_result(value))
}

fn required_tool_id(args: &Map<String, Value>) -> Result<&str, (i64, String)> {
    args.get("tool_id")
        .and_then(Value::as_str)
        .ok_or_else(|| (-32602, "missing required string `tool_id`".to_string()))
}

fn tool_not_found(tool_id: &str) -> Value {
    json!({
        "status": "error",
        "error_type": "tool_not_found",
        "retryable": false,
        "message": format!("Tool '{tool_id}' not found. Use search_tools to find valid tool ids."),
    })
}

fn resolve_site(config: &McpServerConfig, args: &Map<String, Value>) -> Result<String, Value> {
    let site = args
        .get("site")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| config.default_site.clone());
    let Some(site) = site else {
        return Err(json!({
            "status": "error",
            "error_type": "site_not_specified",
            "retryable": false,
            "message": "No site given and the server has no default site. Pass `site`.",
            "available_sites": available_sites()
        }));
    };
    if crate::validate_site_name(&site).is_err() {
        return Err(json!({
            "status": "error",
            "error_type": "site_not_specified",
            "retryable": false,
            "message": format!("Site name '{site}' is invalid — use only letters, digits, hyphens, and underscores."),
            "available_sites": available_sites()
        }));
    }
    Ok(site)
}

fn available_sites() -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(crate::sites_root()) else {
        return Vec::new();
    };
    let mut sites: Vec<String> = entries
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().is_dir())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();
    sites.sort();
    sites
}

fn tool_result(value: Value) -> Value {
    let is_error = value.get("status").and_then(Value::as_str) == Some("error");
    // Compact JSON: the consumer is a model, and indentation is pure token
    // cost on every single tool response.
    let text = value.to_string();
    json!({
        "content": [{ "type": "text", "text": text }],
        "isError": is_error
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(default_site: Option<&str>) -> McpServerConfig {
        McpServerConfig {
            default_site: default_site.map(ToOwned::to_owned),
            live: false,
            offline: false,
            max_pages: 1,
        }
    }

    fn request(id: u64, method: &str, params: Value) -> Value {
        json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
    }

    #[test]
    fn initialize_reports_server_info_and_tools_capability() {
        let response = handle_message(
            &config(Some("demo")),
            &mut SpecCache::default(),
            &request(1, "initialize", json!({ "protocolVersion": "2024-11-05" })),
        )
        .expect("initialize returns a response");

        let result = &response["result"];
        assert_eq!(result["protocolVersion"], "2024-11-05");
        assert_eq!(result["serverInfo"]["name"], "tapestry");
        assert!(result["capabilities"]["tools"].is_object());
        assert!(result["instructions"]
            .as_str()
            .expect("instructions present")
            .contains("search_tools"));
    }

    #[test]
    fn tools_list_exposes_exactly_the_four_runtime_methods() {
        let response = handle_message(
            &config(Some("demo")),
            &mut SpecCache::default(),
            &request(2, "tools/list", json!({})),
        )
        .expect("tools/list returns a response");

        let tools = response["result"]["tools"].as_array().expect("tools array");
        let names: Vec<&str> = tools
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect();
        assert_eq!(
            names,
            vec![
                "search_tools",
                "get_tool_schema",
                "call_tool",
                "get_evidence"
            ]
        );
        // Bound server: site stays optional.
        let required = tools[0]["inputSchema"]["required"]
            .as_array()
            .expect("required array");
        assert!(!required.iter().any(|value| value == "site"));
    }

    #[test]
    fn unbound_server_requires_site_argument() {
        let response = handle_message(
            &config(None),
            &mut SpecCache::default(),
            &request(3, "tools/list", json!({})),
        )
        .expect("tools/list returns a response");

        for tool in response["result"]["tools"].as_array().expect("tools") {
            let required = tool["inputSchema"]["required"]
                .as_array()
                .expect("required array");
            assert!(
                required.iter().any(|value| value == "site"),
                "tool {} should require site",
                tool["name"]
            );
        }
    }

    #[test]
    fn notifications_get_no_response() {
        let message = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
        assert!(
            handle_message(&config(Some("demo")), &mut SpecCache::default(), &message).is_none()
        );
    }

    #[test]
    fn unknown_method_returns_method_not_found() {
        let response = handle_message(
            &config(Some("demo")),
            &mut SpecCache::default(),
            &request(4, "resources/list", json!({})),
        )
        .expect("unknown method with id returns an error response");
        assert_eq!(response["error"]["code"], -32601);
    }

    #[test]
    fn unknown_tool_name_is_a_protocol_error() {
        let response = handle_message(
            &config(Some("demo")),
            &mut SpecCache::default(),
            &request(5, "tools/call", json!({ "name": "delete_everything" })),
        )
        .expect("response");
        assert_eq!(response["error"]["code"], -32602);
    }

    #[test]
    fn unknown_parameter_is_rejected_with_expected_keys() {
        // A model that sends `args` instead of `arguments` must get a
        // correction, not a silent call with default arguments.
        let response = handle_message(
            &config(Some("demo")),
            &mut SpecCache::default(),
            &request(
                7,
                "tools/call",
                json!({
                    "name": "call_tool",
                    "arguments": { "tool_id": "tool_x", "args": { "limit": 3 } }
                }),
            ),
        )
        .expect("response");

        assert_eq!(response["error"]["code"], -32602);
        let message = response["error"]["message"].as_str().expect("message");
        assert!(message.contains("args"));
        assert!(message.contains("arguments"));
    }

    #[test]
    fn missing_site_produces_structured_tool_error() {
        let response = handle_message(
            &config(None),
            &mut SpecCache::default(),
            &request(
                6,
                "tools/call",
                json!({ "name": "search_tools", "arguments": { "query": "list items" } }),
            ),
        )
        .expect("response");

        let result = &response["result"];
        assert_eq!(result["isError"], true);
        let text = result["content"][0]["text"].as_str().expect("text");
        assert!(text.contains("site_not_specified"));
    }

    #[test]
    fn parse_error_returns_jsonrpc_parse_error() {
        let response = handle_line(
            &config(Some("demo")),
            &mut SpecCache::default(),
            "{not json",
        )
        .expect("response");
        assert_eq!(response["error"]["code"], -32700);
    }
}
