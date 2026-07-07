use super::*;
use tapestry_core::*;

#[test]
fn merge_skips_exact_duplicates_and_keeps_new_evidence() {
    let existing = vec![observation(
        "GET",
        "http://x.test/api/items",
        None,
        Some(json!({"items":[1]})),
    )];
    let incoming = vec![
        // Exact duplicate: dropped.
        observation(
            "GET",
            "http://x.test/api/items",
            None,
            Some(json!({"items":[1]})),
        ),
        // Same endpoint, different response: kept as new evidence.
        observation(
            "GET",
            "http://x.test/api/items",
            None,
            Some(json!({"items":[2]})),
        ),
        // New endpoint: kept.
        observation(
            "GET",
            "http://x.test/api/users",
            None,
            Some(json!({"users":[]})),
        ),
    ];

    let outcome = merge_observations(existing, incoming);

    assert!(outcome.merged_into_existing);
    assert_eq!(outcome.added, 2);
    assert_eq!(outcome.duplicates, 1);
    assert_eq!(outcome.observations.len(), 3);
}

#[test]
fn merge_into_empty_site_reports_fresh_import() {
    let incoming = vec![observation("GET", "http://x.test/api/items", None, None)];
    let outcome = merge_observations(Vec::new(), incoming);
    assert!(!outcome.merged_into_existing);
    assert_eq!(outcome.added, 1);
    assert_eq!(
        format_capture_message("demo", &outcome, "Imported"),
        "Imported 1 observations for site 'demo'"
    );
}

#[test]
fn merged_capture_message_reports_new_duplicates_and_total() {
    let existing = vec![observation("GET", "http://x.test/api/items", None, None)];
    let incoming = vec![
        observation("GET", "http://x.test/api/items", None, None),
        observation("GET", "http://x.test/api/users", None, None),
    ];
    let outcome = merge_observations(existing, incoming);
    let message = format_capture_message("demo", &outcome, "Imported");
    assert!(message.contains("1 new"));
    assert!(message.contains("1 duplicate(s) skipped"));
    assert!(message.contains("2 total"));
}

#[test]
fn health_classifies_conformant_live_success_as_healthy() {
    let response = json!({
        "status": "success",
        "data": {},
        "execution": { "mode": "live" },
        "conformance": { "field_compatibility": 1.0, "missing_fields": [] }
    });
    let update = classify_tool_health(&response, "live", "T0", None);
    let health = update.tool_health.expect("health recorded");
    assert_eq!(health.status, "healthy");
    assert_eq!(health.last_success.as_deref(), Some("T0"));
    assert!(update.auth_success);
    assert!(!update.auth_failure);
}

#[test]
fn health_classifies_low_conformance_as_degraded_with_detail() {
    let response = json!({
        "status": "success",
        "data": {},
        "execution": { "mode": "live" },
        "conformance": { "field_compatibility": 0.25, "missing_fields": ["title", "owner"] }
    });
    let update = classify_tool_health(&response, "live", "T0", None);
    let health = update.tool_health.expect("health recorded");
    assert_eq!(health.status, "degraded");
    let detail = health.detail.expect("detail");
    assert!(detail.contains("25%"));
    assert!(detail.contains("title, owner"));
}

#[test]
fn health_auth_expired_updates_auth_state_not_tool_health() {
    let response = json!({
        "status": "error",
        "error_type": "auth_expired",
        "http_status": 401
    });
    let update = classify_tool_health(&response, "live", "T0", None);
    assert!(update.tool_health.is_none());
    assert!(update.auth_failure);
}

#[test]
fn health_endpoint_error_is_broken_and_keeps_previous_success() {
    let response = json!({
        "status": "error",
        "error_type": "endpoint_error",
        "http_status": 500
    });
    let update = classify_tool_health(&response, "live", "T1", Some("T0".to_string()));
    let health = update.tool_health.expect("health recorded");
    assert_eq!(health.status, "broken");
    assert_eq!(health.http_status, Some(500));
    assert_eq!(health.last_success.as_deref(), Some("T0"));
}

#[test]
fn health_ignores_approval_and_argument_errors() {
    for response in [
        json!({ "status": "error", "error_type": "approval_required" }),
        json!({ "status": "error", "error_type": "schema_mismatch" }),
        json!({ "status": "error", "error_type": "rate_limited", "http_status": 429 }),
    ] {
        let update = classify_tool_health(&response, "live", "T0", None);
        assert!(update.tool_health.is_none(), "no health for {response}");
        assert!(!update.auth_failure || response["error_type"] == "auth_expired");
    }
}

#[test]
fn agent_task_successfully_lists_and_summarizes_items() {
    let spec = spec(vec![list_tool()]);
    let output = run_agent_task(
        &spec,
        &[],
        "List the most recent 5 items and summarize them",
        false,
        &tapestry_runtime::RuntimeOptions::default(),
    );

    assert!(output.contains("Summary: 1 item(s) returned"));
    assert!(output.contains("One"));
}

#[test]
fn agent_task_reports_no_matching_tool() {
    let spec = spec(vec![]);
    let output = run_agent_task(
        &spec,
        &[],
        "List items",
        false,
        &tapestry_runtime::RuntimeOptions::default(),
    );

    assert!(output.contains("No matching tool found"));
}

#[test]
fn agent_task_surfaces_approval_required_for_write_tool() {
    let spec = spec(vec![create_tool(false)]);
    let output = run_agent_task(
        &spec,
        &[],
        "Create item named A",
        false,
        &tapestry_runtime::RuntimeOptions::default(),
    );

    assert!(output.contains("approve the tool"));
}

#[test]
fn agent_task_surfaces_missing_required_argument() {
    let spec = spec(vec![get_tool()]);
    let output = run_agent_task(
        &spec,
        &[],
        "Get item",
        false,
        &tapestry_runtime::RuntimeOptions::default(),
    );

    assert!(output.contains("Missing required argument: id"));
    assert!(output.contains("Type: integer"));
    assert!(output.contains("tapestry tools schema fixture get_item"));
}

#[test]
fn agent_task_trace_includes_each_stage() {
    let spec = spec(vec![list_tool()]);
    let output = run_agent_task(
        &spec,
        &[],
        "List 5 items",
        true,
        &tapestry_runtime::RuntimeOptions::default(),
    );

    assert!(output.contains("[agent] search_tools query=\"List 5 items\""));
    assert!(output.contains("[agent] intent=search_or_list"));
    assert!(output.contains("[agent] execution_mode=live_http"));
    assert!(output.contains("[agent] selected tool=list_items score="));
    assert!(output.contains("[agent] rank boost read_search_tool list_items"));
    assert!(output.contains("[agent] schema loaded"));
    assert!(output.contains("\"limit\":5"));
    assert!(output.contains("[agent] arg limit inferred from number_from_task"));
    assert!(output.contains("[agent] call_tool success"));
}

#[test]
fn agent_task_trace_reports_offline_execution_mode() {
    let spec = spec(vec![list_tool()]);
    let options = tapestry_runtime::RuntimeOptions {
        offline_har_replay: true,
        ..tapestry_runtime::RuntimeOptions::default()
    };
    let output = run_agent_task(&spec, &[], "List 5 items", true, &options);

    assert!(output.contains("[agent] execution_mode=offline_har_replay"));
    assert!(output.contains("[agent] call_tool success"));
}

#[test]
fn record_guidance_text_is_actionable() {
    let guidance = record_guidance_text();

    assert!(guidance.contains("Recording started."));
    assert!(guidance.contains("search/list something"));
    assert!(guidance.contains("open a detail page"));
    assert!(guidance.contains("Press Enter when finished."));
}

#[test]
fn record_summary_includes_capture_quality_metrics() {
    let observations = vec![
        Observation {
            method: "GET".to_string(),
            url: "https://example.com/api/items".to_string(),
            path: "/api/items".to_string(),
            query: Default::default(),
            request_headers: Default::default(),
            request_body: None,
            response_status: Some(200),
            response_headers: Default::default(),
            response_body: Some(json!({"items":[{"id":1}]})),
            warnings: vec![],
        },
        Observation {
            method: "POST".to_string(),
            url: "https://example.com/api/items".to_string(),
            path: "/api/items".to_string(),
            query: Default::default(),
            request_headers: Default::default(),
            request_body: Some(json!({"name":"Item"})),
            response_status: Some(200),
            response_headers: Default::default(),
            response_body: None,
            warnings: vec![],
        },
    ];
    let summary = format_record_summary("fixture", &observations);

    assert!(summary.contains("Capture quality:"));
    assert!(summary.contains("API observations: 2"));
    assert!(summary.contains("Response body coverage: 50%"));
    assert!(summary.contains("Replayable tools (estimate): 1"));
    assert!(summary.contains("Missing response bodies: 1"));
    assert!(summary.contains("Recommended next action:"));
}

#[test]
fn record_low_signal_failure_respects_allow_low_signal() {
    let summary = tapestry_input::CaptureSummary::from_observations(&[]);

    assert!(record_low_signal_failure(&summary, 1, false).is_some());
    assert!(record_low_signal_failure(&summary, 1, true).is_none());
}

#[test]
fn record_low_signal_failure_requires_minimum_api_observations() {
    let observations = vec![Observation {
        method: "GET".to_string(),
        url: "https://example.com/page".to_string(),
        path: "/page".to_string(),
        query: Default::default(),
        request_headers: Default::default(),
        request_body: None,
        response_status: Some(200),
        response_headers: Default::default(),
        response_body: None,
        warnings: vec![],
    }];
    let summary = tapestry_input::CaptureSummary::from_observations(&observations);

    assert!(record_low_signal_failure(&summary, 2, false).is_some());
    assert!(record_low_signal_failure(&summary, 0, false).is_none());
}

#[test]
fn agent_task_trace_includes_write_tool_penalty_for_search_intent() {
    let mut write_tool = create_tool(false);
    write_tool.name = "create_clients.SearchResultsOption".to_string();
    write_tool.id = write_tool.name.clone();
    write_tool.description = "Search flights results option".to_string();
    write_tool.path = "/api/flights/search".to_string();
    let spec = spec(vec![write_tool]);
    let output = run_agent_task(
        &spec,
        &[],
        "Search for flights",
        true,
        &tapestry_runtime::RuntimeOptions::default(),
    );

    assert!(output.contains("[agent] intent=search_or_list"));
    assert!(output.contains("[agent] rank penalty write_tool_for_search"));
    assert!(output.contains("SearchResultsOption"));
}

#[test]
fn checkout_intent_trace_prefers_cart_write_tool() {
    let mut cart = create_tool(true);
    cart.name = "create_add-line-items".to_string();
    cart.id = cart.name.clone();
    cart.path = "/checkout/cart".to_string();
    let spec = spec(vec![list_tool(), cart]);
    let output = run_agent_task(
        &spec,
        &[],
        "Add item to cart",
        true,
        &tapestry_runtime::RuntimeOptions::default(),
    );

    assert!(output.contains("[agent] intent=checkout_or_purchase"));
    assert!(output.contains("[agent] rank boost write_checkout_tool create_add-line-items"));
}

#[test]
fn agent_task_offline_reports_replay_not_found() {
    let spec = spec(vec![list_tool_without_example()]);
    let options = tapestry_runtime::RuntimeOptions {
        offline_har_replay: true,
        ..tapestry_runtime::RuntimeOptions::default()
    };
    let output = run_agent_task(&spec, &[], "List 5 items", true, &options);

    assert!(output.contains("[agent] execution_mode=offline_har_replay"));
    assert!(output.contains("[agent] call_tool error=replay_not_found"));
    assert!(output.contains("No captured HAR response matched this request"));
}

#[test]
fn agent_task_infers_filter_from_search_products() {
    let spec = spec(vec![search_filter_tool("filter")]);
    let output = run_agent_task(
        &spec,
        &[],
        "Search for products",
        true,
        &tapestry_runtime::RuntimeOptions::default(),
    );

    assert!(output.contains("[agent] arguments={\"filter\":\"products\"}"));
    assert!(output.contains("[agent] arg filter inferred from search_term_from_task"));
    assert!(output.contains("Summary: 1 item(s) returned"));
}

#[test]
fn agent_task_infers_filter_from_search_sofas() {
    let plan = plan_agent_arguments(
        "Search for sofas",
        None,
        &[],
        &serde_json::to_value(search_filter_tool("filter")).unwrap(),
    );

    assert_eq!(plan.arguments["filter"], "sofas");
    assert!(plan.missing.is_empty());
}

#[test]
fn agent_task_infers_q_query_and_search_args_from_task() {
    for name in ["q", "query", "search"] {
        let plan = plan_agent_arguments(
            "Search for sofas",
            None,
            &[],
            &serde_json::to_value(search_filter_tool(name)).unwrap(),
        );

        assert_eq!(plan.arguments[name], "sofas");
        assert!(plan.missing.is_empty());
    }
}

#[test]
fn agent_task_recovers_graphql_required_object_from_example_input() {
    let mut tool = graphql_tool();
    tool.input_schema = json!({
        "type": "object",
        "properties": {
            "configs": {
                "type": "object",
                "properties": {
                    "term": {"type":"string"}
                },
                "required": ["term"]
            }
        },
        "required": ["configs"]
    });
    tool.example_input = Some(json!({
        "configs": {
            "term": "groceries"
        }
    }));
    let spec = spec(vec![tool]);

    let output = run_agent_task(
        &spec,
        &[],
        "Search groceries",
        true,
        &tapestry_runtime::RuntimeOptions::default(),
    );

    assert!(output.contains("[agent] arguments={\"configs\":{\"term\":\"groceries\"}}"));
    assert!(output.contains("[agent] arg configs inferred from example_input"));
}

#[test]
fn agent_task_recovers_graphql_required_object_from_captured_variables() {
    let mut tool = graphql_tool();
    tool.input_schema = json!({
        "type": "object",
        "properties": {
            "configs": {
                "type": "object",
                "properties": {
                    "term": {"type":"string"}
                },
                "required": ["term"]
            }
        },
        "required": ["configs"]
    });
    tool.example_input = None;
    let spec = spec(vec![tool]);
    let observations = vec![observation(
        "POST",
        "https://xapi.test/",
        Some(json!({
            "operationName": "SearchGroceries",
            "query": "query SearchGroceries($configs: ConfigInput!) { taxonomy(configs: $configs) { name } }",
            "variables": {
                "configs": {
                    "term": "groceries"
                }
            }
        })),
        Some(json!({"data": {"taxonomy": []}})),
    )];

    let selected = select_agent_tool(
        &spec,
        &observations,
        "Search groceries",
        &tapestry_runtime::RuntimeOptions::default(),
    )
    .unwrap();

    assert_eq!(selected.plan.arguments["configs"]["term"], "groceries");
    assert!(selected
        .plan
        .provenance
        .iter()
        .any(|item| item.source == "observed_graphql_variables"));
}

#[test]
fn missing_required_arg_guidance_includes_type_examples_and_schema_command() {
    let spec = spec(vec![required_category_tool()]);
    let output = run_agent_task(
        &spec,
        &[],
        "List items",
        false,
        &tapestry_runtime::RuntimeOptions::default(),
    );

    assert!(output.contains("Missing required argument: category"));
    assert!(output.contains("Type: string"));
    assert!(output.contains("Examples/defaults: examples=none, default=none"));
    assert!(output.contains("Reason: no default/example was available"));
    assert!(output.contains("Or run: tapestry tools schema fixture list_by_category"));
}

#[test]
fn missing_graphql_variable_guidance_is_specific() {
    let mut tool = graphql_tool();
    tool.input_schema = json!({
        "type": "object",
        "properties": {
            "configs": {
                "type": "object"
            }
        },
        "required": ["configs"]
    });
    tool.example_input = None;
    tool.response_schema = json!({
        "type": "object",
        "properties": {},
        "required": []
    });
    let spec = spec(vec![tool]);

    let output = run_agent_task(
        &spec,
        &[],
        "Search groceries",
        false,
        &tapestry_runtime::RuntimeOptions::default(),
    );

    assert!(output.contains("Missing required GraphQL variable: configs"));
    assert!(output.contains("request payloads included"));
}

#[test]
fn agent_selection_penalizes_uninferable_required_args() {
    let mut bad = required_category_tool();
    bad.name = "list_products_by_category".to_string();
    bad.id = bad.name.clone();
    bad.description = "GET /api/products/category".to_string();
    let good = search_filter_tool("filter");
    let spec = spec(vec![bad, good]);

    let selected = select_agent_tool(
        &spec,
        &[],
        "Search for products",
        &tapestry_runtime::RuntimeOptions::default(),
    )
    .unwrap();

    assert_eq!(selected.result.name, "search_products");
    assert!(selected.plan.missing.is_empty());
}

#[test]
fn agent_selection_offline_prefers_replayable_over_lexical_match() {
    let mut lexical = search_filter_tool("filter");
    lexical.name = "list_products.json".to_string();
    lexical.id = lexical.name.clone();
    lexical.description = "GET /api/products/search".to_string();
    lexical.example_response = None;
    lexical.response_schema = json!({"type":"object","properties":{},"required":[]});
    lexical.warnings = vec![
        "no_example_response_available".to_string(),
        "response_schema_empty".to_string(),
    ];

    let mut replayable = base_tool(
        "list_index.json",
        "GET",
        "/api/products/index",
        json!({
            "type": "object",
            "properties": {},
            "required": []
        }),
        json!({"items":[{"id":1,"title":"One"}]}),
        SafetyClassification::Read,
        true,
    );
    replayable.response_schema = json!({
        "type": "object",
        "properties": {
            "items": {
                "type": "array",
                "items": {"type":"object"}
            }
        },
        "required": ["items"]
    });

    let observations = vec![observation(
        "GET",
        "https://next.test/api/products/index",
        None,
        Some(json!({"items":[{"id":1,"title":"One"}]})),
    )];
    let options = tapestry_runtime::RuntimeOptions {
        offline_har_replay: true,
        ..tapestry_runtime::RuntimeOptions::default()
    };
    let spec = spec(vec![lexical, replayable]);

    let selected =
        select_agent_tool(&spec, &observations, "Search for products", &options).unwrap();

    assert_eq!(selected.result.name, "list_index.json");
    assert!(selected.replayable);
    assert!(selected
        .ranking_notes
        .iter()
        .any(|note| note.contains("boosted replayable")));
}

#[test]
fn agent_selection_live_keeps_lexical_best_match() {
    let mut lexical = search_filter_tool("filter");
    lexical.name = "list_products.json".to_string();
    lexical.id = lexical.name.clone();
    lexical.description = "GET /api/products/search".to_string();
    lexical.example_response = None;

    let mut replayable = base_tool(
        "list_index.json",
        "GET",
        "/api/products/index",
        json!({
            "type": "object",
            "properties": {},
            "required": []
        }),
        json!({"items":[{"id":1,"title":"One"}]}),
        SafetyClassification::Read,
        true,
    );
    replayable.response_schema = json!({
        "type": "object",
        "properties": {
            "items": {
                "type": "array",
                "items": {"type":"object"}
            }
        },
        "required": ["items"]
    });

    let observations = vec![observation(
        "GET",
        "https://next.test/api/products/index",
        None,
        Some(json!({"items":[{"id":1,"title":"One"}]})),
    )];
    let spec = spec(vec![lexical, replayable]);

    let selected = select_agent_tool(
        &spec,
        &observations,
        "Search for products",
        &tapestry_runtime::RuntimeOptions::default(),
    )
    .unwrap();

    assert_eq!(selected.result.name, "list_products.json");
    assert!(!selected.replayable);
}

#[test]
fn review_summary_counts_tool_quality_signals() {
    let spec = spec(vec![graphql_tool(), opaque_root_post_tool()]);
    let report = review_toolspec(&spec, None);

    assert_eq!(report.summary.total_tools, 2);
    assert_eq!(report.summary.read_tools, 1);
    assert_eq!(report.summary.unknown_tools, 1);
    assert_eq!(report.summary.graphql_tools, 1);
    assert_eq!(report.summary.opaque_root_post_tools, 1);
    assert_eq!(report.summary.tools_with_warnings, 1);
    assert_eq!(report.summary.tools_missing_examples, 1);
}

#[test]
fn usefulness_grade_calculation_separates_good_and_bad_tools() {
    let good = review_tool(&graphql_tool());
    let bad = review_tool(&opaque_root_post_tool());

    assert!(matches!(good.usefulness_grade.as_str(), "A" | "B"));
    assert_eq!(bad.usefulness_grade, "D");
    assert!(good.usefulness_score > bad.usefulness_score);
}

#[test]
fn review_json_output_has_expected_shape() {
    let report = review_toolspec(&spec(vec![graphql_tool()]), None);
    let value = serde_json::to_value(&report).unwrap();

    assert_eq!(value["site"], "fixture");
    assert_eq!(value["summary"]["total_tools"], 1);
    assert_eq!(value["tools"][0]["name"], "search_groceries");
    assert!(value["tools"][0]["usefulness_grade"].is_string());
}

#[test]
fn graphql_tool_gets_higher_grade_than_opaque_root_post() {
    let report = review_toolspec(&spec(vec![opaque_root_post_tool(), graphql_tool()]), None);
    let graphql = report
        .tools
        .iter()
        .find(|tool| tool.name == "search_groceries")
        .unwrap();
    let opaque = report
        .tools
        .iter()
        .find(|tool| tool.name == "opaque_root_post")
        .unwrap();

    assert!(graphql.usefulness_score > opaque.usefulness_score);
}

#[test]
fn warnings_reduce_usefulness_grade() {
    let mut clean = graphql_tool();
    clean.confidence.overall = 0.95;
    let mut noisy = graphql_tool();
    noisy.confidence.overall = 0.95;
    noisy.warnings = vec![
        "low_sample_count".to_string(),
        "operation_name_missing".to_string(),
        "low_semantic_confidence".to_string(),
    ];

    let clean_review = review_tool(&clean);
    let noisy_review = review_tool(&noisy);

    assert!(clean_review.usefulness_score > noisy_review.usefulness_score);
    assert!(clean_review.usefulness_grade <= noisy_review.usefulness_grade);
}

#[test]
fn localization_resource_receives_lower_usefulness_grade() {
    let localization = review_tool(&localization_tool());
    let api = review_tool(&list_tool());

    assert!(api.usefulness_score > localization.usefulness_score);
    assert!(matches!(localization.usefulness_grade.as_str(), "C" | "D"));
    assert!(localization
        .negative_signals
        .iter()
        .any(|signal| signal.contains("Static localization JSON")));
}

#[test]
fn platform_resource_receives_lower_usefulness_grade() {
    let platform = review_tool(&wix_manifest_tool());
    let commerce = review_tool(&commerce_query_tool());

    assert!(commerce.usefulness_score > platform.usefulness_score);
    assert!(matches!(platform.usefulness_grade.as_str(), "C" | "D"));
    assert!(platform
        .negative_signals
        .iter()
        .any(|signal| signal.contains("platform/config resource")));
}

#[test]
fn commerce_api_gets_positive_review_signal() {
    let review = review_tool(&commerce_query_tool());

    assert!(review
        .positive_signals
        .iter()
        .any(|signal| signal == "Commerce API detected"));
}

#[test]
fn review_text_includes_positive_negative_reasons() {
    let report = review_toolspec(&spec(vec![opaque_root_post_tool()]), None);
    let output = format_review_text(&report, false);

    assert!(output.contains("- opaque_root_post  D"));
    assert!(output.contains("+ Input schema inferred"));
    assert!(output.contains("- Missing example response"));
    assert!(output.contains("- Low semantic confidence"));
}

#[test]
fn review_verbose_includes_graphql_metadata_and_schema_keys() {
    let report = review_toolspec(&spec(vec![graphql_tool()]), None);
    let output = format_review_text(&report, true);

    assert!(output.contains("GraphQL: operation=SearchGroceries type=query batched=false"));
    assert!(output.contains("Input keys: basketId, count"));
    assert!(output.contains("Response keys: data"));
    assert!(output.contains("Evidence count: 1"));
}

#[test]
fn review_only_grade_filters_report_tools() {
    let report = review_toolspec(
        &spec(vec![graphql_tool(), opaque_root_post_tool()]),
        Some("D"),
    );

    assert_eq!(report.summary.total_tools, 1);
    assert_eq!(report.tools[0].name, "opaque_root_post");
    assert_eq!(report.tools[0].usefulness_grade, "D");
}

#[test]
fn review_text_includes_confidence_breakdown() {
    let report = review_toolspec(&spec(vec![graphql_tool()]), None);
    let output = format_review_text(&report, false);

    assert!(output.contains("Confidence: overall=0.90, input=0.90, response=0.90"));
}

#[test]
fn diagnose_reports_request_with_missing_response_body() {
    let observations = vec![observation(
        "POST",
        "https://xapi.test/",
        Some(
            json!({"operationName":"SearchGroceries","query":"query SearchGroceries { search { items { id } } }","variables":{}}),
        ),
        None,
    )];
    let mut tool = graphql_tool();
    tool.example_response = None;
    tool.response_schema = json!({"type":"object","properties":{},"required":[]});
    tool.warnings = vec![
        "response_schema_empty".to_string(),
        "no_example_response_available".to_string(),
    ];
    let report = diagnose_site(&spec(vec![tool]), &observations);
    let output = format_diagnose_text(&report);

    assert_eq!(report.summary.total_observations, 1);
    assert_eq!(report.summary.observations_with_response_bodies, 0);
    assert!(output.contains("Problem: request observed, but no response body captured."));
    assert!(output.contains("Preserve log"));
}

#[test]
fn diagnose_counts_json_response_body() {
    let observations = vec![observation(
        "GET",
        "https://app.test/api/items",
        None,
        Some(json!({"items": []})),
    )];
    let mut tool = list_tool();
    tool.response_schema = json!({
        "type": "object",
        "properties": {
            "items": {"type":"array","items":{}}
        },
        "required": ["items"]
    });
    let report = diagnose_site(&spec(vec![tool]), &observations);

    assert_eq!(report.summary.json_responses, 1);
    assert_eq!(report.summary.observations_with_response_bodies, 1);
    assert!(!report.tools[0].response_schema_empty);
}

#[test]
fn diagnose_counts_graphql_mapped_and_unmapped_responses() {
    let mapped = observation(
        "POST",
        "https://xapi.test/",
        Some(
            json!({"operationName":"SearchGroceries","query":"query SearchGroceries { search { items { id } } }","variables":{}}),
        ),
        Some(json!({"data":{"search":{"items":[]}}})),
    );
    let unmapped = observation(
        "POST",
        "https://xapi.test/",
        Some(
            json!({"operationName":"Other","query":"query Other { other { id } }","variables":{}}),
        ),
        Some(json!({"errors":[{"message":"no data"}]})),
    );
    let report = diagnose_site(&spec(vec![graphql_tool()]), &[mapped, unmapped]);

    assert_eq!(report.summary.graphql_requests, 2);
    assert_eq!(report.summary.graphql_responses_mapped, 1);
}

#[test]
fn diagnose_json_output_has_expected_shape() {
    let observations = vec![observation(
        "POST",
        "https://xapi.test/",
        Some(
            json!({"operationName":"SearchGroceries","query":"query SearchGroceries { search { items { id } } }","variables":{}}),
        ),
        Some(json!({"data":{"search":{"items":[]}}})),
    )];
    let report = diagnose_site(&spec(vec![graphql_tool()]), &observations);
    let value = serde_json::to_value(&report).unwrap();

    assert_eq!(value["site"], "fixture");
    assert_eq!(value["summary"]["generated_tools"], 1);
    assert_eq!(value["tools"][0]["name"], "search_groceries");
    assert!(value["tools"][0]["remediation"].is_string());
}

#[test]
fn diagnose_reports_static_resource_only_capture() {
    let observations = vec![observation(
        "GET",
        "https://game.test/lang/en.json",
        None,
        Some(json!({"PLAY":"Play","SAVE":"Save"})),
    )];
    let report = diagnose_site(&spec(vec![localization_tool()]), &observations);
    let output = format_diagnose_text(&report);

    assert_eq!(report.summary.generated_tools, 1);
    assert_eq!(report.summary.static_resource_tools, 1);
    assert!(output.contains("Only static JSON/config/localization resources were captured."));
    assert!(output.contains("account, save, search, or data API calls"));
}

#[test]
fn diagnose_reports_commerce_apis_with_missing_response_bodies() {
    let observations = vec![observation(
        "POST",
        "https://www.justkandy.co.uk/_api/cart-v2/v2/carts/current/add-line-items",
        Some(json!({"lineItems":[{"id":"1"}]})),
        None,
    )];
    let mut tool = cart_tool();
    tool.response_schema = json!({"type":"object","properties":{},"required":[]});
    tool.example_response = None;

    let report = diagnose_site(&spec(vec![tool, wix_manifest_tool()]), &observations);
    let output = format_diagnose_text(&report);

    assert_eq!(report.summary.commerce_api_tools, 1);
    assert_eq!(report.summary.platform_resource_tools, 1);
    assert!(output
        .contains("Commerce API requests were captured, but many response bodies are missing."));
    assert!(output.contains("Many Wix platform/config resources were captured."));
}

#[test]
fn validate_reports_success_top_tool_and_summaries() {
    let spec = spec(vec![list_tool()]);
    let observations = vec![observation(
        "GET",
        "https://app.test/api/items",
        None,
        Some(json!({"items":[{"id":1,"title":"One"}],"total":1})),
    )];

    let report = validate_site(
        &spec,
        &observations,
        "List the most recent 5 items",
        &tapestry_runtime::RuntimeOptions::default(),
    );
    let text = format_validate_text(&report);

    assert!(report.agent_task.success);
    assert_eq!(
        report.agent_task.top_tool_used.as_deref(),
        Some("list_items")
    );
    assert_eq!(report.review_summary.total_tools, 1);
    assert_eq!(report.diagnose_summary.generated_tools, 1);
    assert!(text.contains("Agent result: success"));
    assert!(text.contains("Recommended next action:"));
}

#[test]
fn validate_reports_no_matching_tool_failure() {
    let report = validate_site(
        &spec(vec![]),
        &[],
        "Find baskets",
        &tapestry_runtime::RuntimeOptions::default(),
    );

    assert!(!report.agent_task.success);
    assert_eq!(
        report.agent_task.failure_type.as_deref(),
        Some("no_matching_tool")
    );
    assert_eq!(report.agent_task.top_tool_used, None);
    assert!(report
        .recommended_next_action
        .contains("Capture a richer task flow"));
}

#[test]
fn validate_recommends_recapture_when_response_bodies_missing() {
    let observations = vec![observation("GET", "https://app.test/api/items", None, None)];
    let mut tool = list_tool();
    tool.example_response = None;
    let report = validate_site(
        &spec(vec![tool]),
        &observations,
        "List the most recent 5 items",
        &tapestry_runtime::RuntimeOptions::default(),
    );

    assert!(report.diagnose_summary.tools_missing_examples > 0);
    assert!(report
        .recommended_next_action
        .contains("Re-capture the HAR"));
}

#[test]
fn validate_offline_reports_replayability_aware_selection() {
    let mut lexical = search_filter_tool("filter");
    lexical.name = "list_products.json".to_string();
    lexical.id = lexical.name.clone();
    lexical.description = "GET /api/products/search".to_string();
    lexical.example_response = None;
    lexical.response_schema = json!({"type":"object","properties":{},"required":[]});

    let mut replayable = base_tool(
        "list_index.json",
        "GET",
        "/api/products/index",
        json!({
            "type": "object",
            "properties": {},
            "required": []
        }),
        json!({"items":[{"id":1,"title":"One"}]}),
        SafetyClassification::Read,
        true,
    );
    replayable.response_schema = json!({
        "type": "object",
        "properties": {
            "items": {
                "type": "array",
                "items": {"type":"object"}
            }
        },
        "required": ["items"]
    });

    let observations = vec![observation(
        "GET",
        "https://next.test/api/products/index",
        None,
        Some(json!({"items":[{"id":1,"title":"One"}]})),
    )];
    let options = tapestry_runtime::RuntimeOptions {
        offline_har_replay: true,
        ..tapestry_runtime::RuntimeOptions::default()
    };
    let report = validate_site(
        &spec(vec![lexical, replayable]),
        &observations,
        "Search for products",
        &options,
    );

    assert!(report.agent_task.success);
    assert_eq!(
        report.agent_task.top_tool_used.as_deref(),
        Some("list_index.json")
    );
    assert!(report
        .agent_task
        .ranking_note
        .as_deref()
        .unwrap_or_default()
        .contains("Offline ranking considered replayability."));
}

#[test]
fn validate_passes_offline_mode_to_runtime() {
    let options = tapestry_runtime::RuntimeOptions {
        offline_har_replay: true,
        ..tapestry_runtime::RuntimeOptions::default()
    };
    let report = validate_site(
        &spec(vec![list_tool_without_example()]),
        &[],
        "List the most recent 5 items",
        &options,
    );

    assert!(!report.agent_task.success);
    assert_eq!(
        report.agent_task.failure_type.as_deref(),
        Some("no_replayable_tool")
    );
}

#[test]
fn validate_json_output_has_expected_shape() {
    let report = validate_site(
        &spec(vec![list_tool()]),
        &[],
        "List the most recent 5 items",
        &tapestry_runtime::RuntimeOptions::default(),
    );
    let value = serde_json::to_value(&report).unwrap();

    assert_eq!(value["site"], "fixture");
    assert_eq!(value["agent_task"]["top_tool_used"], "list_items");
    assert!(value["review_summary"]["total_tools"].is_number());
    assert!(value["diagnose_summary"]["generated_tools"].is_number());
    assert!(value["recommended_next_action"].is_string());
}

#[test]
fn benchmark_suite_freezes_expected_sites_and_tasks() {
    let cases = benchmark_cases();
    let sites = cases
        .iter()
        .map(|case| case.site.as_str())
        .collect::<Vec<_>>();

    assert_eq!(cases.len(), 15);
    assert!(sites.contains(&"tesco"));
    assert!(sites.contains(&"localapp"));
    assert!(sites.contains(&"localapp-cdp"));
    assert!(sites.contains(&"next"));
    assert!(sites.contains(&"next-cdp"));
    assert!(sites.contains(&"justkandy"));
    assert!(sites.contains(&"justkandy-cdp"));
    assert!(sites.contains(&"melvor"));
    assert!(sites.contains(&"argos"));
    assert!(sites.contains(&"amazon"));
    assert!(sites.contains(&"wowhead"));
    assert!(sites.contains(&"skyscanner"));
    assert!(sites.contains(&"onthebeach"));
    assert!(sites.contains(&"fixture"));
    assert!(sites.contains(&"rightmove"));
}

#[test]
fn benchmark_report_serializes_expected_shape() {
    let report = BenchmarkReport {
        total_sites: 1,
        success_count: 1,
        failure_count: 0,
        expected_match_count: 1,
        drift_count: 0,
        capture_parity: Vec::new(),
        context_reduction: ContextReductionReport {
            meta_tool_tokens: 900,
            sites: Vec::new(),
            mean_reduction: None,
        },
        cases: vec![BenchmarkCaseReport {
            site: "fixture".to_string(),
            capture_variant: Some("har".to_string()),
            parity_group: None,
            task: "Search for products".to_string(),
            expected_outcome: "success".to_string(),
            expected_tool: Some("list_items".to_string()),
            selected_tool: Some("list_items".to_string()),
            success: true,
            failure_type: None,
            failure_bucket: "success".to_string(),
            outcome_matches_expected: true,
            tool_matches_expected: Some(true),
            review_grade: Some("A".to_string()),
            diagnose_summary: DiagnoseSummary {
                total_observations: 1,
                candidate_api_observations: 1,
                generated_tools: 1,
                observations_with_response_bodies: 1,
                json_responses: 1,
                graphql_requests: 0,
                graphql_responses_mapped: 0,
                tools_missing_examples: 0,
                tools_with_empty_response_schemas: 0,
                static_resource_tools: 0,
                platform_resource_tools: 0,
                telemetry_tools: 0,
                commerce_api_tools: 1,
            },
            endpoint_coverage: Some(1.0),
            ranking_note: Some("Offline ranking considered replayability.".to_string()),
        }],
    };
    let value = serde_json::to_value(&report).unwrap();
    let text = format_benchmark_text(&report);

    assert_eq!(value["total_sites"], 1);
    assert_eq!(value["cases"][0]["site"], "fixture");
    assert_eq!(value["cases"][0]["expected_outcome"], "success");
    assert_eq!(value["cases"][0]["failure_bucket"], "success");
    assert!(text.contains("Benchmark suite: 1 site(s)"));
    assert!(text.contains("Expected matches: 1 drift: 0"));
    assert!(text.contains("expected=success"));
    assert!(text.contains("failure_bucket=success"));
    assert!(text.contains("review_grade=A"));
}

#[test]
fn no_seeded_secret_survives_the_full_pipeline() {
    // Import the seeded fixture, run the analyzer, and check every
    // artifact an agent or log could ever see.
    let observations = tapestry_input::import_har("../../examples/fixtures/redaction.har").unwrap();
    let spec = tapestry_analyzer::analyze("redaction-test", &observations);

    let observations_json = serde_json::to_string(&observations).unwrap();
    let toolspec_json = serde_json::to_string(&spec).unwrap();
    assert!(
        !observations_json.contains("FAKESECRET"),
        "observations leaked"
    );
    assert!(!toolspec_json.contains("FAKESECRET"), "toolspec leaked");

    // Review and diagnose reports are printed to stdout; they must be
    // clean too.
    let review = review_toolspec(&spec, None);
    let review_json = serde_json::to_string(&review).unwrap();
    assert!(!review_json.contains("FAKESECRET"), "review leaked");
    let diagnose = diagnose_site(&spec, &observations);
    let diagnose_json = serde_json::to_string(&diagnose).unwrap();
    assert!(!diagnose_json.contains("FAKESECRET"), "diagnose leaked");

    // Agent trace output (the noisiest path) must be clean as well.
    let options = tapestry_runtime::RuntimeOptions {
        offline_har_replay: true,
        prefer_har_replay: true,
        ..tapestry_runtime::RuntimeOptions::default()
    };
    let trace = run_agent_task(&spec, &observations, "list items", true, &options);
    assert!(!trace.contains("FAKESECRET"), "agent trace leaked");
}

#[test]
fn endpoint_patterns_match_paths_with_params() {
    assert!(endpoint_pattern_matches("/api/items", "/api/items"));
    assert!(endpoint_pattern_matches("/api/items/{id}", "/api/items/42"));
    // A shorter pattern must NOT be covered by a deeper path.
    assert!(!endpoint_pattern_matches("/api/items", "/api/items/42"));
    assert!(!endpoint_pattern_matches("/api/items/{id}", "/api/items"));
    assert!(!endpoint_pattern_matches("/api/users", "/api/items"));
}

#[test]
fn endpoint_coverage_scores_against_ground_truth() {
    let observations = vec![
        observation("GET", "http://x.test/api/items?page=1", None, None),
        observation("GET", "http://x.test/api/items/7", None, None),
    ];
    let expected = vec![
        "/api/items".to_string(),
        "/api/items/{id}".to_string(),
        "/api/config".to_string(),
    ];
    let coverage = endpoint_coverage(&expected, &observations).expect("coverage");
    assert!((coverage - 2.0 / 3.0).abs() < 1e-9);
    assert!(endpoint_coverage(&[], &observations).is_none());
}

fn parity_case(
    site: &str,
    group: &str,
    cdp: bool,
    api_observations: usize,
    success: bool,
) -> BenchmarkCaseReport {
    BenchmarkCaseReport {
        site: site.to_string(),
        capture_variant: cdp.then(|| "cdp".to_string()),
        parity_group: Some(group.to_string()),
        task: "task".to_string(),
        expected_outcome: "success".to_string(),
        expected_tool: None,
        selected_tool: None,
        success,
        failure_type: (!success).then(|| "no_matching_tool".to_string()),
        failure_bucket: "unknown".to_string(),
        outcome_matches_expected: true,
        tool_matches_expected: None,
        review_grade: None,
        diagnose_summary: DiagnoseSummary {
            total_observations: api_observations + 1,
            candidate_api_observations: api_observations,
            generated_tools: api_observations,
            observations_with_response_bodies: api_observations,
            json_responses: api_observations,
            graphql_requests: 0,
            graphql_responses_mapped: 0,
            tools_missing_examples: 0,
            tools_with_empty_response_schemas: 0,
            static_resource_tools: 0,
            platform_resource_tools: 0,
            telemetry_tools: 0,
            commerce_api_tools: 0,
        },
        endpoint_coverage: None,
        ranking_note: None,
    }
}

#[test]
fn context_reduction_compares_meta_surface_against_full_toolspec() {
    let spec = tapestry_analyzer::analyze(
        "ctx",
        &tapestry_input::import_har("../../examples/fixtures/simple.har").unwrap(),
    );
    assert!(!spec.tools.is_empty());

    let report = build_context_reduction(&[
        ("ctx".to_string(), spec),
        (
            "empty".to_string(),
            ToolSpec {
                site: SiteInfo {
                    name: "empty".to_string(),
                    base_url: None,
                    source: vec![],
                    generated_at: None,
                    spec_version: "0.1.0".to_string(),
                },
                tools: vec![],
            },
        ),
    ]);

    assert!(report.meta_tool_tokens > 0);
    assert_eq!(report.sites.len(), 2);
    let ctx = &report.sites[0];
    assert!(ctx.full_toolspec_tokens > 0);
    // Sites with no tools are excluded from the mean instead of skewing it.
    assert!(report.sites[1].reduction.is_none());
    assert_eq!(report.mean_reduction, ctx.reduction);
}

#[test]
fn capture_parity_pairs_variants_and_flags_regressions() {
    let cases = vec![
        parity_case("app", "app", false, 4, true),
        parity_case("app-cdp", "app", true, 4, true),
        parity_case("shop", "shop", false, 5, true),
        parity_case("shop-cdp", "shop", true, 0, false),
        // Unpaired case: no parity entry.
        parity_case("solo", "solo", false, 2, true),
    ];

    let parity = build_capture_parity(&cases);

    assert_eq!(parity.len(), 2);
    let app = parity.iter().find(|p| p.group == "app").expect("app pair");
    assert!(app.cdp_meets_har);
    let shop = parity
        .iter()
        .find(|p| p.group == "shop")
        .expect("shop pair");
    assert!(!shop.cdp_meets_har);
    assert_eq!(shop.har.api_observations, 5);
    assert_eq!(shop.cdp.api_observations, 0);
}

#[test]
fn capture_parity_accepts_cdp_success_when_har_failed() {
    let cases = vec![
        parity_case("app", "app", false, 2, false),
        parity_case("app-cdp", "app", true, 3, true),
    ];
    let parity = build_capture_parity(&cases);
    assert!(parity[0].cdp_meets_har);
}

#[test]
fn cli_parses_record_command_arguments() {
    let cli = Cli::parse_from([
        "tapestry",
        "record",
        "https://example.com",
        "--site",
        "demo",
        "--browser",
        "chrome.exe",
        "--headless",
        "--timeout-secs",
        "30",
        "--max-body-bytes",
        "1024",
        "--include-third-party",
        "--output-observations",
        "--keep-profile",
        "--min-api-observations",
        "3",
        "--allow-low-signal",
    ]);

    match cli.command {
        Command::Record {
            url,
            site,
            browser,
            headless,
            timeout_secs,
            max_body_bytes,
            include_third_party,
            output_observations,
            keep_profile,
            min_api_observations,
            allow_low_signal,
            replace,
            ephemeral_profile,
            generate,
        } => {
            assert!(!replace);
            assert!(!ephemeral_profile);
            assert!(!generate);
            assert_eq!(url, "https://example.com");
            assert_eq!(site, "demo");
            assert_eq!(browser.as_deref(), Some(std::path::Path::new("chrome.exe")));
            assert!(headless);
            assert_eq!(timeout_secs, 30);
            assert_eq!(max_body_bytes, 1024);
            assert!(include_third_party);
            assert!(output_observations);
            assert!(keep_profile);
            assert_eq!(min_api_observations, 3);
            assert!(allow_low_signal);
        }
        other => panic!("unexpected command: {:?}", other),
    }
}

#[test]
fn runtime_options_prefer_har_replay_for_fixture_har_site() {
    let mut spec = spec(vec![list_tool()]);
    spec.site.source = vec!["har".to_string()];
    spec.site.base_url = Some("http://localhost:3000".to_string());

    let options = runtime_options_for(&spec, 1, false, false);

    assert!(options.allow_har_replay);
    assert!(options.prefer_har_replay);
}

#[test]
fn runtime_options_live_forces_live_http() {
    let mut spec = spec(vec![list_tool()]);
    spec.site.source = vec!["har".to_string()];
    spec.site.base_url = Some("http://localhost:3000".to_string());

    let options = runtime_options_for(&spec, 3, true, false);

    assert_eq!(options.max_pages, 3);
    assert!(!options.allow_har_replay);
    assert!(!options.prefer_har_replay);
}

#[test]
fn runtime_options_do_not_prefer_replay_for_normal_live_site() {
    let mut spec = spec(vec![list_tool()]);
    spec.site.name = "production".to_string();
    spec.site.source = vec!["har".to_string()];
    spec.site.base_url = Some("https://api.example.com".to_string());

    let options = runtime_options_for(&spec, 1, false, false);

    assert!(options.allow_har_replay);
    assert!(!options.prefer_har_replay);
}

#[test]
fn runtime_options_offline_forces_har_replay_only() {
    let spec = spec(vec![list_tool()]);

    let options = runtime_options_for(&spec, 2, false, true);

    assert_eq!(options.max_pages, 2);
    assert!(options.allow_har_replay);
    assert!(options.prefer_har_replay);
    assert!(options.offline_har_replay);
}

fn spec(tools: Vec<ToolDefinition>) -> ToolSpec {
    ToolSpec {
        site: SiteInfo {
            name: "fixture".to_string(),
            base_url: None,
            source: vec!["test".to_string()],
            generated_at: None,
            spec_version: "0.1.0".to_string(),
        },
        tools,
    }
}

fn list_tool() -> ToolDefinition {
    base_tool(
        "list_items",
        "GET",
        "/api/items",
        json!({
            "type": "object",
            "properties": {
                "limit": {"type":"integer"},
                "page": {"type":"integer", "default": 1}
            },
            "required": []
        }),
        json!({"items":[{"id":1,"title":"One"}],"total":1}),
        SafetyClassification::Read,
        true,
    )
}

fn list_tool_without_example() -> ToolDefinition {
    let mut tool = list_tool();
    tool.example_response = None;
    tool
}

fn get_tool() -> ToolDefinition {
    let mut tool = base_tool(
        "get_item",
        "GET",
        "/api/items/{id}",
        json!({
            "type": "object",
            "properties": {
                "id": {"type":"integer"}
            },
            "required": ["id"]
        }),
        json!({"id":1,"title":"One"}),
        SafetyClassification::Read,
        true,
    );
    tool.path_params = vec![PathParameter {
        name: "id".to_string(),
        schema: json!({"type":"integer"}),
        confidence: 0.9,
        examples: vec![json!(1)],
    }];
    tool
}

fn create_tool(approved: bool) -> ToolDefinition {
    base_tool(
        "create_item",
        "POST",
        "/api/items",
        json!({
            "type": "object",
            "properties": {
                "name": {"type":"string"}
            },
            "required": ["name"]
        }),
        json!({"id":1,"name":"A"}),
        SafetyClassification::Write,
        approved,
    )
}

fn search_filter_tool(arg_name: &str) -> ToolDefinition {
    base_tool(
        "search_products",
        "GET",
        "/api/products/search",
        json!({
            "type": "object",
            "properties": {
                arg_name: {"type":"string"}
            },
            "required": [arg_name]
        }),
        json!({"items":[{"id":1,"title":"Sofa"}]}),
        SafetyClassification::Read,
        true,
    )
}

fn required_category_tool() -> ToolDefinition {
    base_tool(
        "list_by_category",
        "GET",
        "/api/products/category",
        json!({
            "type": "object",
            "properties": {
                "category": {"type":"string"}
            },
            "required": ["category"]
        }),
        json!({"items":[{"id":1,"title":"Chair"}]}),
        SafetyClassification::Read,
        true,
    )
}

fn graphql_tool() -> ToolDefinition {
    let mut tool = base_tool(
        "search_groceries",
        "POST",
        "/",
        json!({
            "type": "object",
            "properties": {
                "basketId": {"type":"string"},
                "count": {"type":"integer"}
            },
            "required": []
        }),
        json!({"data":{"search":{"items":[{"id":1,"title":"Bread"}]}}}),
        SafetyClassification::Read,
        true,
    );
    tool.description = "Observed GraphQL query SearchGroceries at POST /".to_string();
    tool.graphql = Some(GraphqlInfo {
        operation_name: Some("SearchGroceries".to_string()),
        operation_type: Some("query".to_string()),
        query: Some(
            "query SearchGroceries($basketId: ID) { basket { groceries { title } } }".to_string(),
        ),
        batched: false,
    });
    tool.response_schema = json!({
        "type": "object",
        "properties": {
            "data": {"type":"object","properties":{"search":{"type":"object"}}}
        },
        "required": ["data"]
    });
    tool
}

fn opaque_root_post_tool() -> ToolDefinition {
    let mut tool = base_tool(
        "opaque_root_post",
        "POST",
        "/",
        json!({"type":"object","properties":{"payload":{"type":"object"}},"required":[]}),
        json!({"ok": true}),
        SafetyClassification::Unknown,
        false,
    );
    tool.response_schema = json!({"type":"object","properties":{},"required":[]});
    tool.example_response = None;
    tool.confidence.overall = 0.35;
    tool.warnings = vec![
        "opaque_root_post".to_string(),
        "operation_name_missing".to_string(),
        "low_semantic_confidence".to_string(),
    ];
    tool
}

fn localization_tool() -> ToolDefinition {
    let mut tool = base_tool(
        "list_en.json",
        "GET",
        "/lang/en.json",
        json!({"type":"object","properties":{},"required":[]}),
        json!({"PLAY":"Play","SAVE":"Save"}),
        SafetyClassification::Read,
        true,
    );
    tool.resource_kind = ResourceKind::LocalizationResource;
    tool.response_schema = json!({
        "type": "object",
        "properties": {
            "PLAY": {"type":"string"},
            "SAVE": {"type":"string"}
        },
        "required": ["PLAY", "SAVE"]
    });
    tool.warnings = vec!["localization_resource".to_string()];
    tool
}

fn wix_manifest_tool() -> ToolDefinition {
    let mut tool = base_tool(
        "list_rb_wixui.corvid.manifest.min.json",
        "GET",
        "/services/editor-elements/1.15085.0/rb_wixui.corvid.manifest.min.json",
        json!({"type":"object","properties":{},"required":[]}),
        json!({"components":{"ProductSpecification":["bundle.js"],"SearchBox":["bundle.js"]}}),
        SafetyClassification::Read,
        true,
    );
    tool.resource_kind = ResourceKind::PlatformResource;
    tool.response_schema = json!({
        "type":"object",
        "properties":{"components":{"type":"object"}},
        "required":["components"]
    });
    tool.warnings = vec!["platform_resource".to_string()];
    tool
}

fn commerce_query_tool() -> ToolDefinition {
    let mut tool = base_tool(
        "list_query",
        "GET",
        "/_api/cloud-data/v2/items/query",
        json!({
            "type":"object",
            "properties":{"filter":{"type":"string"}},
            "required":[]
        }),
        json!({"items":[{"name":"Sweets"}]}),
        SafetyClassification::Read,
        true,
    );
    tool.resource_kind = ResourceKind::CommerceApi;
    tool.warnings = vec!["commerce_api".to_string()];
    tool
}

fn cart_tool() -> ToolDefinition {
    let mut tool = base_tool(
        "create_add-line-items",
        "POST",
        "/_api/cart-v2/v2/carts/current/add-line-items",
        json!({
            "type":"object",
            "properties":{"lineItems":{"type":"array"}},
            "required":["lineItems"]
        }),
        json!({"cart":{"lineItems":[]}}),
        SafetyClassification::Write,
        false,
    );
    tool.resource_kind = ResourceKind::CommerceApi;
    tool.warnings = vec!["commerce_api".to_string()];
    tool
}

fn base_tool(
    name: &str,
    method: &str,
    path: &str,
    input_schema: Value,
    example_response: Value,
    safety: SafetyClassification,
    approved: bool,
) -> ToolDefinition {
    ToolDefinition {
        id: name.to_string(),
        name: name.to_string(),
        description: format!("{method} {path}"),
        method: method.to_string(),
        path: path.to_string(),
        resource_kind: ResourceKind::ApiAction,
        graphql: None,
        path_params: vec![],
        input_schema,
        response_schema: json!({"type":"object","properties":{},"required":[]}),
        example_response: Some(example_response),
        example_input: None,
        auth: AuthRequirement {
            required: false,
            method: None,
        },
        safety: SafetyInfo {
            classification: safety,
            confidence: 0.9,
            reasoning: "test".to_string(),
        },
        confidence: ConfidenceScores {
            overall: 0.9,
            path: 0.9,
            path_params: 0.9,
            method: 0.99,
            input_schema: 0.9,
            response_schema: 0.9,
            auth: 0.5,
            safety: 0.9,
        },
        evidence: vec![Evidence {
            source: "har".to_string(),
            evidence_type: "observed_requests".to_string(),
            count: 1,
            confidence: 0.9,
            detail: None,
        }],
        warnings: vec![],
        idempotency: IdempotencyInfo {
            safe_to_retry: method == "GET",
            confidence: 0.9,
            reasoning: "test".to_string(),
        },
        pagination: None,
        rate_limit: None,
        approved,
    }
}

fn observation(
    method: &str,
    url: &str,
    request_body: Option<Value>,
    response_body: Option<Value>,
) -> Observation {
    let parsed = url::Url::parse(url).unwrap();
    Observation {
        method: method.to_string(),
        url: url.to_string(),
        path: parsed.path().to_string(),
        query: parsed
            .query_pairs()
            .map(|(key, value)| (key.to_string(), Value::String(value.to_string())))
            .collect(),
        request_headers: request_body
            .as_ref()
            .map(|_| {
                std::collections::BTreeMap::from([(
                    "content-type".to_string(),
                    "application/json".to_string(),
                )])
            })
            .unwrap_or_default(),
        request_body,
        response_status: Some(200),
        response_headers: response_body
            .as_ref()
            .map(|_| {
                std::collections::BTreeMap::from([(
                    "content-type".to_string(),
                    "application/json".to_string(),
                )])
            })
            .unwrap_or_default(),
        response_body,
        warnings: vec![],
    }
}
