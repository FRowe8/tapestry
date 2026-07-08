#!/usr/bin/env python3
"""Real-agent MCP benchmark (readiness plan Phase 5).

Drives predefined tasks through Claude Code's actual MCP client — `claude -p`
in headless mode, connected to `tapestry serve` via --mcp-config — and
records, per task: success (verifiable string checks against the answer),
turns, and real token usage from the CLI's usage report. Alongside, it
computes the naive-baseline context cost: the estimated token size of
serializing every generated tool schema into context (chars/4, the same
estimator `tapestry benchmark` uses), which is what an agent without the
four-meta-tool design would carry on every request.

Usage:
    python benchmarks/agent_bench.py                       # all sites present
    python benchmarks/agent_bench.py --sites demo
    python benchmarks/agent_bench.py --model claude-sonnet-5

Needs the `claude` CLI on PATH and, for sites marked live, network access to
the site's API (or the localapp server, which this script starts itself).
Each task consumes real model usage on your account. Results land in
benchmarks/results/ (gitignored); the summary table is printed for pasting
into docs/BENCHMARKS.md.
"""

import argparse
import json
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BENCH_DIR = REPO_ROOT / "benchmarks"
RESULTS_DIR = BENCH_DIR / "results"
TASKS_FILE = BENCH_DIR / "agent_tasks.json"

MCP_TOOLS = [
    "mcp__tapestry__search_tools",
    "mcp__tapestry__get_tool_schema",
    "mcp__tapestry__call_tool",
    "mcp__tapestry__get_evidence",
]
MAX_TURNS = 15


def resolve_tapestry_binary():
    import os

    env_bin = os.environ.get("TAPESTRY_BIN")
    if env_bin:
        return Path(env_bin)
    on_path = shutil.which("tapestry")
    if on_path:
        return Path(on_path)
    exe = "tapestry.exe" if sys.platform == "win32" else "tapestry"
    built = REPO_ROOT / "target" / "debug" / exe
    if not built.exists():
        subprocess.run(
            ["cargo", "build", "-q", "-p", "tapestry-cli"], cwd=REPO_ROOT, check=True
        )
    return built


def site_toolspec(site):
    path = REPO_ROOT / ".tapestry-dev" / "sites" / site / "toolspec.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def estimate_tokens(text):
    """chars/4 — deliberately the same estimator as `tapestry benchmark`,
    so the naive baseline here matches the context-reduction report."""
    return len(text) // 4


def naive_schema_dump_tokens(spec):
    return estimate_tokens(json.dumps(spec["tools"]))


def write_mcp_config(tapestry_bin, site, live):
    args = ["serve", "--site", site]
    if live:
        args.append("--live")
    config = {
        "mcpServers": {
            "tapestry": {"command": str(tapestry_bin), "args": args}
        }
    }
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    path = RESULTS_DIR / f".mcp-{site}.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    return path


def run_claude_task(mcp_config, task, model):
    prompt = (
        "You are connected to an MCP server named 'tapestry'. Using ONLY its "
        "tools (search_tools, get_tool_schema, call_tool, get_evidence), "
        f"complete this task and finish with a concise answer.\nTask: {task}"
    )
    cmd = [
        "claude",
        "-p",
        prompt,
        "--mcp-config",
        str(mcp_config),
        "--strict-mcp-config",
        "--allowedTools",
        ",".join(MCP_TOOLS),
        "--output-format",
        "json",
        "--max-turns",
        str(MAX_TURNS),
    ]
    if model:
        cmd += ["--model", model]
    proc = subprocess.run(
        cmd, cwd=REPO_ROOT, capture_output=True, text=True, timeout=600
    )
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {
            "is_error": True,
            "result": f"unparseable claude output (exit {proc.returncode}): "
            f"{proc.stdout[:400]} {proc.stderr[:400]}",
        }


def task_succeeded(definition, answer):
    text = (answer or "").lower()
    for needle in definition.get("check_all", []):
        if needle.lower() not in text:
            return False
    check_any = definition.get("check_any", [])
    if check_any and not any(needle.lower() in text for needle in check_any):
        return False
    return True


def run_site(site, config, tapestry_bin, model):
    spec = site_toolspec(site)
    if spec is None:
        print(f"-- skipping {site}: no generated toolspec (.tapestry-dev/sites/{site})")
        return None

    server = None
    if config.get("localapp_server"):
        server = subprocess.Popen(
            [sys.executable, str(REPO_ROOT / "scripts" / "localapp_server.py")],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(1.0)

    mcp_config = write_mcp_config(tapestry_bin, site, config.get("live", False))
    rows = []
    models_used = set()
    try:
        for definition in config["tasks"]:
            result = run_claude_task(mcp_config, definition["task"], model)
            usage = result.get("usage", {})
            models_used.update((result.get("modelUsage") or {}).keys())
            answer = result.get("result", "")
            row = {
                "task": definition["task"],
                "success": (not result.get("is_error", False))
                and task_succeeded(definition, answer),
                "num_turns": result.get("num_turns"),
                "input_tokens": usage.get("input_tokens", 0),
                "cache_creation_tokens": usage.get("cache_creation_input_tokens", 0),
                "cache_read_tokens": usage.get("cache_read_input_tokens", 0),
                "output_tokens": usage.get("output_tokens", 0),
                "cost_usd": result.get("total_cost_usd"),
                "answer": (answer or "")[:300],
            }
            rows.append(row)
            status = "ok " if row["success"] else "FAIL"
            print(f"  [{status}] {definition['task'][:60]} "
                  f"(turns={row['num_turns']}, out={row['output_tokens']}t)")
    finally:
        if server:
            server.terminate()

    succeeded = sum(1 for r in rows if r["success"])
    total_context = [
        r["input_tokens"] + r["cache_creation_tokens"] + r["cache_read_tokens"]
        for r in rows
    ]
    naive = naive_schema_dump_tokens(spec)
    return {
        "site": site,
        "model": sorted(models_used),
        "tools_in_site": len(spec["tools"]),
        "tasks": len(rows),
        "succeeded": succeeded,
        "completion_rate": succeeded / len(rows) if rows else 0.0,
        "mean_turns": round(
            sum(r["num_turns"] or 0 for r in rows) / len(rows), 1
        ),
        "mean_context_tokens_per_task": int(sum(total_context) / len(rows)),
        "mean_output_tokens_per_task": int(
            sum(r["output_tokens"] for r in rows) / len(rows)
        ),
        "total_cost_usd": round(
            sum(r["cost_usd"] or 0 for r in rows), 4
        ),
        "naive_schema_dump_tokens": naive,
        "rows": rows,
    }


def print_summary(results):
    print("\n================ REAL-AGENT MCP BENCHMARK ================")
    header = (
        f"{'site':<16} {'tools':>5} {'tasks':>5} {'done':>5} {'turns':>6} "
        f"{'ctx tok/task':>12} {'out tok/task':>12} {'schema dump':>11}"
    )
    print(header)
    print("-" * len(header))
    for r in results:
        print(
            f"{r['site']:<16} {r['tools_in_site']:>5} {r['tasks']:>5} "
            f"{r['completion_rate']:>4.0%} {r['mean_turns']:>6} "
            f"{r['mean_context_tokens_per_task']:>12} "
            f"{r['mean_output_tokens_per_task']:>12} "
            f"{r['naive_schema_dump_tokens']:>11}"
        )
    print(
        "\nctx tok/task = measured input+cache tokens per task through the four "
        "meta-tools.\nschema dump = estimated tokens of every generated tool "
        "schema, which the naive\ndesign would add to context on top of the "
        "conversation -- on every request."
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sites", default=None, help="Comma-separated site subset")
    parser.add_argument("--model", default=None, help="Model override for claude -p")
    args = parser.parse_args()

    if shutil.which("claude") is None:
        sys.exit("claude CLI not found on PATH")
    tapestry_bin = resolve_tapestry_binary()
    all_tasks = json.loads(TASKS_FILE.read_text(encoding="utf-8"))
    all_tasks.pop("_comment", None)
    wanted = args.sites.split(",") if args.sites else list(all_tasks)

    results = []
    for site in wanted:
        site = site.strip()
        if site not in all_tasks:
            print(f"-- unknown site {site} (not in agent_tasks.json)")
            continue
        print(f"\n=== {site} ===")
        result = run_site(site, all_tasks[site], tapestry_bin, args.model)
        if result:
            results.append(result)

    if results:
        print_summary(results)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = RESULTS_DIR / f"agent-report-{stamp}.json"
        path.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"\nfull report: {path}")


if __name__ == "__main__":
    main()
