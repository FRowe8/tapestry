#!/usr/bin/env python3
"""One-command self-hosted benchmark runner (readiness plan Phase 4).

For each requested app this script: waits for the app, seeds it with demo
data over its HTTP API, serves a small "driver" page whose JavaScript
exercises the app's real API from a browser, records that traffic headlessly
with `tapestry record`, generates tools, approves what needs approving, and
then measures the four BENCHMARKS.md metrics:

  - endpoint callability   (live 2xx + >=80% schema field compatibility)
  - task completion rate   (tapestry validate --live per defined task)
  - time to first working tool (record start -> first callable tool)
  - manual correction rate (tools whose own example input fails with an
                            argument/schema error — a human would have to
                            fix the tool or its arguments before use)

Usage:
    python benchmarks/run.py                    # nocodb + ghost (needs Docker)
    python benchmarks/run.py --apps localapp    # no-Docker harness smoke test
    python benchmarks/run.py --apps nocodb

The Docker apps come from benchmarks/docker-compose.yml (pinned versions,
bound to 127.0.0.1). The script starts them itself when Docker is available.
Results land in benchmarks/results/ (gitignored). Real captures are secrets;
these instances are throwaway with well-known seeded credentials, which is
the only reason their captures may be treated casually.
"""

import argparse
import http.cookiejar
import http.server
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BENCH_DIR = REPO_ROOT / "benchmarks"
RESULTS_DIR = BENCH_DIR / "results"
COMPOSE_FILE = BENCH_DIR / "docker-compose.yml"

RECORD_TIMEOUT_SECS = 25
CALLABILITY_CONFORMANCE = 0.8
ARGUMENT_ERRORS = {"missing_required_argument", "invalid_argument_type", "unknown_argument"}


# ---------------------------------------------------------------------------
# tapestry invocation


def tapestry_command():
    env_bin = os.environ.get("TAPESTRY_BIN")
    if env_bin:
        return [env_bin]
    on_path = shutil.which("tapestry")
    if on_path:
        return [on_path]
    return ["cargo", "run", "-q", "-p", "tapestry-cli", "--"]


TAPESTRY = tapestry_command()


def run_tapestry(args, timeout=300):
    """Run a tapestry command from the repo root; returns (exit_code, stdout)."""
    proc = subprocess.run(
        TAPESTRY + args,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return proc.returncode, proc.stdout


def run_tapestry_json(args, timeout=300):
    code, out = run_tapestry(args, timeout=timeout)
    try:
        return code, json.loads(out)
    except json.JSONDecodeError:
        return code, None


# ---------------------------------------------------------------------------
# HTTP helpers (stdlib only)


def request_json(method, url, body=None, headers=None, opener=None, timeout=15):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    for name, value in (headers or {}).items():
        req.add_header(name, value)
    open_fn = opener.open if opener else urllib.request.urlopen
    with open_fn(req, timeout=timeout) as response:
        raw = response.read()
    return json.loads(raw) if raw.strip() else {}


def wait_for_http(url, timeout_secs, expect_json=False):
    deadline = time.time() + timeout_secs
    last_error = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                if response.status < 500:
                    if not expect_json:
                        return
                    return
        except Exception as error:  # noqa: BLE001 - retry loop
            last_error = error
        time.sleep(1.5)
    raise RuntimeError(f"{url} not reachable after {timeout_secs}s: {last_error}")


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class DriverServer:
    """Serves one HTML page that exercises an app's API from the browser."""

    def __init__(self, html):
        self.port = free_port()
        page = html.encode()

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - stdlib API
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(page)

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return f"http://127.0.0.1:{self.port}/"

    def __exit__(self, *exc):
        self.server.shutdown()


# ---------------------------------------------------------------------------
# App definitions


class LocalApp:
    """No-Docker smoke app: proves the harness end to end using the same
    deterministic server as the capture-parity pair."""

    name = "localapp"
    site = "bench-localapp"
    requires_docker = False
    tasks = ["List the most recent 5 items"]

    def __init__(self):
        self.base_url = "http://127.0.0.1:8971"
        self.process = None

    def start(self):
        self.process = subprocess.Popen(
            [sys.executable, str(REPO_ROOT / "scripts" / "localapp_server.py")],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        wait_for_http(f"{self.base_url}/api/config", 20)

    def stop(self):
        if self.process:
            self.process.terminate()

    def seed(self):
        return {}

    def driver_html(self, state):
        return None  # the app's own page fires every API call on load

    def record_url(self, state):
        return f"{self.base_url}/"

    def credentials(self, state):
        return {}


class NocoDb:
    name = "nocodb"
    site = "bench-nocodb"
    requires_docker = True
    tasks = [
        "List the records in the Items table",
        "Create a new record in the Items table",
    ]

    def __init__(self):
        self.base_url = "http://127.0.0.1:8980"

    def start(self):
        wait_for_http(f"{self.base_url}/dashboard", 180)

    def stop(self):
        pass  # compose lifecycle is managed by main()

    def seed(self):
        auth = {"email": "bench@example.com", "password": "Benchmark-passw0rd1!"}
        try:
            signup = request_json("POST", f"{self.base_url}/api/v1/auth/user/signup", auth)
        except urllib.error.HTTPError:
            signup = request_json("POST", f"{self.base_url}/api/v1/auth/user/signin", auth)
        token = signup["token"]
        headers = {"xc-auth": token}

        base = request_json(
            "POST", f"{self.base_url}/api/v2/meta/bases", {"title": "BenchBase"}, headers
        )
        table = request_json(
            "POST",
            f"{self.base_url}/api/v2/meta/bases/{base['id']}/tables",
            {
                "table_name": "Items",
                "title": "Items",
                "columns": [
                    {"column_name": "Title", "title": "Title", "uidt": "SingleLineText"},
                    {"column_name": "Status", "title": "Status", "uidt": "SingleLineText"},
                    {"column_name": "Price", "title": "Price", "uidt": "Number"},
                ],
            },
            headers,
        )
        rows = [
            {"Title": "Alpha", "Status": "published", "Price": 10},
            {"Title": "Beta", "Status": "draft", "Price": 12},
            {"Title": "Gamma", "Status": "published", "Price": 8},
            {"Title": "Delta", "Status": "review", "Price": 21},
            {"Title": "Epsilon", "Status": "published", "Price": 5},
        ]
        request_json(
            "POST", f"{self.base_url}/api/v2/tables/{table['id']}/records", rows, headers
        )
        return {"token": token, "base_id": base["id"], "table_id": table["id"]}

    def driver_html(self, state):
        return f"""<!doctype html>
<html><head><title>nocodb bench driver</title><script>
const base = {json.dumps(self.base_url)};
const headers = {{ "xc-auth": {json.dumps(state["token"])} }};
const tid = {json.dumps(state["table_id"])};
async function drive() {{
  await fetch(`${{base}}/api/v2/meta/bases`, {{ headers }});
  await fetch(`${{base}}/api/v2/meta/bases/{state["base_id"]}/tables`, {{ headers }});
  await fetch(`${{base}}/api/v2/tables/${{tid}}/records?limit=25&offset=0`, {{ headers }});
  await fetch(`${{base}}/api/v2/tables/${{tid}}/records?limit=25&offset=0&where=(Status,eq,published)`, {{ headers }});
  await fetch(`${{base}}/api/v2/tables/${{tid}}/records/1`, {{ headers }});
  await fetch(`${{base}}/api/v2/tables/${{tid}}/records/count`, {{ headers }});
  await fetch(`${{base}}/api/v2/tables/${{tid}}/records`, {{
    method: "POST",
    headers: {{ ...headers, "content-type": "application/json" }},
    body: JSON.stringify({{ "Title": "FromBrowser", "Status": "draft", "Price": 1 }})
  }});
}}
drive();
</script></head><body>nocodb bench driver</body></html>"""

    def record_url(self, state):
        return None  # use the driver page

    def credentials(self, state):
        return {"xc-auth": state["token"]}


class Ghost:
    """Best-effort: Ghost's Content API authenticates with a query-string key,
    which Tapestry's redaction strips and its credential store cannot inject
    (headers only). Expect capture and task replay to work but live
    callability to fail on the keyed endpoints — a real product gap this
    suite exists to surface. See benchmarks/README.md."""

    name = "ghost"
    site = "bench-ghost"
    requires_docker = True
    tasks = ["List the most recent posts"]

    def __init__(self):
        self.base_url = "http://127.0.0.1:8981"

    def start(self):
        wait_for_http(f"{self.base_url}/", 180)

    def stop(self):
        pass

    def seed(self):
        owner = {
            "name": "Bench Owner",
            "email": "bench@example.com",
            "password": "Benchmark-passw0rd1!",
            "blogTitle": "Tapestry Bench",
        }
        try:
            request_json(
                "POST",
                f"{self.base_url}/ghost/api/admin/authentication/setup/",
                {"setup": [owner]},
            )
        except urllib.error.HTTPError:
            pass  # already set up from a previous run

        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        request_json(
            "POST",
            f"{self.base_url}/ghost/api/admin/session/",
            {"username": owner["email"], "password": owner["password"]},
            headers={"Origin": self.base_url},
            opener=opener,
        )
        integration = request_json(
            "POST",
            f"{self.base_url}/ghost/api/admin/integrations/?include=api_keys",
            {"integrations": [{"name": f"tapestry-bench-{int(time.time())}"}]},
            headers={"Origin": self.base_url},
            opener=opener,
        )
        keys = integration["integrations"][0]["api_keys"]
        content_key = next(k["secret"] for k in keys if k["type"] == "content")
        return {"content_key": content_key}

    def driver_html(self, state):
        return f"""<!doctype html>
<html><head><title>ghost bench driver</title><script>
const base = {json.dumps(self.base_url)};
const key = {json.dumps(state["content_key"])};
async function drive() {{
  await fetch(`${{base}}/members/api/site`);
  const posts = await (await fetch(`${{base}}/ghost/api/content/posts/?key=${{key}}&limit=5&include=tags,authors`)).json();
  await fetch(`${{base}}/ghost/api/content/settings/?key=${{key}}`);
  await fetch(`${{base}}/ghost/api/content/tags/?key=${{key}}&limit=10`);
  if (posts.posts && posts.posts.length) {{
    await fetch(`${{base}}/ghost/api/content/posts/${{posts.posts[0].id}}/?key=${{key}}`);
  }}
}}
drive();
</script></head><body>ghost bench driver</body></html>"""

    def record_url(self, state):
        return None

    def credentials(self, state):
        return {}


APPS = {app.name: app for app in (LocalApp(), NocoDb(), Ghost())}


# ---------------------------------------------------------------------------
# Pipeline


def site_dir(site):
    return REPO_ROOT / ".tapestry-dev" / "sites" / site


def load_toolspec(site):
    return json.loads((site_dir(site) / "toolspec.json").read_text(encoding="utf-8"))


def record_and_generate(app, state):
    record_url = app.record_url(state)
    started = time.time()
    if record_url is not None:
        capture(app.site, record_url)
    else:
        with DriverServer(app.driver_html(state)) as driver_url:
            capture(app.site, driver_url)
    code, out = run_tapestry(["generate", app.site])
    if code != 0:
        raise RuntimeError(f"generate failed for {app.site}:\n{out}")
    return started


def capture(site, url):
    code, out = run_tapestry(
        [
            "record",
            url,
            "--site",
            site,
            "--headless",
            "--timeout-secs",
            str(RECORD_TIMEOUT_SECS),
            "--replace",
            "--allow-low-signal",
            "--ephemeral-profile",
        ],
        timeout=RECORD_TIMEOUT_SECS + 120,
    )
    if code != 0:
        raise RuntimeError(f"record failed for {site}:\n{out}")


def store_credentials(app, state):
    for header, value in app.credentials(state).items():
        code, out = run_tapestry(["credentials", app.site, "set", header, value])
        if code != 0:
            raise RuntimeError(f"credentials set failed for {app.site}:\n{out}")


def approve_all_pending(site, spec):
    for tool in spec["tools"]:
        if not tool.get("approved", False):
            run_tapestry(["approve", site, tool["id"]])


def build_args(tool):
    """Arguments a non-LLM client can derive from the tool itself: the
    example input when present, else path-param examples and schema
    defaults. Anything a human would still have to supply counts against
    the manual-correction metric."""
    if tool.get("example_input"):
        return tool["example_input"]
    args = {}
    for param in tool.get("path_params", []):
        examples = param.get("examples") or []
        if examples:
            args[param["name"]] = examples[0]
    properties = tool.get("input_schema", {}).get("properties", {})
    for name, prop in properties.items():
        if name not in args and isinstance(prop, dict) and "default" in prop:
            args[name] = prop["default"]
    return args


def measure_callability(site, spec, record_started):
    """Live-call every tool with derivable arguments; returns per-tool rows
    plus the timestamp of the first success (for time-to-first-tool)."""
    rows = []
    first_success_at = None
    for tool in spec["tools"]:
        args = build_args(tool)
        code, response = run_tapestry_json(
            ["run", site, tool["id"], "--live", "--args", json.dumps(args)]
        )
        row = {
            "tool_id": tool["id"],
            "name": tool["name"],
            "safety": tool["safety"]["classification"],
            "callable": False,
            "needs_correction": False,
            "error_type": None,
        }
        if response is None:
            row["error_type"] = f"unparseable_output_exit_{code}"
            row["needs_correction"] = True
        elif response.get("status") == "success":
            conformance = response.get("conformance", {}).get("field_compatibility", 1.0)
            row["callable"] = conformance >= CALLABILITY_CONFORMANCE
            row["needs_correction"] = not row["callable"]
            if row["callable"] and first_success_at is None:
                first_success_at = time.time() - record_started
        else:
            row["error_type"] = response.get("error_type")
            # Argument/schema failures mean a human must fix the tool or its
            # example before it works; auth/network/server failures are
            # environment problems, not generation defects.
            row["needs_correction"] = row["error_type"] in ARGUMENT_ERRORS | {"schema_mismatch"}
        rows.append(row)
    return rows, first_success_at


def measure_tasks(site, tasks):
    rows = []
    for task in tasks:
        code, report = run_tapestry_json(
            ["validate", site, "--task", task, "--format", "json", "--live"]
        )
        agent = (report or {}).get("agent_task", {})
        rows.append(
            {
                "task": task,
                "success": bool(agent.get("success")),
                "tool_used": agent.get("top_tool_used"),
                "failure_type": agent.get("failure_type"),
            }
        )
    return rows


def run_app(app):
    print(f"\n=== {app.name} ({app.site}) ===")
    app.start()
    state = app.seed()
    print(f"seeded {app.name}")
    record_started = record_and_generate(app, state)
    store_credentials(app, state)
    spec = load_toolspec(app.site)
    approve_all_pending(app.site, spec)
    print(f"generated {len(spec['tools'])} tools")

    call_rows, first_success = measure_callability(app.site, spec, record_started)
    task_rows = measure_tasks(app.site, app.tasks)
    app.stop()

    total = len(call_rows)
    callable_count = sum(1 for r in call_rows if r["callable"])
    corrections = sum(1 for r in call_rows if r["needs_correction"])
    tasks_ok = sum(1 for r in task_rows if r["success"])
    return {
        "app": app.name,
        "site": app.site,
        "tools_generated": total,
        "callability": callable_count / total if total else 0.0,
        "task_completion": tasks_ok / len(task_rows) if task_rows else 0.0,
        "time_to_first_tool_secs": round(first_success, 1) if first_success else None,
        "manual_correction_rate": corrections / total if total else 0.0,
        "tools": call_rows,
        "tasks": task_rows,
    }


# ---------------------------------------------------------------------------
# Reporting


TARGETS = {
    "callability": 0.70,
    "task_completion": 0.60,
    "manual_correction_rate": 0.30,  # upper bound
    "time_to_first_tool_secs": 600,  # upper bound (automated target: 10 min)
}


def print_report(results):
    print("\n================ BENCHMARK REPORT ================")
    header = f"{'app':<10} {'tools':>5} {'callable':>9} {'tasks':>6} {'ttft(s)':>8} {'correct%':>9}"
    print(header)
    print("-" * len(header))
    for result in results:
        ttft = result["time_to_first_tool_secs"]
        print(
            f"{result['app']:<10} {result['tools_generated']:>5} "
            f"{result['callability']:>8.0%} {result['task_completion']:>6.0%} "
            f"{ttft if ttft is not None else '-':>8} "
            f"{result['manual_correction_rate']:>8.0%}"
        )
    print("\nTargets: callability >=70%, task completion >=60%, "
          "correction rate <30%, time-to-first-tool <10min")
    for result in results:
        misses = []
        if result["callability"] < TARGETS["callability"]:
            misses.append("callability")
        if result["task_completion"] < TARGETS["task_completion"]:
            misses.append("task_completion")
        if result["manual_correction_rate"] > TARGETS["manual_correction_rate"]:
            misses.append("manual_correction_rate")
        ttft = result["time_to_first_tool_secs"]
        if ttft is None or ttft > TARGETS["time_to_first_tool_secs"]:
            misses.append("time_to_first_tool")
        status = "PASS" if not misses else f"MISS ({', '.join(misses)})"
        print(f"  {result['app']}: {status}")


def write_report(results):
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = RESULTS_DIR / f"report-{stamp}.json"
    path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nfull report: {path}")


# ---------------------------------------------------------------------------


def docker_compose(*args):
    return subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), *args],
        cwd=BENCH_DIR,
        check=True,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apps",
        default="nocodb,ghost",
        help="Comma-separated apps to benchmark: localapp, nocodb, ghost",
    )
    parser.add_argument(
        "--keep-compose",
        action="store_true",
        help="Leave the compose apps running after the benchmark",
    )
    args = parser.parse_args()

    apps = [APPS[name.strip()] for name in args.apps.split(",") if name.strip()]
    needs_docker = any(app.requires_docker for app in apps)
    if needs_docker:
        if shutil.which("docker") is None:
            sys.exit(
                "docker not found. Install Docker, or run the no-Docker smoke "
                "test with: python benchmarks/run.py --apps localapp"
            )
        docker_compose("up", "-d")

    results = []
    try:
        for app in apps:
            try:
                results.append(run_app(app))
            except Exception as error:  # noqa: BLE001 - report and continue
                print(f"!! {app.name} failed: {error}")
                results.append({"app": app.name, "site": app.site, "error": str(error)})
    finally:
        if needs_docker and not args.keep_compose:
            docker_compose("down")

    completed = [r for r in results if "error" not in r]
    if completed:
        print_report(completed)
    write_report(results)
    if len(completed) < len(results):
        sys.exit(1)


if __name__ == "__main__":
    main()
