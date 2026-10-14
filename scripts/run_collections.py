# ruff: noqa: ANN001, ANN201, ANN202, D103, S603, S607, T201
# A release tool, not library code: every function is local to this file.
"""Run the Postman and Bruno collections end to end against a live mock.

Both collections are something a user imports and presses "Run" on, and
neither had been run that way: the Postman one built every URL from a host
that carried the path (`/agents/` with a trailing slash, a 404), nothing in
either captured a token, the Bruno one kept its query parameters in a block
the CLI does not send, and both carried requests the mock answers 4xx to
since 2.6.0. One request in each collection could lock the run out — an
import of a partial snapshot, or a generated API token — and none could
recover, because `/_dev/reset` needs the token that was gone.

Each collection now fetches its own tokens and hands the ids it lists or
creates to the requests after it, so it runs from nothing but a base URL.
This runs both with their official CLIs, fetched by `npx` (network needed
the first time; nothing is installed globally), with every base-URL
variable pointed at `--base-url`, and fails on any answer of 400 or above
other than the ones listed in `EXPECTED`.

    backend/.venv/bin/python scripts/run_collections.py --base-url http://127.0.0.1:8104

Start the mock first (from `backend/`:
`.venv/bin/python -m uvicorn main:app --port 8104`). The mock is reset before
each collection and after. Exit status 1 when anything else fails.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
ADMIN = {"Authorization": "ApiToken admin-token-0000-0000-000000000001"}

#: Answers that are right. Nothing in the seed is a fired alert and nothing
#: in mockdr fires one, so the delete can only meet a name that is not there.
EXPECTED = {
    ("DELETE", "/splunk/services/alerts/fired_alerts/replace-with-alert-name"): 404,
}


def bases(base: str) -> dict[str, str]:
    return {
        "base_url": f"{base}/web/api/v2.1", "s1_base_url": f"{base}/web/api/v2.1",
        "cs_base_url": f"{base}/cs", "mde_base_url": f"{base}/mde",
        "elastic_base_url": f"{base}/elastic", "kibana_base_url": f"{base}/kibana",
        "xdr_base_url": f"{base}/xdr/public_api/v1", "splunk_base_url": f"{base}/splunk",
        "sentinel_base_url": f"{base}/sentinel", "graph_base_url": f"{base}/graph",
    }


def reset(base: str) -> None:
    r = httpx.post(f"{base}/web/api/v2.1/_dev/reset", headers=ADMIN, timeout=30)
    if r.status_code != 200:
        sys.exit(f"cannot reset the mock at {base}: {r.status_code} — is it running?")


def judge(base: str, rows: list[tuple[str, str, int | None, str]]) -> list[str]:
    bad = []
    for method, url, status, name in rows:
        path = url.removeprefix(base).split("?", 1)[0]
        if status is not None and status < 400:
            continue
        if EXPECTED.get((method, path)) == status:
            continue
        bad.append(f"{status} {method} {path}  [{name}]")
    return bad


def run_postman(base: str, tmp: Path) -> tuple[int, list[str]]:
    env = {"name": "doc-run", "values": [{"key": k, "value": v, "enabled": True}
                                         for k, v in bases(base).items()]}
    (tmp / "env.json").write_text(json.dumps(env))
    report = tmp / "newman.json"
    subprocess.run(["npx", "-y", "newman@6", "run",
                    str(ROOT / "postman" / "mockdr.postman_collection.json"),
                    "-e", str(tmp / "env.json"), "--reporters", "json",
                    "--reporter-json-export", str(report)],
                   capture_output=True, check=False)
    rows = []
    for e in json.loads(report.read_text())["run"]["executions"]:
        url = e["request"]["url"]
        full = "{}://{}:{}/{}".format(url.get("protocol"), ".".join(url["host"]),
                                      url.get("port"), "/".join(url.get("path", [])))
        rows.append((e["request"]["method"], full,
                     (e.get("response") or {}).get("code"), e["item"]["name"]))
    return len(rows), judge(base, rows)


def run_bruno(base: str, tmp: Path) -> tuple[int, list[str]]:
    report = tmp / "bru.json"
    args = ["npx", "-y", "@usebruno/cli@2", "run", "-r", "--env", "local",
            "--reporter-json", str(report)]
    for k, v in bases(base).items():
        args += ["--env-var", f"{k}={v}"]
    subprocess.run(args, cwd=ROOT / "bruno" / "mockdr", capture_output=True, check=False)
    rows = [(r["request"]["method"], r["request"]["url"],
             (r.get("response") or {}).get("status"), r["test"]["filename"])
            for r in json.loads(report.read_text())[0]["results"]]
    return len(rows), judge(base, rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--base-url", required=True, help="the running mock")
    parser.add_argument("--only", choices=["postman", "bruno"])
    args = parser.parse_args()
    base = args.base_url.rstrip("/")
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        for name, runner in (("postman", run_postman), ("bruno", run_bruno)):
            if args.only and args.only != name:
                continue
            reset(base)
            total, bad = runner(base, Path(tmp))
            print(f"{name}: {total} requests, {len(bad)} failing")
            for line in bad:
                print(f"  {line}")
            failures += len(bad)
            reset(base)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
