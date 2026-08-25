"""Send every probe to both targets and report where they disagree.

Usage:
    python -m harness.runner probes/splunk.yaml
    python -m harness.runner probes/*.yaml --json findings.json

Credentials come from each probe file, because they are a property of the
platform: the user Elasticsearch recognises is not the one splunkd does. A
single command-line default would authenticate one platform wrong, both
sides would answer 401, and that would compare as agreement.

Exit status is 1 when any finding is reported, so this can gate a pipeline
once a platform is clean, and 2 when a target could not be reached — a
distinction that matters, because "no findings" and "never ran" look
identical in a report that does not separate them.
"""
from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from harness.bootstrap import BOOTSTRAPS, BootstrapError
from harness.clients import Clients
from harness.diff import Finding, Response, compare, compare_values
from harness.normalize import strip_prefix
from harness.spec import PlatformSpec, Probe, SpecError, load_spec, substitute

_TARGETS = ("mock", "real")


class TargetUnreachableError(Exception):
    """A target did not answer, so its probes were not run."""


def _auth_for(probe: Probe, target: str, spec: PlatformSpec) -> tuple[str, str] | None:
    """Resolve the probe's declared auth scheme for one target.

    HEC probes carry their token in a header or query parameter the probe
    itself spells out, so that one can describe sending a *wrong* token;
    they leave ``auth`` at its default of ``none`` and nothing is added here.
    """
    if probe.request.auth == "none":
        return None
    credential = spec.credentials.get(target)
    return credential.pair if credential else None


def _send(
    clients: Clients, probe: Probe, target: str, context: dict[str, str],
    spec: PlatformSpec,
) -> Response:
    """Perform one probe against one target."""
    request = probe.request
    client = clients.get(probe.endpoint, target)
    url = substitute(request.path, context)

    try:
        response = client.request(
            request.method,
            url,
            params=substitute(request.query, context) or None,
            headers=substitute(request.headers, context) or None,
            json=substitute(request.json_body, context)
            if request.json_body is not None else None,
            content=substitute(request.content, context)
            if request.content is not None else None,
            auth=_auth_for(probe, target, spec),
        )
    except httpx.HTTPError as exc:
        raise TargetUnreachableError(f"{target} {client.base_url}{url}: {exc}") from exc

    headers = {k.lower(): v for k, v in response.headers.items()}
    # Only the media type matters in content-type; the charset is noise. No
    # other header is cut: a WWW-Authenticate challenge's parameters are
    # exactly what a client reads.
    if "content-type" in headers:
        headers["content-type"] = headers["content-type"].split(";")[0].strip()

    try:
        body = response.json()
        # mockdr serves each vendor under a mount prefix and echoes it back in
        # error messages; the real product has no prefix to echo.
        if target == "mock":
            body = strip_prefix(body, urlsplit(str(client.base_url)).path.rstrip("/"))
        body_error = ""
    except ValueError:
        body = None
        # Recorded rather than raised: a target answering XML where the other
        # answers JSON is itself a finding, and the most interesting one.
        body_error = f"non-json ({headers.get('content-type', 'unknown')})"

    return Response(response.status_code, headers, body, body_error, response.text)


def _needs_context(probe: Probe) -> bool:
    """Whether the probe references a placeholder the bootstrap must supply."""
    request = probe.request
    return "${" in " ".join([
        request.path, str(request.query), str(request.headers),
        str(request.json_body), str(request.content),
    ])


def run_platform(
    spec: PlatformSpec,
    seeded: bool = False,
) -> tuple[list[Finding], list[str], int]:
    """Run every applicable probe.

    Returns the findings, human-readable notes, and how many probes could
    not be run. That last number is not cosmetic: it is what stops a run
    where nothing answered from exiting 0 and reading as a clean bill.
    """
    findings: list[Finding] = []
    notes: list[str] = []
    not_run = 0

    with Clients(spec.endpoints) as clients:
        contexts: dict[str, dict[str, str]] = {}
        failed_bootstrap: set[str] = set()
        bootstrap = BOOTSTRAPS.get(spec.platform)
        for target in _TARGETS:
            if bootstrap is None:
                contexts[target] = {}
                continue
            try:
                contexts[target] = bootstrap(spec, target, clients, seeded=seeded)
            except (BootstrapError, httpx.HTTPError) as exc:
                # Structural probes still work with no context, and they are
                # most of the yield. Probes that need a placeholder cannot
                # run, and are counted as such rather than sent with the
                # literal "${hec_token}" and compared as if they had.
                contexts[target] = {}
                failed_bootstrap.add(target)
                notes.append(f"bootstrap {target} failed: {exc}")

        # An endpoint that refused once will refuse again, so remember it
        # rather than making every remaining probe wait out the same timeout.
        unreachable: dict[str, str] = {}

        with ThreadPoolExecutor(max_workers=len(_TARGETS)) as pool:
            for probe in spec.probes:
                if probe.needs_seed and not seeded:
                    notes.append(f"skipped {probe.id}: needs both targets seeded alike")
                    continue
                if failed_bootstrap and _needs_context(probe):
                    notes.append(f"not run {probe.id}: bootstrap failed, placeholder unresolved")
                    not_run += 1
                    continue
                if probe.endpoint in unreachable:
                    notes.append(f"not run {probe.id}: {unreachable[probe.endpoint]}")
                    not_run += 1
                    continue

                # mock and real are independent hosts; the round trips
                # overlap rather than stack.
                futures = {
                    target: pool.submit(
                        _send, clients, probe, target, contexts[target], spec,
                    )
                    for target in _TARGETS
                }
                try:
                    responses = {target: f.result() for target, f in futures.items()}
                except TargetUnreachableError as exc:
                    # One dead endpoint must not cost the findings from the
                    # others: Splunk's management API is worth probing when
                    # its collector is down, and the reverse.
                    unreachable[probe.endpoint] = str(exc)
                    notes.append(f"not run {probe.id}: {exc}")
                    not_run += 1
                    continue

                if probe.compare_values:
                    findings.extend(compare_values(
                        probe.id, responses["mock"], responses["real"],
                        spec.volatile_fields, probe.why,
                        probe.ignore_leading_lines,
                    ))
                else:
                    findings.extend(compare(
                        probe.id, responses["mock"], responses["real"],
                        spec.significant_keys,
                        (*spec.ignore_paths, *probe.ignore_paths), probe.why,
                    ))

    if not_run:
        notes.append(
            f"WARNING: {not_run} probe(s) not run; "
            f"any 'no differences' below means 'nothing ran'",
        )
    return findings, notes, not_run


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns the process exit status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("specs", nargs="+", type=Path, help="probe files to run")
    parser.add_argument(
        "--seeded", action="store_true",
        help="both targets hold the same data, so data probes are meaningful",
    )
    parser.add_argument("--json", type=Path, help="also write findings as JSON")
    args = parser.parse_args(argv)

    all_findings: list[Finding] = []
    anything_not_run = False

    for path in args.specs:
        try:
            spec = load_spec(path)
        except SpecError as exc:
            print(f"!! {exc}", file=sys.stderr)
            return 2

        print(f"── {spec.platform} ({len(spec.probes)} probes) ──")
        findings, notes, not_run = run_platform(spec, seeded=args.seeded)
        anything_not_run = anything_not_run or not_run > 0

        for note in notes:
            print(f"   .. {note}")
        if not findings:
            print("   no differences")
        for finding in findings:
            print(f"   {finding.describe()}")
            if finding.why:
                print(f"        why: {finding.why}")
        all_findings.extend(findings)

    if args.json:
        args.json.write_text(json.dumps([asdict(f) for f in all_findings], indent=2))

    print(f"\n{len(all_findings)} finding(s)")
    if anything_not_run:
        return 2
    return 1 if all_findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
