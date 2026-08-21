"""Send every probe to both targets and report where they disagree.

Usage:
    python -m harness.runner probes/splunk.yaml --real-auth admin:password
    python -m harness.runner probes/*.yaml --json findings.json

Exit status is 1 when any finding is reported, so this can gate a pipeline
once a platform is clean, and 2 when a target could not be reached — a
distinction that matters, because "no findings" and "never ran" look
identical in a report that does not separate them.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from harness.bootstrap import BOOTSTRAPS, BootstrapError
from harness.diff import Finding, Response, compare
from harness.normalize import strip_prefix
from harness.spec import Endpoint, PlatformSpec, Probe, SpecError, load_spec, substitute

_TARGETS = ("mock", "real")


class TargetUnreachableError(Exception):
    """A target did not answer, so its probes were not run."""


def _auth_for(probe: Probe, target: str, credentials: dict[str, tuple[str, str]]) -> Any:
    """Resolve the probe's declared auth scheme for one target.

    ``hec`` deliberately resolves to nothing: the HEC token travels in a
    header or query parameter the probe itself carries, so that a probe can
    describe sending a *wrong* one. Handling it here would make the negative
    cases inexpressible.
    """
    if probe.request.auth in ("none", "hec"):
        return None
    return credentials.get(target)


def _send(
    endpoint: Endpoint, probe: Probe, target: str, context: dict[str, str],
    credentials: dict[str, tuple[str, str]],
) -> Response:
    """Perform one probe against one target."""
    request = probe.request
    base = endpoint.mock if target == "mock" else endpoint.real
    url = substitute(request.path, context)

    try:
        with httpx.Client(
            base_url=base, verify=endpoint.verify_tls, timeout=30.0,
            follow_redirects=False,
        ) as client:
            response = client.request(
                request.method,
                url,
                params=substitute(request.query, context) or None,
                headers=substitute(request.headers, context) or None,
                json=substitute(request.json_body, context)
                if request.json_body is not None else None,
                content=substitute(request.content, context)
                if request.content is not None else None,
                auth=_auth_for(probe, target, credentials),
            )
    except httpx.HTTPError as exc:
        raise TargetUnreachableError(f"{target} {base}{url}: {exc}") from exc

    headers = {k.lower(): v.split(";")[0].strip() for k, v in response.headers.items()}
    try:
        body = response.json()
        # mockdr serves each vendor under a mount prefix and echoes it back in
        # error messages; the real product has no prefix to echo.
        if target == "mock":
            body = strip_prefix(body, urlsplit(base).path.rstrip("/"))
        body_error = ""
    except ValueError:
        body = None
        # Recorded rather than raised: a target answering XML where the other
        # answers JSON is itself a finding, and the most interesting one.
        body_error = f"non-json ({headers.get('content-type', 'unknown')})"

    return Response(response.status_code, headers, body, body_error)


def run_platform(
    spec: PlatformSpec,
    credentials: dict[str, tuple[str, str]],
    seeded: bool = False,
) -> tuple[list[Finding], list[str], int]:
    """Run every applicable probe.

    Returns the findings, human-readable notes, and how many endpoints could
    not be reached. That last number is not cosmetic: it is what stops a run
    where nothing answered from exiting 0 and reading as a clean bill.
    """
    findings: list[Finding] = []
    notes: list[str] = []

    contexts: dict[str, dict[str, str]] = {}
    bootstrap = BOOTSTRAPS.get(spec.platform)
    for target in _TARGETS:
        if bootstrap is None:
            contexts[target] = {}
            continue
        try:
            contexts[target] = bootstrap(spec, target, credentials[target])
        except (BootstrapError, httpx.HTTPError) as exc:
            # Probes that need no placeholder still work without a context,
            # and those are the structural ones worth most of the yield.
            contexts[target] = {}
            notes.append(f"bootstrap {target} failed, placeholders unresolved: {exc}")

    # An endpoint that refused once will refuse again, so remember it rather
    # than making every remaining probe wait out the same timeout.
    unreachable: dict[str, str] = {}

    for probe in spec.probes:
        if probe.needs_seed and not seeded:
            notes.append(f"skipped {probe.id}: needs both targets seeded alike")
            continue
        if probe.endpoint in unreachable:
            notes.append(f"skipped {probe.id}: {unreachable[probe.endpoint]}")
            continue

        endpoint = spec.endpoints[probe.endpoint]
        try:
            responses = {
                target: _send(endpoint, probe, target, contexts[target], credentials)
                for target in _TARGETS
            }
        except TargetUnreachableError as exc:
            # One dead endpoint must not cost the findings from the others:
            # Splunk's management API is worth probing when its collector is
            # down, and the reverse.
            unreachable[probe.endpoint] = str(exc)
            notes.append(f"skipped {probe.id}: {exc}")
            continue

        findings.extend(compare(
            probe.id, responses["mock"], responses["real"],
            spec.significant_keys, probe.ignore_paths, probe.why,
        ))

    if unreachable:
        notes.append(
            f"WARNING: {len(unreachable)} endpoint(s) unreachable; "
            f"any 'no differences' below means 'nothing ran'",
        )
    return findings, notes, len(unreachable)


def _parse_credential(value: str) -> tuple[str, str]:
    user, _, password = value.partition(":")
    return user, password


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns the process exit status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("specs", nargs="+", type=Path, help="probe files to run")
    parser.add_argument("--mock-auth", default="admin:mockdr-admin")
    parser.add_argument("--real-auth", default="admin:Probe-Passw0rd!")
    parser.add_argument(
        "--seeded", action="store_true",
        help="both targets hold the same data, so data probes are meaningful",
    )
    parser.add_argument("--json", type=Path, help="also write findings as JSON")
    args = parser.parse_args(argv)

    credentials = {
        "mock": _parse_credential(args.mock_auth),
        "real": _parse_credential(args.real_auth),
    }

    all_findings: list[Finding] = []
    unreachable = False

    for path in args.specs:
        try:
            spec = load_spec(path)
        except SpecError as exc:
            print(f"!! {exc}", file=sys.stderr)
            return 2

        print(f"── {spec.platform} ({len(spec.probes)} probes) ──")
        findings, notes, unreachable_count = run_platform(
            spec, credentials, seeded=args.seeded,
        )
        unreachable = unreachable or unreachable_count > 0

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
    if unreachable:
        return 2
    return 1 if all_findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
