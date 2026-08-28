"""The declarative probe format the harness executes.

A probe is one request described once and sent to two places: mockdr, and the
real vendor product. Describing it once is the point — a probe that phrased
the request differently for each target could not tell you anything about the
difference between them.

Requests carry `${placeholder}` references rather than literal credentials or
ids, because those necessarily differ per target: the real Splunk generates
its own HEC token at bootstrap, mockdr seeds a known one. The bootstrap step
supplies a context per target and the runner substitutes into both.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_PLACEHOLDER = re.compile(r"\$\{([a-z0-9_]+)\}")
#: ``${env:NAME}`` or ``${env:NAME:-default}``, resolved at load time from the
#: environment. This is how a spec shares one password with compose.yml
#: without either file copying the other's literal.
_ENV_REF = re.compile(r"\$\{env:([A-Z0-9_]+)(?::-([^}]*))?\}")


class SpecError(Exception):
    """A probe file is malformed. Raised with the offending probe's id."""


@dataclass(frozen=True)
class Endpoint:
    """Where a family of probes is sent, on each of the two targets.

    A platform can expose several: Splunk serves the management API and the
    event collector on different ports, while mockdr serves both behind one
    prefix. Probes name the endpoint rather than a URL so that asymmetry
    stays in the config instead of leaking into every probe.
    """

    mock: str
    real: str
    verify_tls: bool = True


@dataclass(frozen=True)
class Credential:
    """A username and password for one target."""

    user: str
    password: str

    @property
    def pair(self) -> tuple[str, str]:
        """The form httpx's ``auth=`` takes."""
        return (self.user, self.password)


@dataclass(frozen=True)
class Request:
    """One HTTP request, before placeholder substitution."""

    method: str
    path: str
    query: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    json_body: Any = None
    content: str | None = None
    auth: str = "none"


@dataclass(frozen=True)
class Probe:
    """A single comparison, and the reason it is worth making."""

    id: str
    endpoint: str
    request: Request
    #: Why this probe exists. Read by a human looking at a finding, so it
    #: should say what the request is trying to provoke, not restate the path.
    why: str = ""
    #: JSON paths whose difference is expected and must not be reported.
    #: Prefer a volatility rule in `normalize` over listing paths here — an
    #: ignore that is really "this value is a timestamp" belongs in the rules,
    #: where it applies everywhere, not in one probe.
    ignore_paths: tuple[str, ...] = ()
    #: Marks a probe that only means something once both targets hold the
    #: same data. Skipped unless the runner is given a seeded environment.
    needs_seed: bool = False
    #: Compare the response *values*, not the shape around them. It needs
    #: both targets to hold the same data — either ``needs_seed``, or a
    #: search that generates its own rows (``| makeresults``), which needs
    #: nothing from the index at all.
    compare_values: bool = False
    #: Drop this many lines from the top of a text body before comparing it.
    #: One case needs it: splunkd puts a line before a oneshot's CSV that is
    #: empty on one run and a single space on the next — its own streaming,
    #: not an answer. Everything below it is compared.
    ignore_leading_lines: int = 0


@dataclass(frozen=True)
class PlatformSpec:
    """Every probe for one vendor, plus where and how to send them."""

    platform: str
    endpoints: dict[str, Endpoint]
    probes: tuple[Probe, ...]
    #: Per target. These live in the spec rather than on the command line
    #: because they are a property of the platform: the user Elasticsearch
    #: recognises is not the one splunkd does, and a single global default
    #: silently authenticates one of them wrong. Both sides then answer 401,
    #: which compares as agreement — and real findings vanish.
    credentials: dict[str, Credential] = field(default_factory=dict)
    #: Keys whose *values* are compared, not merely their presence and type.
    #: This is where a platform's semantics live: Splunk's `code`, Kibana's
    #: `statusCode`. Everything else is compared structurally, because values
    #: legitimately differ between a seeded mock and a fresh install.
    significant_keys: frozenset[str] = frozenset()
    #: Fields whose values belong to the instance rather than to the API —
    #: bucket ids, index times, the server's own name. Dropped from every row
    #: before a ``compare: values`` probe looks at it, because comparing them
    #: would report the two installs' identities as a difference.
    volatile_fields: frozenset[str] = frozenset()
    #: Paths no probe compares at all, because they describe what happened
    #: during *this run* rather than what the API answers. A shard that was
    #: still allocating when a search reached it adds a whole
    #: ``_shards.failures`` subtree to the real reply and none to the mock,
    #: and reported eight differences that say nothing about either product.
    #: Added to every probe's own ``ignore_paths``.
    ignore_paths: tuple[str, ...] = ()

    def probe(self, probe_id: str) -> Probe:
        """Look one probe up by id, for running a single comparison."""
        for candidate in self.probes:
            if candidate.id == probe_id:
                return candidate
        raise SpecError(f"no probe with id {probe_id!r} in {self.platform}")


def substitute(value: Any, context: dict[str, str]) -> Any:
    """Replace every ``${name}`` in a nested structure from ``context``.

    A placeholder with no matching entry is left as it is rather than raising:
    a probe that deliberately sends an unresolvable token is a legitimate way
    to ask "what does this reject look like", and failing here would make that
    impossible to express.
    """
    if isinstance(value, str):
        return _PLACEHOLDER.sub(lambda m: context.get(m.group(1), m.group(0)), value)
    if isinstance(value, dict):
        return {k: substitute(v, context) for k, v in value.items()}
    if isinstance(value, list):
        return [substitute(v, context) for v in value]
    return value


def resolve_env(value: str) -> str:
    """Expand ``${env:NAME:-default}`` references from the environment."""
    def _lookup(match: re.Match[str]) -> str:
        name, default = match.group(1), match.group(2)
        found = os.environ.get(name)
        if found is not None:
            return found
        if default is not None:
            return default
        raise SpecError(f"environment variable {name} is not set and has no default")
    return _ENV_REF.sub(_lookup, value)


def _load_credentials(raw: Any, path: Path) -> dict[str, Credential]:
    out: dict[str, Credential] = {}
    for target, entry in (raw or {}).items():
        try:
            out[str(target)] = Credential(
                user=resolve_env(str(entry["user"])),
                password=resolve_env(str(entry["password"])),
            )
        except (KeyError, TypeError) as exc:
            raise SpecError(f"{path}: credentials.{target}: {exc}") from exc
    return out


#: What a probe entry and its `request` may name. An unknown key used to be
#: dropped in silence, so a probe that wrote `params:` for `query:` ran
#: against no parameters at all and reported that as agreement — the same
#: silent wrongness this harness exists to catch.
_PROBE_KEYS = frozenset({
    "id", "endpoint", "request", "why", "ignore_paths", "needs_seed",
    "compare", "ignore_leading_lines",
})
_REQUEST_KEYS = frozenset({
    "method", "path", "query", "headers", "json", "content", "auth",
})


def _no_unknown_keys(
    path: object, probe_id: str, what: str, entry: dict, allowed: frozenset,
) -> None:
    """Refuse a key the loader would otherwise drop without reading."""
    unknown = sorted(set(entry) - allowed)
    if unknown:
        raise SpecError(
            f"{path}: probe {probe_id!r}: unknown {what} key(s) "
            f"{', '.join(unknown)}; allowed: {', '.join(sorted(allowed))}",
        )


def load_spec(path: Path) -> PlatformSpec:
    """Read and validate one platform's probe file."""
    raw = yaml.safe_load(path.read_text())
    if not isinstance(raw, dict):
        raise SpecError(f"{path}: expected a mapping at the top level")

    try:
        platform = str(raw["platform"])
        endpoints = {
            name: Endpoint(
                mock=str(cfg["mock"]),
                real=str(cfg["real"]),
                verify_tls=bool(cfg.get("verify_tls", True)),
            )
            for name, cfg in raw["endpoints"].items()
        }
    except (KeyError, TypeError) as exc:
        raise SpecError(f"{path}: {exc}") from exc

    probes: list[Probe] = []
    for entry in raw.get("probes") or []:
        probe_id = str(entry.get("id", "<unnamed>"))
        try:
            spec = entry["request"]
            _no_unknown_keys(path, probe_id, "request", spec, _REQUEST_KEYS)
            request = Request(
                method=str(spec.get("method", "GET")).upper(),
                path=str(spec["path"]),
                query=dict(spec.get("query") or {}),
                headers=dict(spec.get("headers") or {}),
                json_body=spec.get("json"),
                content=spec.get("content"),
                auth=str(spec.get("auth", "none")),
            )
        except (KeyError, TypeError) as exc:
            raise SpecError(f"{path}: probe {probe_id!r}: {exc}") from exc

        _no_unknown_keys(path, probe_id, "probe", entry, _PROBE_KEYS)
        if entry.get("endpoint") not in endpoints:
            raise SpecError(
                f"{path}: probe {probe_id!r} names unknown endpoint "
                f"{entry.get('endpoint')!r}",
            )
        probes.append(Probe(
            id=probe_id,
            endpoint=str(entry["endpoint"]),
            request=request,
            why=str(entry.get("why", "")),
            ignore_paths=tuple(entry.get("ignore_paths") or ()),
            needs_seed=bool(entry.get("needs_seed", False)),
            compare_values=str(entry.get("compare", "shape")) == "values",
            ignore_leading_lines=int(entry.get("ignore_leading_lines", 0)),
        ))

    ids = [p.id for p in probes]
    duplicates = {i for i in ids if ids.count(i) > 1}
    if duplicates:
        raise SpecError(f"{path}: duplicate probe ids: {sorted(duplicates)}")

    return PlatformSpec(
        platform=platform,
        endpoints=endpoints,
        probes=tuple(probes),
        significant_keys=frozenset(raw.get("significant_keys") or ()),
        volatile_fields=frozenset(raw.get("volatile_fields") or ()),
        ignore_paths=tuple(raw.get("ignore_paths") or ()),
        credentials=_load_credentials(raw.get("credentials"), path),
    )
