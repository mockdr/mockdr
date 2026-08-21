"""Turning two responses into findings.

A finding is a way in which mockdr and the real product disagree. The kinds
are ordered by how badly each one misleads a client:

`status` and `code` come first because they are what a client branches on. A
client asks "did this work" and gets a different answer from the two servers —
that is the whole failure mode mockdr exists to expose, and the HEC
query-string defect this harness was built after was exactly this shape.

`missing_key` outranks `extra_key` for the same reason: a field the real
product returns and mockdr does not is a field a client may read and find
absent in production. The reverse is generous rather than dangerous — though
still worth reporting, because a client written against mockdr may come to
depend on something that will not be there.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from harness.normalize import SIGNIFICANT_HEADERS, mask, skeleton

#: Severity order, worst first. Also the report's sort order.
KIND_ORDER: tuple[str, ...] = (
    "status", "value", "missing_key", "type", "extra_key", "header",
)


@dataclass(frozen=True)
class Finding:
    """One disagreement between the two targets."""

    probe_id: str
    kind: str
    path: str
    mock: str
    real: str
    why: str = ""

    @property
    def rank(self) -> int:
        """Position in `KIND_ORDER`, for sorting worst-first."""
        return KIND_ORDER.index(self.kind) if self.kind in KIND_ORDER else len(KIND_ORDER)

    def describe(self) -> str:
        """One line, phrased so the real product is the standard."""
        return (
            f"[{self.kind}] {self.probe_id} {self.path}\n"
            f"    real:  {self.real}\n"
            f"    mock:  {self.mock}"
        )


@dataclass(frozen=True)
class Response:
    """What one target answered, reduced to what is worth comparing."""

    status: int
    headers: dict[str, str]
    body: Any
    #: Set when the body was not JSON, so the harness can say so rather than
    #: silently comparing two empty skeletons and reporting agreement.
    body_error: str = ""


def _ignored(path: str, ignore_paths: tuple[str, ...]) -> bool:
    """Whether a path was explicitly excluded by the probe."""
    return any(path == p or path.startswith(f"{p}.") or path.startswith(f"{p}[")
               for p in ignore_paths)


def _empty_arrays(skel: dict[str, str]) -> set[str]:
    """Array paths that this side reported with no elements at all."""
    arrays = {p for p, kind in skel.items() if kind == "array"}
    return {a for a in arrays if not any(p.startswith(f"{a}[*]") for p in skel)}


def _under_empty_array(path: str, empty: set[str]) -> bool:
    """Whether a path lives inside an array that one side reported as empty.

    A seeded mock returns twenty rules where a fresh Kibana returns none. Every
    field of every rule then reads as an extra key, which is true and useless:
    the shapes were never compared, because one side had nothing to compare.
    Probes that genuinely need both sides populated declare `needs_seed`.
    """
    return any(path.startswith(f"{a}[*]") for a in empty)


def compare(
    probe_id: str,
    mock: Response,
    real: Response,
    significant_keys: frozenset[str],
    ignore_paths: tuple[str, ...] = (),
    why: str = "",
) -> list[Finding]:
    """Compare one probe's two responses, worst finding first."""
    findings: list[Finding] = []

    if mock.status != real.status:
        findings.append(Finding(
            probe_id, "status", "$", str(mock.status), str(real.status), why,
        ))

    for name in sorted(SIGNIFICANT_HEADERS):
        mock_value = mask(mock.headers.get(name, ""))
        real_value = mask(real.headers.get(name, ""))
        # A header absent from both is agreement, not a finding.
        if mock_value != real_value and (mock_value or real_value):
            findings.append(Finding(
                probe_id, "header", f"header:{name}", mock_value or "<absent>",
                real_value or "<absent>", why,
            ))

    if mock.body_error or real.body_error:
        findings.append(Finding(
            probe_id, "type", "$",
            mock.body_error or "json", real.body_error or "json", why,
        ))
        return sorted(findings, key=lambda f: (f.rank, f.path))

    mock_skeleton = skeleton(mock.body, significant_keys)
    real_skeleton = skeleton(real.body, significant_keys)
    uncomparable = _empty_arrays(mock_skeleton) | _empty_arrays(real_skeleton)

    for path in sorted(set(mock_skeleton) | set(real_skeleton)):
        if _ignored(path, ignore_paths) or _under_empty_array(path, uncomparable):
            continue
        in_mock = mock_skeleton.get(path)
        in_real = real_skeleton.get(path)
        if in_mock == in_real:
            continue
        if in_real is None:
            findings.append(Finding(probe_id, "extra_key", path, in_mock or "", "<absent>", why))
        elif in_mock is None:
            findings.append(Finding(probe_id, "missing_key", path, "<absent>", in_real, why))
        else:
            # A leading '=' marks a significant key, whose *value* differs.
            kind = "value" if in_real.startswith("=") or in_mock.startswith("=") else "type"
            findings.append(Finding(probe_id, kind, path, in_mock, in_real, why))

    return sorted(findings, key=lambda f: (f.rank, f.path))
