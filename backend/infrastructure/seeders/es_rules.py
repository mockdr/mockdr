"""Elastic Security detection rules seeder."""
from __future__ import annotations

import random

from faker import Faker

from domain.es_rule import EsRule
from infrastructure.seeders._shared import rand_ago
from infrastructure.seeders.es_shared import (
    ES_EQL_QUERIES,
    ES_KQL_QUERIES,
    ES_MITRE_TACTICS,
    ES_MITRE_TECHNIQUES,
    ES_RULE_NAMES,
    ES_SEVERITY_LEVELS,
    es_uuid,
)
from repository.es_rule_repo import es_rule_repo

_RISK_SCORE_MAP: dict[str, tuple[int, int]] = {
    "low": (1, 25),
    "medium": (26, 50),
    "high": (51, 75),
    "critical": (76, 100),
}

_TAG_POOL: list[str] = [
    "Elastic", "Windows", "Linux", "macOS", "Threat Detection",
    "Persistence", "Defense Evasion", "Credential Access",
    "Command and Control", "Initial Access", "Execution",
    "Lateral Movement", "Collection", "Exfiltration",
]


def _build_threat_mapping() -> list[dict]:
    """Build a realistic MITRE ATT&CK threat mapping with 1-2 entries."""
    count = random.randint(1, 2)
    mappings: list[dict] = []
    tactics = random.sample(ES_MITRE_TACTICS, min(count, len(ES_MITRE_TACTICS)))
    for tactic in tactics:
        technique = random.choice(ES_MITRE_TECHNIQUES)
        mappings.append({
            "framework": "MITRE ATT&CK",
            "tactic": tactic,
            "technique": [technique],
        })
    return mappings


def seed_es_rules(fake: Faker) -> list[str]:
    """Generate 25 Elastic Security detection rules.

    Creates 15 KQL-based, 8 EQL-based, and 2 threshold rules with realistic
    MITRE threat mappings, tags, severity, and risk scores.

    Args:
        fake: Shared Faker instance (seeded externally).

    Returns:
        List of rule ID strings.
    """
    rule_ids: list[str] = []
    created_by = "elastic"

    for i, name in enumerate(ES_RULE_NAMES):
        rule_id_str = es_uuid()
        doc_id = es_uuid()
        rule_ids.append(doc_id)

        severity = random.choice(ES_SEVERITY_LEVELS)
        lo, hi = _RISK_SCORE_MAP[severity]
        risk_score = random.randint(lo, hi)

        # Determine rule type and query
        if i < 15:
            rule_type = "query"
            language = "kuery"
            query = ES_KQL_QUERIES[i % len(ES_KQL_QUERIES)]
        elif i < 23:
            rule_type = "eql"
            language = "eql"
            query = ES_EQL_QUERIES[(i - 15) % len(ES_EQL_QUERIES)]
        else:
            rule_type = "threshold"
            language = "kuery"
            query = random.choice(ES_KQL_QUERIES)

        tags = random.sample(_TAG_POOL, random.randint(2, 5))
        threat = _build_threat_mapping()
        enabled = random.random() < 0.80
        created_at = rand_ago(random.randint(30, 180))

        es_rule_repo.save(EsRule(
            id=doc_id,
            rule_id=rule_id_str,
            name=name,
            description=f"Detects {name.lower()} activity on managed endpoints.",
            type=rule_type,
            query=query,
            language=language,
            index=["logs-endpoint.events.*", "filebeat-*", "winlogbeat-*"],
            severity=severity,
            risk_score=risk_score,
            enabled=enabled,
            tags=tags,
            threat=threat,
            author=["Elastic"],
            version=random.randint(1, 10),
            interval=random.choice(["5m", "10m", "15m"]),
            from_field="now-6m",
            max_signals=100,
            false_positives=[],
            references=[],
            actions=[],
            exceptions_list=[],
            created_at=created_at,
            created_by=created_by,
            # taken after created_at: now_ts was sampled before the loop, so a
            # created_at drawn close to "now" could land after it
            updated_at=rand_ago(0),
            updated_by=created_by,
            immutable=False,
            last_execution=_last_execution(enabled),
        ))

    return rule_ids


def _last_execution(enabled: bool) -> dict | None:
    """What this rule's last run reported, for a rule that has ever run.

    A disabled rule in a fresh install has none, and Kibana leaves
    `execution_summary` out for it entirely. An enabled one has run within
    its interval, so a client reading rule health sees a rule that is alive
    rather than one that has never started.
    """
    if not enabled:
        return None
    return {
        "date": rand_ago(0),
        "status": "succeeded",
        "status_order": 0,
        "message": "succeeded",
        "metrics": {
            "total_search_duration_ms": random.randint(20, 400),
            "total_indexing_duration_ms": random.randint(5, 120),
            "execution_gap_duration_s": 0,
        },
    }
