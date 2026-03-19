"""Seed Microsoft Graph Defender for Office 365 data (attack simulations, threat assessments)."""
from __future__ import annotations

from faker import Faker

from domain.graph.attack_simulation import GraphAttackSimulation
from domain.graph.threat_assessment import GraphThreatAssessment
from infrastructure.seeders._shared import rand_ago
from infrastructure.seeders.graph.graph_shared import graph_uuid
from repository.graph.attack_simulation_repo import graph_attack_simulation_repo
from repository.graph.threat_assessment_repo import graph_threat_assessment_repo


def seed_graph_defender_office(fake: Faker, user_ids: list[str]) -> None:
    """Seed attack simulations and threat assessment requests.

    Args:
        fake: Shared Faker instance (seeded externally).
        user_ids: Graph user IDs for simulation targeting.
    """
    # ── Attack Simulations ────────────────────────────────────────────────
    simulations: list[dict] = [
        {
            "displayName": "Credential Harvest - IT Alert",
            "attackTechnique": "credentialHarvesting",
            "attackType": "social",
            "status": "succeeded",
            "report": {
                "overview": {
                    "resolvedTargetsCount": 20,
                    "compromisedRate": 0.15,
                },
                "simulationUsers": [],
            },
        },
        {
            "displayName": "Link in Attachment",
            "attackTechnique": "linkInAttachment",
            "attackType": "social",
            "status": "succeeded",
            "report": {
                "overview": {
                    "resolvedTargetsCount": 18,
                    "compromisedRate": 0.22,
                },
                "simulationUsers": [],
            },
        },
        {
            "displayName": "Drive-by URL",
            "attackTechnique": "driveByUrl",
            "attackType": "social",
            "status": "completed",
            "report": {
                "overview": {
                    "resolvedTargetsCount": 15,
                    "compromisedRate": 0.07,
                },
                "simulationUsers": [],
            },
        },
    ]

    for sim_data in simulations:
        launch_dt = rand_ago(max_days=60)
        completion_dt = rand_ago(max_days=30)
        sim = GraphAttackSimulation(
            id=graph_uuid(),
            displayName=sim_data["displayName"],
            status=sim_data["status"],
            launchDateTime=launch_dt,
            completionDateTime=completion_dt,
            attackTechnique=sim_data["attackTechnique"],
            attackType=sim_data["attackType"],
            report=sim_data["report"],
            createdDateTime=launch_dt,
        )
        graph_attack_simulation_repo.save(sim)

    # ── Threat Assessment Requests ────────────────────────────────────────
    assessments: list[dict] = [
        {"contentType": "mail", "category": "phishing", "expectedAssessment": "block"},
        {"contentType": "mail", "category": "phishing", "expectedAssessment": "block"},
        {"contentType": "url", "category": "malware", "expectedAssessment": "block"},
        {"contentType": "url", "category": "malware", "expectedAssessment": "block"},
        {"contentType": "file", "category": "malware", "expectedAssessment": "block"},
    ]

    for assess_data in assessments:
        assessment = GraphThreatAssessment(
            id=graph_uuid(),
            contentType=assess_data["contentType"],
            expectedAssessment=assess_data["expectedAssessment"],
            status="completed",
            category=assess_data["category"],
            result={
                "resultType": "checkPolicy",
                "message": f"This {assess_data['contentType']} has been assessed as {assess_data['category']}.",
            },
            createdDateTime=rand_ago(max_days=45),
            requestSource="administrator",
        )
        graph_threat_assessment_repo.save(assessment)
