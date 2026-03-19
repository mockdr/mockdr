"""Graph-specific reference data and helper functions.

Constants and pure helpers shared across all Graph domain seeders.
No repository imports — this module must remain free of side effects.
"""
from __future__ import annotations

import random
import uuid

# ---------------------------------------------------------------------------
# Tenant / domain constants
# ---------------------------------------------------------------------------

GRAPH_TENANT_ID: str = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
"""Mock Azure AD tenant ID (shared with MDE for consistency)."""

GRAPH_DOMAIN: str = "acmecorp.onmicrosoft.com"
"""Primary verified domain for the mock tenant."""

GRAPH_COMPANY_NAME: str = "AcmeCorp"
"""Company display name."""

# ---------------------------------------------------------------------------
# License / SKU constants
# ---------------------------------------------------------------------------

SKU_ID_M365_E5: str = "06ebc4ee-1bb5-47dd-8120-11324bc54e06"
SKU_ID_M365_E3: str = "05e9a617-0261-4cee-bb36-b42ad1a7e415"
SKU_ID_M365_BUSINESS_PREMIUM: str = "cbdc14ab-d96c-4c30-b9f4-6ada7cdc1d46"
SKU_ID_MDE_P2: str = "64bfac92-2b17-4482-b5e5-a0304429de3e"
SKU_ID_INTUNE_P1: str = "882e1d05-acd1-4ccb-8708-6ee03664b117"

SKU_PART_NUMBERS: dict[str, str] = {
    SKU_ID_M365_E5: "SPE_E5",
    SKU_ID_M365_E3: "SPE_E3",
    SKU_ID_M365_BUSINESS_PREMIUM: "SPB",
    SKU_ID_MDE_P2: "WIN_DEF_ATP",
    SKU_ID_INTUNE_P1: "INTUNE_A",
}

# ---------------------------------------------------------------------------
# ID generation
# ---------------------------------------------------------------------------


def graph_uuid() -> str:
    """Generate a deterministic UUID using the seeded RNG."""
    return str(uuid.UUID(int=random.getrandbits(128), version=4))
