"""EVALUATE's output shape: a two-valued decision, never a bare bool.

Matches the evidence→facts→decisions diagram exactly: "policy = ALLOW /
DENY + reasons" — no third "allow at a lower level" state invented here.
`policy_version` is stamped for the same reason a VerificationRecord
stamps `trust_root`: a decision made under last quarter's policy and one
made under today's are not the same fact wearing the same label.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel


class PolicyOutcome(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class Decision(BaseModel):
    outcome: PolicyOutcome
    reasons: list[str]
    policy_version: str
