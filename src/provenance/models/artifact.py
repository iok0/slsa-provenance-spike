"""Platform-side artifact identity — the ASSOCIATE stage's target shape.

Artifact identity is (tenant, repo, package, version, file), per the
README. No real backend exists to look this up against, so this is a
plain value object; see associate.py for the (hand-seeded stub) lookup.
"""

from __future__ import annotations

from pydantic import BaseModel


class ArtifactRef(BaseModel):
    tenant_id: str
    repo: str
    package: str
    version: str
    file: str
