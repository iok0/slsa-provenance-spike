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
    namespace: str | None = None
    """Format-level namespace, distinct from `tenant_id` (the the platform
    account) — npm scope, Maven groupId, Docker image namespace, Conan
    user/channel, ... Several formats have no such concept (PyPI,
    RubyGems, NuGet, generic uploads), hence optional rather than a
    forced empty-string placeholder. Needed because `package` alone is
    not a unique key within a repo for namespaced formats: `server`
    under `@acme` and `server` under `@other` are different packages
    that happen to share a name. Both real fixtures are plain generic
    tarball releases with no namespace, so this stays None for them —
    not yet pinned against a real namespaced fixture."""
    package: str
    version: str
    file: str
