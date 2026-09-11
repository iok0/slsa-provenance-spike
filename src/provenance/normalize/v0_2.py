"""Adapter for SLSA provenance v0.2 (`https://slsa.dev/provenance/v0.2`).

Every extraction rule below is pinned to the real fixture
(tests/fixtures/bundles/scorecard-5.5.0-darwin-amd64-slsa-v0.2/), not to
the SLSA spec from memory — see that fixture's decoded predicate for the
exact shape this was written against. Two corrections found only by
looking at the real bytes, recorded here rather than left implicit:

- The build-invocation-id field is `metadata.buildInvocationID` — capital
  "ID", not "Id".
- `metadata.buildStartedOn` / `buildFinishedOn` do not exist in the real
  predicate at all. started_at/finished_at are left None; no fallback is
  invented for a field that's genuinely absent.

`invocation.configSource` is used as the sole source of `source_repo` /
`source_revision`. The real fixture's `materials[]` happens to duplicate
the same URI+digest, and SPIKE-derived design notes mention materials[]
as a fallback when configSource is absent — but no fixture exercises that
absence, so that fallback branch is not written here. It's a named,
unexercised extension point, not implemented code.
"""

from __future__ import annotations

from typing import Any

from provenance.models.provenance import CanonicalProvenance, Dependency
from provenance.normalize._util import without_paths

ADAPTER_ID = "slsa_provenance_v0_2"
ADAPTER_VERSION = "1.0.0"

_MAPPED_PATHS = [
    ["builder"],
    ["buildType"],
    ["invocation", "configSource"],
    ["metadata", "buildInvocationID"],
    ["materials"],
]


def adapt(statement: dict[str, Any]) -> CanonicalProvenance:
    """Normalize one SLSA v0.2 in-toto Statement into the canonical model."""
    predicate_type = statement["predicateType"]
    predicate = statement["predicate"]

    config_source = predicate.get("invocation", {}).get("configSource", {})
    source_revision = config_source.get("digest", {}).get("sha1")

    dependencies = [
        Dependency(uri=m["uri"], digest=m.get("digest", {}))
        for m in predicate.get("materials", [])
    ]

    return CanonicalProvenance(
        predicate_type=predicate_type,
        predicate_version=predicate_type.rsplit("/", 1)[-1],
        adapter_id=ADAPTER_ID,
        adapter_version=ADAPTER_VERSION,
        builder_id=predicate.get("builder", {}).get("id"),
        build_type=predicate.get("buildType"),
        source_repo=config_source.get("uri"),
        source_revision=source_revision,
        invocation_id=predicate.get("metadata", {}).get("buildInvocationID"),
        started_at=None,  # genuinely absent from the real predicate — see module docstring
        finished_at=None,
        dependencies=dependencies,
        raw_unmapped=without_paths(predicate, _MAPPED_PATHS),
    )
