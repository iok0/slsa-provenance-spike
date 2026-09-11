"""Adapter for SLSA provenance v1.0 (`https://slsa.dev/provenance/v1`).

Every extraction rule below is pinned to the real fixture
(tests/fixtures/bundles/ruff-0.16.7-linux-x86_64-slsa-v1/) — see that
fixture's decoded predicate for the exact shape this was written against.
One correction found only by looking: the real predicate string is
`.../provenance/v1`, not `.../v1.0` — `predicate_version` below reflects
that rather than the more readable version some docs use.

`source_repo` / `source_revision` extraction is genuinely build-type-
specific in v1.0 (a SLSA v1.0 predicate's `externalParameters` shape is
defined by whoever owns the buildType, not by the SLSA spec itself) — see
README. This module only implements the one buildType in evidence,
GitHub's `actions.github.io/buildtypes/workflow/v1`: source repo comes
from `externalParameters.workflow.repository`, source revision from the
`resolvedDependencies[]` entry whose URI matches that repository. Any
other buildType (a Tekton, Google Cloud Build, or custom pipeline would
each have their own externalParameters shape entirely) raises rather than
guessing at an unfamiliar shape — adding a second buildType later is a new
branch here, not a rewrite, but no branch gets written for an ecosystem
with no fixture to pin it against.

The URI match below is exact-string, after stripping the `git+` scheme
prefix and an `@ref` suffix — sufficient for the one real fixture, where
both fields come from the same tool's internal state and so already agree
on protocol/casing/suffix. It will not survive a `.git` suffix, a
protocol mismatch (`https://` vs `git+https://` appearing on only one
side), or org/repo case differences — known, named, not handled, because
no fixture exercises any of those variants. See
implementation_learnings.md's "External review" section.
"""

from __future__ import annotations

from typing import Any

from provenance.models.provenance import CanonicalProvenance, Dependency
from provenance.normalize._util import without_paths

ADAPTER_ID = "slsa_provenance_v1_0"
ADAPTER_VERSION = "1.0.0"

_SUPPORTED_BUILD_TYPES = {"https://actions.github.io/buildtypes/workflow/v1"}

_MAPPED_PATHS = [
    ["buildDefinition", "buildType"],
    ["buildDefinition", "externalParameters"],
    ["buildDefinition", "resolvedDependencies"],
    ["runDetails", "builder"],
    ["runDetails", "metadata", "invocationId"],
]


class UnsupportedBuildType(ValueError):
    """A v1.0 predicate with a buildType this adapter has no fixture for.

    Deliberately a hard failure, not a best-effort fallback — a
    different buildType means a different externalParameters shape that
    this code has never seen and would otherwise be guessing at.
    """


def _strip_git_ref(uri: str) -> str:
    """"git+https://github.com/astral-sh/ruff@refs/heads/main" ->
    "https://github.com/astral-sh/ruff" — exact-match only, see module
    docstring on what this does not normalize."""
    uri = uri.removeprefix("git+")
    return uri.split("@", 1)[0]


def adapt(statement: dict[str, Any]) -> CanonicalProvenance:
    """Normalize one SLSA v1.0 in-toto Statement into the canonical model."""
    predicate_type = statement["predicateType"]
    predicate = statement["predicate"]

    build_definition = predicate["buildDefinition"]
    build_type = build_definition["buildType"]
    if build_type not in _SUPPORTED_BUILD_TYPES:
        raise UnsupportedBuildType(
            f"no v1.0 extractor for buildType {build_type!r} — "
            "externalParameters shape is build-type-specific, see module docstring"
        )

    workflow_repo = build_definition["externalParameters"]["workflow"]["repository"]
    resolved_dependencies = build_definition.get("resolvedDependencies", [])

    source_revision = None
    for dep in resolved_dependencies:
        if _strip_git_ref(dep["uri"]) == workflow_repo:
            source_revision = dep.get("digest", {}).get("gitCommit")
            break

    dependencies = [
        Dependency(uri=d["uri"], digest=d.get("digest", {}))
        for d in resolved_dependencies
    ]

    return CanonicalProvenance(
        predicate_type=predicate_type,
        predicate_version=predicate_type.rsplit("/", 1)[-1],
        adapter_id=ADAPTER_ID,
        adapter_version=ADAPTER_VERSION,
        builder_id=predicate.get("runDetails", {}).get("builder", {}).get("id"),
        build_type=build_type,
        source_repo=workflow_repo,
        source_revision=source_revision,
        invocation_id=predicate.get("runDetails", {}).get("metadata", {}).get("invocationId"),
        started_at=None,  # genuinely absent from the real predicate — see module docstring
        finished_at=None,
        dependencies=dependencies,
        raw_unmapped=without_paths(predicate, _MAPPED_PATHS),
    )
