"""The canonical provenance model — NORMALISE's output shape.

Field set matches the README's candidate list, but every extraction rule
behind these fields is pinned to what the two real captured fixtures
actually contain (tests/fixtures/bundles/), not to the SLSA spec from
memory. See the two adapters (normalize/v0_2.py, normalize/v1_0.py) for the
exact JSON paths each field comes from, and their docstrings for what's
genuinely absent rather than merely unextracted.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel


class Dependency(BaseModel):
    """One resolved dependency / material, copied close to verbatim.

    `digest` is kept as the original digest dict (e.g. `{"sha1": "..."}` or
    `{"gitCommit": "..."}`) rather than renamed onto a canonical
    digest-algorithm scheme — inventing that mapping across versions from
    two examples would be exactly the kind of guess this model is trying
    to avoid. See CanonicalProvenance.source_revision's docstring for the
    one place a digest value *is* flattened, and why.
    """

    uri: str
    digest: dict[str, str]


class CanonicalProvenance(BaseModel):
    """One canonical projection of a verified SLSA provenance predicate.

    This is the "facts" layer (see README's evidence→facts→decisions
    model) — it must never be surfaced without the VerificationRecord for
    the same raw record attached, or it implies more certainty than
    normalization alone earned.
    """

    predicate_type: str
    """Verbatim `predicateType` string, e.g.
    "https://slsa.dev/provenance/v1" — note the real value is `.../v1`,
    not `.../v1.0`, confirmed against the actual ruff fixture."""

    predicate_version: str
    """The version segment of predicate_type (e.g. "v1", "v0.2") — a
    convenience split of predicate_type, not independently observed."""

    adapter_id: str
    """Which adapter module produced this record, e.g.
    "slsa_provenance_v0_2". Distinct from predicate_type/predicate_version
    (the spec version) — see the module docstring on adapter versioning."""

    adapter_version: str
    """The adapter code's own version, bumped on adapter bug fixes
    independent of the SLSA spec version it targets."""

    builder_id: str | None = None
    build_type: str | None = None

    source_repo: str | None = None

    source_revision: str | None = None
    """A git commit-ish string. Deliberately flattened to a plain string
    even though the two real fixtures store it under different digest
    keys — v0.2's `invocation.configSource.digest.sha1`, v1.0's matching
    `resolvedDependencies[].digest.gitCommit`. This flattening is
    provisional on those two examples: if a future fixture's dependency
    entry carries a source digest under some other key, or more than one
    digest, that's real evidence to revise this rule against — see
    `dependencies`, which keeps the original digest dict so that revision
    has something to work from."""

    invocation_id: str | None = None
    """Shape genuinely differs between the two real fixtures, not just
    the field path: v1.0 (ruff) gives a full run URL
    ("https://github.com/.../actions/runs/.../attempts/1"); v0.2
    (scorecard) gives an opaque "{run_id}-{attempt}" string. Both are
    "invocation_id" conceptually; neither is parsed further."""

    started_at: datetime | None = None
    finished_at: datetime | None = None
    """Neither real fixture's predicate carries build start/end
    timestamps at all — not "present but unextracted," genuinely absent
    from both. These stay None rather than the adapter inventing a
    fallback (e.g. Rekor's integratedTime is a signing time, not a build
    time, and using it here would misrepresent what these fields mean)."""

    dependencies: list[Dependency] = []
    """From v0.2's `materials[]` / v1.0's `resolvedDependencies[]`,
    copied close to verbatim (see Dependency). Both real fixtures happen
    to have exactly one entry each — the source repo itself — so this
    field is not exercised with genuine build-input dependencies (a
    fetched tool, a base image, ...) by either fixture; don't read the
    tests as proof of multi-dependency handling."""

    raw_unmapped: dict[str, Any] = {}
    """The predicate with exactly the leaf keys mapped above removed —
    a debugging aid pointing at what the adapter didn't claim, *not* the
    completeness guarantee (that's the raw record itself, stored
    verbatim). Can be non-trivially sized: e.g. v0.2's
    `invocation.environment.github_event_payload` alone measured ~8.5KB
    on the real scorecard fixture. See the README's "raw_unmapped bulk
    exclusion" open question for why that isn't fixed by excluding it
    here."""
