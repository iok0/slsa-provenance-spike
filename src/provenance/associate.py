"""ASSOCIATE: resolve an evidence-side digest to a platform artifact.

Deliberately one thin function against a hand-seeded stub table, not a
subsystem with its own tests (see README's ASSOCIATE section) — the
design is real, the code is a stand-in on purpose. Three concerns the
README names in full but this function does not implement:

- **Late-binding.** Attestation and artifact can arrive independently and
  out of order; a real implementation resolves when both sides exist,
  not as a synchronous check. This stub assumes the artifact side is
  already in the table.
- **Digest algorithm agility / strong-digest floor beyond sha256.** Only
  a cryptographically strong digest may be the association basis; a weak
  digest (sha1) sitting alongside a strong one in a real subject list
  must never be usable to attach a real attestation to different bytes.
  This function takes a single digest string and trusts the caller to
  have already chosen it — it does no algorithm filtering itself. (The
  caller that builds the subject-digest index this looks up against —
  api/demo_bootstrap.py — only ever reads a subject's `sha256` key for
  exactly this reason; see that module's docstring.)
- **OCI/container manifest depth.** For container subjects, association
  may need to match an index digest or any per-platform manifest digest,
  not one fixed level. Out of scope here — file digests only, matching
  what both real fixtures actually are. (OCI is also exactly the kind of
  format `ArtifactRef.format_namespace` exists for — a per-format
  sub-scope, not the platform's own account-level "namespace" — so this
  and that field are the same unbuilt generalization, not two independent
  ones.)

Tenant-scoping IS real here, not just named: the stub table is keyed by
(tenant_id, digest), so a lookup can never cross tenants even if two
tenants coincidentally reference the same bytes — a security property
(stops laundering a real attestation across a trust boundary purely
because digests agree), not just identity-resolution convenience.
"""

from __future__ import annotations

from provenance.models.artifact import ArtifactRef

# Hand-seeded stub, not a database — see module docstring. Keyed on the
# two real subject digests already present in the committed fixtures
# (tests/fixtures/bundles/), not on invented digests: this row's key is
# literally the sha256 of ruff-x86_64-unknown-linux-gnu.tar.gz, the same
# bytes the ruff fixture's provenance is about.
_STUB_ARTIFACTS: dict[tuple[str, str], ArtifactRef] = {
    (
        "acme",
        "sha256:73894c7b7c9a53fd66ed715eb3a1ec65077f316328e377057a98bdb7fcba0326",
    ): ArtifactRef(
        tenant_id="acme",
        repo="acme-tools",
        format_namespace=None,  # generic tarball release, no format sub-scope involved
        package="ruff",
        version="0.16.7",
        file="ruff-x86_64-unknown-linux-gnu.tar.gz",
    ),
    (
        "acme",
        "sha256:979487ca20e726f6a4d2bd63a0a4c544184f589724b3d12d2ba8d0ea80889063",
    ): ArtifactRef(
        tenant_id="acme",
        repo="acme-security",
        format_namespace=None,  # generic tarball release, no format sub-scope involved
        package="scorecard",
        version="5.5.0",
        file="scorecard_5.5.0_darwin_amd64.tar.gz",
    ),
}


def associate(subject_digest: str, tenant_id: str) -> ArtifactRef | None:
    """Resolve (subject_digest, tenant_id) to an ArtifactRef, or None if
    this tenant has no such artifact — including when the digest is
    known, just not to *this* tenant (see module docstring on why that
    must not fall through to another tenant's entry)."""
    return _STUB_ARTIFACTS.get((tenant_id, subject_digest))
