"""Per-subject (admission-time) policy: a plain Python predicate function.

No engine (no OPA/Cedar/CEL) — struck deliberately, see README. The
interesting artifact is the input document (EvidenceItem, from
provenance.models.evidence) and the decision contract (Decision), not
this function; it can be replaced by a real engine later without
touching either.

A pure function of the artifact's *evidence set*, not a single
attestation in isolation — some admission-relevant facts only exist
across the set. "Provenance present but SBOM missing" is the
motivating example for why this has to be set-level at all, but it's
illustrative only: no SBOM evidence type exists in this build (see the
README), so there's no code path that could check it. The one such
check actually implemented is two provenance attestations disagreeing
on builder identity, and even that is only exercised by a constructed
test — both real fixtures are singleton evidence sets, so no real
fixture reaches it either.

## The SLSA-level check, and what the real fixtures forced

"SLSA level met" is not a field in any predicate — it's asserted
out-of-band by whoever operates the build platform (README). So level is
determined by mapping the verified `builder_id` against a maintained
allowlist below. That mapping alone is insufficient against both real
fixtures:

- The real ruff (v1.0, GitHub-native) fixture has
  `buildDefinition.internalParameters.github.runner_environment ==
  "self-hosted"`. GitHub's Build L3 claim covers only GitHub-*hosted*
  runners, not self-hosted (operator-controlled) ones — so this
  builder's allowlisted level-3 ceiling doesn't apply to *this
  specific* attestation, even though the builder itself is allowlisted.
  This isn't a single GitHub sentence to that effect; it's two real,
  separately-documented facts combined: GitHub's own runner-security
  docs state self-hosted runners lack the ephemeral/isolated-VM
  guarantee GitHub-hosted runners have and "can be persistently
  compromised by untrusted code in a workflow"
  (https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#hardening-for-self-hosted-runners),
  and SLSA Build L3 itself requires exactly that isolation property —
  "strong controls to prevent runs from influencing one another, even
  within the same project" (https://slsa.dev/spec/v1.0/levels,
  Build L3).
- The real scorecard (v0.2, slsa-github-generator) fixture's predicate
  shape has no equivalent field at all. v0.2 evidence structurally
  cannot be confirmed on this axis.

Both cases are treated as "the required level cannot be positively
confirmed" — fail-closed on missing confirmation, not fail-open: an
unconfirmed non-falsifiability claim provides no more assurance than no
claim at all. Run against both real fixtures, this denies both, for two
different reasons — see the README for why that's a finding to keep,
not a bug to fix.

## builder_id is only trustworthy if it matches who actually signed

`builder_id` is NORMALISE output — a string read verbatim out of the
signed payload's content. Verification proves the payload was signed by
whoever held the cert's key; it says nothing about whether *that*
identity was entitled to write this particular `builder_id` into its own
predicate. Allowlisting on `builder_id` alone would let any signer with
an acceptable issuer self-assert its way past the allowlist — the same
"downstream layer implying more certainty than the layer beneath earned"
mistake the rest of this codebase is built to avoid. So `_evaluate_item`
requires `builder_id == item.verification.identity` (the cert SAN) before
trusting an allowlist hit at all. For both real fixtures the two are
equal by construction — GitHub-native `attest-build-provenance` and
slsa-github-generator's reusable workflow both run in an isolated context
the calling job can't write to — but the check exists for the builder
that doesn't offer that isolation, not for these two.
"""

from __future__ import annotations

from provenance.models.evidence import EvidenceItem
from provenance.policy.models import Decision, PolicyOutcome

POLICY_VERSION = "1.0.0"

# Hand-seeded, same spirit as associate.py's stub artifact table — a
# maintained allowlist in production, a fixed dict here. Maps builder_id
# to the SLSA level that builder is documented as *capable of*; whether
# a given attestation actually earns it is checked per-item below.
_BUILDER_ALLOWLIST: dict[str, int] = {
    "https://github.com/astral-sh/ruff/.github/workflows/release.yml@refs/heads/main": 3,
    "https://github.com/slsa-framework/slsa-github-generator/"
    ".github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0": 3,
}

_ACCEPTABLE_ISSUERS = {"https://token.actions.githubusercontent.com"}

_REQUIRED_LEVEL = 3

# The one buildType for which this function knows where to look for a
# runner-environment signal — see v1_0.py, which only supports this same
# buildType. A different v1.0 buildType would have its own
# externalParameters/internalParameters shape entirely; no equivalent
# check is invented for it here.
_GHA_WORKFLOW_BUILD_TYPE = "https://actions.github.io/buildtypes/workflow/v1"


def _confirmed_github_hosted(item: EvidenceItem) -> bool | None:
    """True if this attestation's runner_environment is confirmed
    github-hosted, False if confirmed otherwise, None if this evidence
    source doesn't expose the signal at all (see module docstring)."""
    if item.provenance.build_type != _GHA_WORKFLOW_BUILD_TYPE:
        return None
    runner_environment = (
        item.provenance.raw_unmapped.get("buildDefinition", {})
        .get("internalParameters", {})
        .get("github", {})
        .get("runner_environment")
    )
    if runner_environment is None:
        return None
    return runner_environment == "github-hosted"


def _evaluate_item(item: EvidenceItem) -> list[str]:
    """Denial reasons for one evidence item; empty if it raises none."""
    reasons: list[str] = []

    if not item.verification.fully_verified:
        return [f"{item.raw_digest}: verification did not fully pass ({item.verification.error})"]

    if item.verification.issuer not in _ACCEPTABLE_ISSUERS:
        reasons.append(
            f"{item.raw_digest}: issuer {item.verification.issuer!r} not in "
            "the acceptable-issuer list"
        )

    # builder_id is self-asserted NORMALISE output, not itself verified —
    # see module docstring's "builder_id is only trustworthy..." section.
    builder_id = item.provenance.builder_id
    if builder_id != item.verification.identity:
        reasons.append(
            f"{item.raw_digest}: builder_id {builder_id!r} asserted in the "
            f"provenance predicate does not match the verified signing "
            f"identity {item.verification.identity!r} — builder_id is "
            "self-asserted payload content, not itself verified, so it "
            "cannot be trusted as an allowlist key unless it matches who "
            "the cryptography says actually signed this"
        )
        return reasons

    claimed_level = _BUILDER_ALLOWLIST.get(builder_id)
    if claimed_level is None:
        reasons.append(f"{item.raw_digest}: builder {builder_id!r} not in builder allowlist")
    elif claimed_level < _REQUIRED_LEVEL:
        reasons.append(
            f"{item.raw_digest}: builder {builder_id!r} claims level "
            f"{claimed_level}, required {_REQUIRED_LEVEL}"
        )
    else:
        confirmed = _confirmed_github_hosted(item)
        if confirmed is None:
            reasons.append(
                f"{item.raw_digest}: builder {builder_id!r}'s claimed level "
                f"{claimed_level} depends on runner isolation that "
                f"{item.provenance.predicate_type} evidence does not expose "
                "a signal for — cannot confirm"
            )
        elif confirmed is False:
            reasons.append(
                f"{item.raw_digest}: builder {builder_id!r}'s claimed level "
                f"{claimed_level} is documented for GitHub-hosted runners; "
                "this attestation's runner_environment was not github-hosted"
            )

    return reasons


def evaluate(evidence_set: list[EvidenceItem]) -> Decision:
    """Evaluate one artifact's full evidence set, not one item at a time."""
    if not evidence_set:
        return Decision(
            outcome=PolicyOutcome.DENY,
            reasons=["no evidence for this artifact"],
            policy_version=POLICY_VERSION,
        )

    reasons: list[str] = []
    for item in evidence_set:
        reasons.extend(_evaluate_item(item))

    # The one genuine evidence-*set*-level check (not per-item) — see
    # module docstring on why no real fixture exercises this branch.
    builder_ids = {item.provenance.builder_id for item in evidence_set}
    if len(builder_ids) > 1:
        reasons.append(
            f"evidence set disagrees on builder identity across attestations: {builder_ids}"
        )

    outcome = PolicyOutcome.DENY if reasons else PolicyOutcome.ALLOW
    return Decision(outcome=outcome, reasons=reasons, policy_version=POLICY_VERSION)
