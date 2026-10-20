"""VerificationRecord.fully_verified: the one place the granular record
collapses to a boolean, and the gate EVALUATE's verification check reads."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from provenance.models.verification import VerificationRecord

CHECKS = ("signature_verified", "chain_verified", "sct_verified", "tlog_verified")


def _record(**checks) -> VerificationRecord:
    return VerificationRecord(
        raw_digest="deadbeef",
        verified_at=datetime.now(timezone.utc),
        trust_root="production",
        **checks,
    )


def test_fully_verified_when_every_check_passed():
    assert _record(**dict.fromkeys(CHECKS, True)).fully_verified is True


@pytest.mark.parametrize("value", [False, None])
@pytest.mark.parametrize("check", CHECKS)
def test_not_fully_verified_if_any_one_check_did_not_pass(check, value):
    """A single failed or unknown check is enough to withhold it — `None`
    ("couldn't confirm it ran") counts against, same as `False`."""
    checks = dict.fromkeys(CHECKS, True)
    checks[check] = value
    assert _record(**checks).fully_verified is False
