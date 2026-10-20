"""Shared test configuration.

Under mutmut only (it sets MUTANT_UNDER_TEST, possibly to ""), force
`Verifier.production()` offline so each mutant reuses the TUF trust root
cached by the last online run instead of re-fetching it. Hundreds of
network fetches would make a mutation run slow, and a flaky fetch would
count as a false "killed". Plain pytest and CI are unaffected and still
exercise the live fetch.
"""

import os

import pytest
from sigstore.verify import Verifier


@pytest.fixture(autouse=True)
def _offline_trust_root_under_mutmut(monkeypatch):
    if "MUTANT_UNDER_TEST" not in os.environ:
        return
    production = Verifier.production.__func__
    monkeypatch.setattr(
        Verifier,
        "production",
        classmethod(lambda cls, offline=False: production(cls, offline=True)),
    )
