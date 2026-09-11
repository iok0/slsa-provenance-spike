#!/usr/bin/env python3
"""Run the /v1/ provenance API against the two committed real fixtures.

    uvicorn.run via: python scripts/run_demo_api.py

Then, e.g.:
    curl http://127.0.0.1:8000/v1/provenance/acme/sha256:73894c7b7c9a53fd66ed715eb3a1ec65077f316328e377057a98bdb7fcba0326

This is where the coupling to tests/fixtures/bundles/ lives — deliberately
here, not inside src/provenance/api/, which stays fixture-agnostic (see
demo_bootstrap.py and app.py's docstrings).
"""

from pathlib import Path

import uvicorn

from provenance.api.app import create_app
from provenance.api.demo_bootstrap import seed_from_fixtures

FIXTURES = Path(__file__).parent.parent / "tests" / "fixtures" / "bundles"

BUNDLE_PATHS = [
    FIXTURES / "ruff-0.16.7-linux-x86_64-slsa-v1" / "bundle.json",
    FIXTURES / "scorecard-5.5.0-darwin-amd64-slsa-v0.2" / "bundle.json",
]

if __name__ == "__main__":
    data = seed_from_fixtures(BUNDLE_PATHS)
    app = create_app(data)
    uvicorn.run(app, host="127.0.0.1", port=8000)
