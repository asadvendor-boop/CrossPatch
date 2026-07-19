#!/usr/bin/env python3
"""Generate the claim map from existing machine-produced verification artifacts."""

from __future__ import annotations

import json

from verification_lib import generate_claim_map

if __name__ == "__main__":
    print(json.dumps(generate_claim_map(), indent=2, sort_keys=True))
