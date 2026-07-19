from __future__ import annotations

import json

import pytest
from crosspatch.agents.schemas import (
    BailiffOutput,
    CounselOutput,
    MagistrateOutput,
    ProsecutorOutput,
)
from pydantic import ValidationError


def test_prosecutor_output_is_a_strict_discriminated_union() -> None:
    schema = ProsecutorOutput.model_json_schema()
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    root_schema = schema["properties"]["root"]
    assert root_schema["discriminator"]["propertyName"] == "outcome"
    assert {entry["$ref"].rsplit("/", 1)[-1] for entry in root_schema["oneOf"]} == {
        "SupportedRival",
        "NoSupportedRival",
    }

    with pytest.raises(ValidationError):
        ProsecutorOutput.model_validate(
            {
                "root": {
                    "outcome": "NO_SUPPORTED_RIVAL",
                    "counterexample_ids": [],
                    "test_ids": [],
                    "rival_mechanism": "CHECK_THEN_INSERT_RACE",
                }
            }
        )


def test_counsel_schema_structurally_forbids_commands_and_test_source() -> None:
    schema = json.dumps(CounselOutput.model_json_schema()).lower()
    assert all(term not in schema for term in ("argv", "command", "test_code", "test_source"))

    with pytest.raises(ValidationError):
        CounselOutput.model_validate(
            {
                "normalized_diff": "--- a/a\n+++ b/a\n",
                "test_intentions": [],
                "argv": ["sh", "-c", "id"],
            }
        )

    with pytest.raises(ValidationError):
        CounselOutput.model_validate(
            {
                "normalized_diff": "--- a/a\n+++ b/a\n",
                "test_intentions": [],
            }
        )


def test_bailiff_output_can_only_carry_a_warrant_identifier() -> None:
    assert set(BailiffOutput.model_json_schema()["properties"]) == {"warrant_id"}
    with pytest.raises(ValidationError):
        BailiffOutput.model_validate({"warrant_id": "w-1", "command": "pytest"})


def test_magistrate_schema_requires_evidence_citations() -> None:
    with pytest.raises(ValidationError):
        MagistrateOutput.model_validate(
            {
                "verdict": "CLEAR",
                "finding_codes": ["CAUSAL_AND_SCOPED"],
                "required_changes": [],
            }
        )
