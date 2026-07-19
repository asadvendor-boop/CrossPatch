from __future__ import annotations

import pytest
from crosspatch.runtime.scenarios import (
    LIVE_TRIAL_SCENARIOS,
    OPERATOR_SCENARIOS,
    require_live_trial_scenario,
    require_operator_scenario,
)


def test_operator_registry_is_closed_and_live_trials_remain_race_only() -> None:
    assert tuple(OPERATOR_SCENARIOS) == (
        "webhook-race",
        "webhook-payload-equivalence",
    )
    assert LIVE_TRIAL_SCENARIOS == frozenset({"webhook-race"})

    race = require_operator_scenario("webhook-race")
    assert race.default_title == "Duplicate order-paid delivery"
    assert race.affected_plan_id == "victim.duplicate-race.affected"
    assert race.candidate_plan_id == "victim.duplicate-race.candidate"
    assert race.reproduction_profile == "duplicate-race"

    equivalence = require_operator_scenario("webhook-payload-equivalence")
    assert equivalence.default_title == "Equivalent webhook retry rejected"
    assert equivalence.affected_plan_id == "victim.payload-equivalence.affected"
    assert equivalence.candidate_plan_id == "victim.payload-equivalence.candidate"
    assert equivalence.reproduction_profile == "payload-equivalence"

    with pytest.raises(ValueError, match="unsupported incident scenario"):
        require_operator_scenario("model-authored")
    with pytest.raises(ValueError, match="live trials support only"):
        require_live_trial_scenario("webhook-payload-equivalence")


def test_scenario_registry_and_source_paths_are_immutable() -> None:
    expected_sources = (
        "victim/src/victim/app.py",
        "victim/src/victim/db.py",
        "victim/src/victim/webhooks.py",
        "victim/src/victim/worker.py",
    )
    assert all(
        definition.source_paths == expected_sources
        for definition in OPERATOR_SCENARIOS.values()
    )

    with pytest.raises(TypeError):
        OPERATOR_SCENARIOS["model-authored"] = OPERATOR_SCENARIOS["webhook-race"]


@pytest.mark.parametrize("value", ["", "WEBHOOK-RACE", "webhook-race ", "webhook"])
def test_scenario_lookup_never_normalizes_or_partially_matches(value: str) -> None:
    with pytest.raises(ValueError, match="unsupported incident scenario"):
        require_operator_scenario(value)

