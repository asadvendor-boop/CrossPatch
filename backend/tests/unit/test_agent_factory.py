from __future__ import annotations

from crosspatch.agents.factory import AgentFactory
from crosspatch.agents.prompts import cache_prefix, instructions_for, prompt_cache_key
from crosspatch.agents.schemas import (
    AgentRunInput,
    BailiffOutput,
    CounselOutput,
    InspectorOutput,
    MagistrateOutput,
    ProsecutorOutput,
)
from crosspatch.domain.enums import Effort, Seat
from crosspatch.runtime.scenarios import OPERATOR_SCENARIOS


def factory() -> AgentFactory:
    return AgentFactory(
        evidence_mcp_url="http://evidence-mcp:8011/mcp",
        broker_mcp_url="http://broker-mcp:8012/mcp",
        evidence_token=lambda incident_id: f"evidence-token-{incident_id}",
        broker_token=lambda: "broker-token",
        origin="https://control.crosspatch.test",
    )


def test_seat_order_models_and_initial_efforts_are_exact() -> None:
    specs = factory().agent_specs

    assert [(spec.seat, spec.model, spec.initial_effort.value) for spec in specs] == [
        (Seat.PROSECUTOR, "gpt-5.6-luna", "low"),
        (Seat.INSPECTOR, "gpt-5.6-terra", "medium"),
        (Seat.COUNSEL, "gpt-5.6-terra", "medium"),
        (Seat.MAGISTRATE, "gpt-5.6-sol", "medium"),
        (Seat.BAILIFF, "gpt-5.6-luna", "none"),
    ]


def test_sdk_agents_have_exact_models_efforts_outputs_and_mcp_boundaries() -> None:
    agent_factory = factory()
    expected_outputs = {
        Seat.PROSECUTOR: ProsecutorOutput,
        Seat.INSPECTOR: InspectorOutput,
        Seat.COUNSEL: CounselOutput,
        Seat.MAGISTRATE: MagistrateOutput,
        Seat.BAILIFF: BailiffOutput,
    }
    expected_max_output_tokens = {
        Seat.PROSECUTOR: 3_072,
        Seat.INSPECTOR: 3_072,
        Seat.COUNSEL: 6_144,
        Seat.MAGISTRATE: 8_192,
        Seat.BAILIFF: 768,
    }

    for spec in agent_factory.agent_specs:
        agent = agent_factory.for_seat(
            spec.seat,
            incident_id="inc-agent-factory",
        )
        assert agent.name == spec.seat.value
        assert agent.model == spec.model
        assert agent.model_settings.reasoning.effort == spec.initial_effort.value
        assert agent.model_settings.max_tokens == expected_max_output_tokens[spec.seat]
        assert agent.model_settings.extra_args == {
            "prompt_cache_key": prompt_cache_key("inc-agent-factory")
        }
        assert agent.model_settings.store is False
        assert agent.model_settings.retry is not None
        assert agent.model_settings.retry.max_retries == 0
        assert agent.output_type is expected_outputs[spec.seat]
        assert agent.tools == []
        assert agent.handoffs == []
        assert [guardrail.get_name() for guardrail in agent.input_guardrails] == [
            "crosspatch_typed_model_input"
        ]
        assert [guardrail.get_name() for guardrail in agent.output_guardrails] == [
            "crosspatch_typed_model_output"
        ]

        if spec.seat is Seat.BAILIFF:
            assert [server.name for server in agent.mcp_servers] == ["crosspatch-broker"]
            assert agent_factory.visible_mcp_tools(agent) == ("execute_warrant",)
            assert agent.mcp_servers[0].tool_filter == {
                "allowed_tool_names": ["execute_warrant"]
            }
        else:
            assert [server.name for server in agent.mcp_servers] == ["crosspatch-evidence"]
            assert agent_factory.visible_mcp_tools(agent) == (
                "list_incident_evidence",
                "get_sanitized_artifact",
                "search_source",
                "get_source_blob",
                "list_test_catalog",
                "get_test_result",
                "get_incident_timeline",
            )
            assert agent.mcp_servers[0].tool_filter == {
                "allowed_tool_names": list(agent_factory.visible_mcp_tools(agent))
            }

    magistrate = agent_factory.for_seat(
        Seat.MAGISTRATE,
        incident_id="inc-agent-factory",
    )
    assert "crosspatch-broker" not in [server.name for server in magistrate.mcp_servers]


def test_all_seats_share_one_front_loaded_cache_prefix() -> None:
    instructions = {spec.seat: instructions_for(spec.seat) for spec in factory().agent_specs}
    prefix_marker = "CROSSPATCH_STATIC_AGENT_CONTRACT_V4"

    assert all(instruction.startswith(prefix_marker) for instruction in instructions.values())
    assert all(len(instruction) >= 4_096 for instruction in instructions.values())
    assert all("UNTRUSTED_EVIDENCE" in instruction for instruction in instructions.values())
    assert all("crosspatch.agent-input.v1" in instruction for instruction in instructions.values())
    assert instructions[Seat.INSPECTOR] != instructions[Seat.COUNSEL]


def test_scenarios_seats_and_escalations_share_one_byte_identical_cache_prefix() -> None:
    stable = cache_prefix().encode("utf-8")
    observed_prefixes = []
    dynamic_inputs = set()

    for scenario, definition in OPERATOR_SCENARIOS.items():
        request = AgentRunInput(
            incident_id=f"inc-{scenario}",
            scenario=definition.scenario_id,
            candidate_plan_id=definition.candidate_plan_id,
            phase="mechanism-analysis",
        )
        dynamic_inputs.add(request.model_dump_json().encode("utf-8"))
        assert request.scenario == scenario
        assert request.candidate_plan_id == definition.candidate_plan_id

        for seat in Seat:
            for _effort in Effort:
                rendered = instructions_for(seat).encode("utf-8")
                observed_prefixes.append(rendered[: len(stable)])

    assert set(observed_prefixes) == {stable}
    assert len(dynamic_inputs) == len(OPERATOR_SCENARIOS)


def test_review_instructions_copy_dynamic_plan_without_hardcoded_catalog_id() -> None:
    counsel = instructions_for(Seat.COUNSEL)
    magistrate = instructions_for(Seat.MAGISTRATE)

    assert "candidate_plan_id" in counsel
    assert "copy" in counsel.lower()
    assert "server-owned candidate plan in typed input" in magistrate
    for definition in OPERATOR_SCENARIOS.values():
        assert definition.candidate_plan_id not in counsel
        assert definition.candidate_plan_id not in magistrate


def test_magistrate_defers_exact_patch_application_to_trusted_broker() -> None:
    instructions = instructions_for(Seat.MAGISTRATE)

    assert "Do not require actual post-image Git blob IDs" in instructions
    assert "trusted broker verifies and applies the exact hash-bound bytes" in instructions


def test_incident_cache_key_is_deterministic_scoped_and_within_responses_limit() -> None:
    first = prompt_cache_key("inc_0123456789abcdef0123456789abcdef")
    second = prompt_cache_key("inc_fedcba9876543210fedcba9876543210")

    assert first == prompt_cache_key("inc_0123456789abcdef0123456789abcdef")
    assert first != second
    assert len(first) <= 64


def test_bailiff_broker_mcp_is_sdk_approval_resumable_defense_in_depth() -> None:
    bailiff = factory().for_seat(Seat.BAILIFF)
    server = bailiff.mcp_servers[0]

    assert server._needs_approval_policy is True
    assert server.params["headers"]["Authorization"] == "Bearer broker-token"
    assert server.params["headers"]["Origin"] == "https://control.crosspatch.test"
    assert server.params["timeout"] == 180
    assert server.client_session_timeout_seconds == 180


def test_inspector_to_prosecutor_is_one_forced_bounded_sdk_handoff() -> None:
    transition = factory().inspector_to_prosecutor(
        incident_id="inc-agent-factory",
        inspector_effort=Effort.MEDIUM,
        prosecutor_effort=Effort.LOW,
    )

    assert transition.starting_agent.name == Seat.INSPECTOR.value
    assert transition.target_agent.name == Seat.PROSECUTOR.value
    assert transition.starting_agent.handoffs == [transition.handoff]
    assert transition.target_agent.handoffs == []
    assert transition.handoff.agent_name == Seat.PROSECUTOR.value
    assert transition.handoff.tool_name == "transfer_inspector_finding_to_prosecutor"
    assert transition.starting_agent.model_settings.tool_choice == transition.handoff.tool_name
    assert transition.starting_agent.model_settings.parallel_tool_calls is False
    assert transition.target_agent.model_settings.parallel_tool_calls is False
    assert transition.handoff.tool_name in transition.starting_agent.instructions
    assert transition.starting_agent.mcp_servers[0] is transition.target_agent.mcp_servers[0]
    assert [server.name for server in transition.starting_agent.mcp_servers] == [
        "crosspatch-evidence"
    ]
    assert "crosspatch-broker" not in {
        server.name
        for agent in (transition.starting_agent, transition.target_agent)
        for server in agent.mcp_servers
    }
    schema = transition.handoff.input_json_schema
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {"mechanism", "evidence_ids", "falsifiers"}


def test_analysis_agents_receive_distinct_incident_bound_evidence_credentials() -> None:
    agent_factory = factory()

    first = agent_factory.for_seat(Seat.INSPECTOR, incident_id="inc-a")
    second = agent_factory.for_seat(Seat.INSPECTOR, incident_id="inc-b")

    assert first.mcp_servers[0].params["headers"]["Authorization"] == (
        "Bearer evidence-token-inc-a"
    )
    assert second.mcp_servers[0].params["headers"]["Authorization"] == (
        "Bearer evidence-token-inc-b"
    )
