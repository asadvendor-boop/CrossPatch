from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any

import pytest
from agents import Model, ModelResponse, Runner, Usage
from agents.exceptions import ModelBehaviorError
from crosspatch.agents.factory import AgentFactory
from crosspatch.agents.schemas import (
    AgentRunInput,
    InspectorHandoffPayload,
    InspectorOutput,
    NoSupportedRival,
    ProsecutorOutput,
)
from crosspatch.agents.sdk import AgentsSDKRuntime, ModelCallNotice
from crosspatch.domain.enums import Effort, MechanismCode, Seat
from crosspatch.orchestration.sessions import IncidentSessionStore
from openai.types.responses import (
    Response,
    ResponseCompletedEvent,
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
    ResponseUsage,
)


class NoopMCPManager:
    def __init__(self, servers, **kwargs) -> None:
        self.servers = servers

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None


class NoopTrace(AbstractContextManager):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None


class ScriptedModel(Model):
    def __init__(self, responses: list[ModelResponse], *, before_response=None) -> None:
        self.responses = responses
        self.inputs: list[str | list[dict[str, Any]]] = []
        self.before_response = before_response

    async def get_response(
        self,
        system_instructions,
        input,
        model_settings,
        tools,
        output_schema,
        handoffs,
        tracing,
        **kwargs,
    ) -> ModelResponse:
        self.inputs.append(input)
        if self.before_response is not None:
            self.before_response()
        return self.responses.pop(0)

    async def stream_response(
        self,
        system_instructions,
        input,
        model_settings,
        tools,
        output_schema,
        handoffs,
        tracing,
        **kwargs,
    ) -> AsyncIterator:
        self.inputs.append(input)
        if self.before_response is not None:
            self.before_response()
        response = self.responses.pop(0)
        completed = Response(
            id=response.response_id or "response-scripted",
            created_at=0,
            model="gpt-5.6-luna",
            object="response",
            output=response.output,
            parallel_tool_calls=False,
            tool_choice="auto",
            tools=[],
            status="completed",
            usage=ResponseUsage(
                input_tokens=response.usage.input_tokens,
                input_tokens_details=response.usage.input_tokens_details,
                output_tokens=response.usage.output_tokens,
                output_tokens_details=response.usage.output_tokens_details,
                total_tokens=response.usage.total_tokens,
            ),
        )
        completed._request_id = response.request_id
        yield ResponseCompletedEvent(
            response=completed,
            sequence_number=0,
            type="response.completed",
        )


class FixedTransitionFactory:
    def __init__(self, transition) -> None:
        self.transition = transition

    def inspector_to_prosecutor(self, **kwargs):
        return self.transition


def factory() -> AgentFactory:
    return AgentFactory(
        evidence_mcp_url="http://evidence-mcp:8011/mcp",
        broker_mcp_url="http://broker-mcp:8012/mcp",
        evidence_token=lambda incident_id: f"evidence-token-{incident_id}",
        broker_token=lambda: "broker-token",
        origin="https://control.crosspatch.test",
    )


def response_message(payload: str, response_id: str) -> ModelResponse:
    return ModelResponse(
        output=[
            ResponseOutputMessage(
                id=f"message-{response_id}",
                content=[
                    ResponseOutputText(
                        annotations=[],
                        text=payload,
                        type="output_text",
                    )
                ],
                role="assistant",
                status="completed",
                type="message",
            )
        ],
        usage=Usage(
            requests=1,
            input_tokens=21,
            input_tokens_details={"cached_tokens": 0, "cache_write_tokens": 0},
            output_tokens=5,
            total_tokens=26,
        ),
        response_id=response_id,
        request_id="request-prosecutor",
    )


def handoff_response(tool_name: str, arguments: str) -> ModelResponse:
    return ModelResponse(
        output=[
            ResponseFunctionToolCall(
                arguments=arguments,
                call_id="handoff-call-1",
                name=tool_name,
                type="function_call",
                status="completed",
            )
        ],
        usage=Usage(
            requests=1,
            input_tokens=11,
            input_tokens_details={"cached_tokens": 2, "cache_write_tokens": 0},
            output_tokens=3,
            total_tokens=14,
        ),
        response_id="response-inspector",
        request_id="request-inspector",
    )


@pytest.mark.asyncio
async def test_real_sdk_runner_executes_one_validated_filtered_handoff(tmp_path: Path) -> None:
    transition = factory().inspector_to_prosecutor(
        incident_id="inc-1",
        inspector_effort=Effort.MEDIUM,
        prosecutor_effort=Effort.LOW,
    )
    transition.starting_agent.mcp_servers = []
    transition.target_agent.mcp_servers = []
    handoff_payload = InspectorHandoffPayload(
        mechanism=MechanismCode.CHECK_THEN_INSERT_RACE,
        evidence_ids=("ev-1",),
        falsifiers=("serialized delivery",),
    )
    prosecutor_output = ProsecutorOutput(
        root=NoSupportedRival(
            outcome="NO_SUPPORTED_RIVAL",
            counterexample_ids=("counter-1",),
            test_ids=("victim.contract",),
            evidence_ids=("ev-1",),
        )
    )
    validation_order: list[str] = []
    source_model = ScriptedModel(
        [handoff_response(transition.handoff.tool_name, handoff_payload.model_dump_json())]
    )
    target_model = ScriptedModel(
        [response_message(prosecutor_output.model_dump_json(), "response-prosecutor")],
        before_response=lambda: validation_order.append("target"),
    )
    transition.starting_agent.model = source_model
    transition.target_agent.model = target_model
    sessions = IncidentSessionStore(tmp_path / "sessions.sqlite")
    telemetry: list[ModelCallNotice] = []
    runtime = AgentsSDKRuntime(
        factory=FixedTransitionFactory(transition),
        sessions=sessions,
        telemetry_sink=telemetry.append,
        runner=Runner,
        mcp_manager_factory=NoopMCPManager,
        trace_factory=lambda *args, **kwargs: NoopTrace(),
    )

    async def validate_inspector(output: InspectorOutput) -> InspectorOutput:
        validation_order.append("validated")
        assert output.analysis == ""
        return output

    result = await runtime.run_inspector_to_prosecutor(
        request=AgentRunInput(
            incident_id="inc-1",
            scenario="webhook-race",
            candidate_plan_id="victim.duplicate-race.candidate",
            phase="mechanism-analysis",
        ),
        inspector_effort=Effort.MEDIUM,
        prosecutor_effort=Effort.LOW,
        validate_inspector=validate_inspector,
    )

    assert result.inspector == InspectorOutput(
        mechanism=MechanismCode.CHECK_THEN_INSERT_RACE,
        evidence_ids=("ev-1",),
        falsifiers=("serialized delivery",),
    )
    assert result.prosecutor == prosecutor_output
    assert validation_order == ["validated", "target"]
    assert len(source_model.inputs) == 1
    assert len(target_model.inputs) == 1
    target_input = target_model.inputs[0]
    assert isinstance(target_input, list) and len(target_input) == 1
    filtered = AgentRunInput.model_validate_json(target_input[0]["content"])
    assert filtered.phase == "hypothesis-challenge"
    assert [summary.seat for summary in filtered.prior_outputs] == [Seat.INSPECTOR]
    assert "analysis" not in json.dumps(filtered.prior_outputs[0].material)
    assert sessions.for_transition(
        "inc-1",
        Seat.INSPECTOR,
        Seat.PROSECUTOR,
    ).session_id not in {
        sessions.for_seat("inc-1", Seat.INSPECTOR).session_id,
        sessions.for_seat("inc-1", Seat.PROSECUTOR).session_id,
    }
    assert len(telemetry) == 2
    assert [notice.as_public_dict() for notice in telemetry] == [
        {
            "source": "openai-responses-api",
            "seat": "Inspector",
            "model": "gpt-5.6-terra",
            "effort": "medium",
            "phase": "mechanism-analysis",
            "response_id": "response-inspector",
            "request_id": "request-inspector",
            "latency_ms": telemetry[0].latency_ms,
            "usage": {
                "input_tokens": 11,
                "cached_input_tokens": 2,
                "output_tokens": 3,
                "total_tokens": 14,
            },
            "uncached": False,
            "schema_valid": True,
            "failure_outcome": None,
        },
        {
            "source": "openai-responses-api",
            "seat": "Prosecutor",
            "model": "gpt-5.6-luna",
            "effort": "low",
            "phase": "hypothesis-challenge",
            "response_id": "response-prosecutor",
            "request_id": "request-prosecutor",
            "latency_ms": telemetry[1].latency_ms,
            "usage": {
                "input_tokens": 21,
                "cached_input_tokens": 0,
                "output_tokens": 5,
                "total_tokens": 26,
            },
            "uncached": True,
            "schema_valid": True,
            "failure_outcome": None,
        },
    ]
    await sessions.close()


@pytest.mark.asyncio
async def test_handoff_payload_with_prose_or_extra_fields_fails_closed_before_target(
    tmp_path: Path,
) -> None:
    transition = factory().inspector_to_prosecutor(
        incident_id="inc-1",
        inspector_effort=Effort.MEDIUM,
        prosecutor_effort=Effort.LOW,
    )
    transition.starting_agent.mcp_servers = []
    transition.target_agent.mcp_servers = []
    source_model = ScriptedModel(
        [
            handoff_response(
                transition.handoff.tool_name,
                json.dumps(
                    {
                        "mechanism": "CHECK_THEN_INSERT_RACE",
                        "evidence_ids": ["ev-1"],
                        "falsifiers": ["serialized delivery"],
                        "analysis": "untrusted prose must not cross the handoff",
                    }
                ),
            )
        ]
    )
    target_model = ScriptedModel([])
    transition.starting_agent.model = source_model
    transition.target_agent.model = target_model
    telemetry: list[ModelCallNotice] = []
    runtime = AgentsSDKRuntime(
        factory=FixedTransitionFactory(transition),
        sessions=IncidentSessionStore(tmp_path / "sessions.sqlite"),
        telemetry_sink=telemetry.append,
        runner=Runner,
        mcp_manager_factory=NoopMCPManager,
        trace_factory=lambda *args, **kwargs: NoopTrace(),
    )

    with pytest.raises(ModelBehaviorError):
        await runtime.run_inspector_to_prosecutor(
            request=AgentRunInput(
                incident_id="inc-1",
                scenario="webhook-race",
                candidate_plan_id="victim.duplicate-race.candidate",
                phase="mechanism-analysis",
            ),
            inspector_effort=Effort.MEDIUM,
            prosecutor_effort=Effort.LOW,
            validate_inspector=lambda output: output,
        )

    assert target_model.inputs == []
    assert len(telemetry) == 1
    notice = telemetry[0]
    assert notice.seat is Seat.INSPECTOR
    assert notice.model == "gpt-5.6-terra"
    assert notice.effort is Effort.MEDIUM
    assert notice.phase == "mechanism-analysis"
    assert notice.response_id == "response-inspector"
    assert notice.request_id == "request-inspector"
    assert notice.input_tokens == 11
    assert notice.cached_input_tokens == 2
    assert notice.output_tokens == 3
    assert notice.total_tokens == 14
    assert notice.schema_valid is False
    assert notice.failure_outcome == "ModelBehaviorError"
