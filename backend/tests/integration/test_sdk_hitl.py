from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from agents import Agent, Model, ModelResponse, Runner, Usage, function_tool
from crosspatch.agents.factory import AgentFactory
from crosspatch.agents.schemas import BailiffOutput
from crosspatch.agents.sdk import AgentsSDKRuntime
from crosspatch.domain.enums import Effort, Seat
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
    entered = 0

    def __init__(self, servers, **kwargs) -> None:
        self.servers = servers

    async def __aenter__(self):
        type(self).entered += 1
        return self

    async def __aexit__(self, *args):
        return None


class ScriptedBailiffModel(Model):
    def __init__(self, responses: list[ModelResponse]) -> None:
        self.responses = responses
        self.inputs: list[str | list[dict[str, Any]]] = []

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


def tool_call(warrant_id: str) -> ModelResponse:
    return ModelResponse(
        output=[
            ResponseFunctionToolCall(
                arguments=f'{{"id":"{warrant_id}"}}',
                call_id="execute-call-1",
                name="execute_warrant",
                type="function_call",
                status="completed",
            )
        ],
        usage=Usage(),
        response_id="response-before-approval",
    )


def final_message(warrant_id: str) -> ModelResponse:
    payload = BailiffOutput(warrant_id=warrant_id).model_dump_json()
    return ModelResponse(
        output=[
            ResponseOutputMessage(
                id="message-after-approval",
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
        usage=Usage(),
        response_id="response-after-approval",
    )


class BailiffFactory:
    def __init__(self, model: Model, execute_tool) -> None:
        self._base = AgentFactory(
            evidence_mcp_url="http://evidence-mcp:8011/mcp",
            broker_mcp_url="http://broker-mcp:8012/mcp",
            evidence_token=lambda incident_id: f"evidence-token-{incident_id}",
            broker_token=lambda: "broker-token",
            origin="https://control.crosspatch.test",
        )
        self._model = model
        self._execute_tool = execute_tool

    def for_seat(
        self,
        seat: Seat,
        *,
        effort: Effort | None = None,
        incident_id: str | None = None,
    ) -> Agent:
        agent = self._base.for_seat(
            seat,
            effort=effort,
            incident_id=incident_id,
        )
        return agent.clone(
            model=self._model,
            mcp_servers=[],
            tools=[self._execute_tool],
        )


@pytest.mark.asyncio
async def test_real_sdk_hitl_interrupt_round_trip_executes_only_after_resume(
    tmp_path: Path,
) -> None:
    NoopMCPManager.entered = 0
    calls: list[str] = []

    @function_tool(name_override="execute_warrant", needs_approval=True)
    async def execute_for_test(id: str) -> str:
        """Execute one test warrant after SDK approval."""

        calls.append(id)
        return '{"status":"PASSED"}'

    model = ScriptedBailiffModel(
        [tool_call("warrant-1"), final_message("warrant-1")]
    )
    sessions = IncidentSessionStore(tmp_path / "sessions.sqlite")
    runtime = AgentsSDKRuntime(
        factory=BailiffFactory(model, execute_for_test),  # type: ignore[arg-type]
        sessions=sessions,
        runner=Runner,
        mcp_manager_factory=NoopMCPManager,
        trace_factory=lambda *args, **kwargs: _NoopTrace(),
    )

    output = await runtime.execute_approved_warrant(
        incident_id="inc-1",
        warrant_id="warrant-1",
        approval_reference="apr-1",
    )

    assert calls == ["warrant-1"]
    assert output == BailiffOutput(warrant_id="warrant-1")
    assert len(model.inputs) == 2
    assert NoopMCPManager.entered == 2
    await sessions.close()


class _NoopTrace:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None
