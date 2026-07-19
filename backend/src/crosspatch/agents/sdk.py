"""Installed OpenAI Agents SDK adapter with sessions, tracing, streaming, and resume."""

from __future__ import annotations

import asyncio
import inspect
import json
import time
from collections.abc import Awaitable, Callable
from contextlib import nullcontext
from dataclasses import dataclass
from typing import Any

from agents import (
    Agent,
    HandoffCallItem,
    HandoffOutputItem,
    ModelResponse,
    OpenAIProvider,
    RunConfig,
    RunHooks,
    Runner,
    RunState,
    trace,
)
from agents.mcp import MCPServerManager
from pydantic import BaseModel

from crosspatch.agents.factory import AgentFactory
from crosspatch.agents.guardrails import SDKRunContext
from crosspatch.agents.handoffs import InspectorProsecutorContext, InspectorValidator
from crosspatch.agents.schemas import (
    AgentRunInput,
    BailiffOutput,
    BailiffRunInput,
    InspectorProsecutorResult,
    ProsecutorOutput,
    SeatOutput,
)
from crosspatch.domain.enums import Effort, Seat
from crosspatch.domain.seats import SEAT_SPECS
from crosspatch.orchestration.failures import (
    IncompleteResponse,
    InvalidSchema,
    ModelRefusal,
    SDKException,
)
from crosspatch.orchestration.sessions import IncidentSessionStore


@dataclass(frozen=True, slots=True)
class StreamNotice:
    classification: str
    incident_id: str
    seat: Seat
    phase: str
    status: str


StreamSink = Callable[[StreamNotice], Awaitable[None] | None]
_SPEC_BY_SEAT = {spec.seat: spec for spec in SEAT_SPECS}


@dataclass(frozen=True, slots=True)
class ModelCallNotice:
    """Sanitized, machine-verifiable metadata for one genuine Responses API run."""

    incident_id: str
    seat: Seat
    phase: str
    effort: Effort
    model: str
    response_id: str | None
    request_id: str | None
    latency_ms: int
    input_tokens: int
    cached_input_tokens: int
    output_tokens: int
    total_tokens: int
    schema_valid: bool
    failure_outcome: str | None

    def as_public_dict(self) -> dict[str, Any]:
        return {
            "source": "openai-responses-api",
            "seat": self.seat.value,
            "model": self.model,
            "effort": self.effort.value,
            "phase": self.phase,
            "response_id": self.response_id,
            "request_id": self.request_id,
            "latency_ms": self.latency_ms,
            "usage": {
                "input_tokens": self.input_tokens,
                "cached_input_tokens": self.cached_input_tokens,
                "output_tokens": self.output_tokens,
                "total_tokens": self.total_tokens,
            },
            "uncached": self.cached_input_tokens == 0,
            "schema_valid": self.schema_valid,
            "failure_outcome": self.failure_outcome,
        }


TelemetrySink = Callable[[ModelCallNotice], Awaitable[None] | None]


@dataclass(slots=True)
class _CapturedModelCall:
    """Private per-call timing and usage source; never serialized or published."""

    agent: Agent[Any]
    seat: Seat
    effort: Effort
    phase: str
    started_at: float
    finished_at: float | None = None
    response: ModelResponse | None = None


class _HandoffTelemetryHooks(RunHooks[InspectorProsecutorContext]):
    """Capture each SDK model call before handoff validation can fail."""

    def __init__(
        self,
        *,
        source_agent: Agent[Any],
        target_agent: Agent[Any],
        inspector_effort: Effort,
        prosecutor_effort: Effort,
        inspector_phase: str,
    ) -> None:
        self._source_agent = source_agent
        self._target_agent = target_agent
        self._inspector_effort = inspector_effort
        self._prosecutor_effort = prosecutor_effort
        self._inspector_phase = inspector_phase
        self.calls: list[_CapturedModelCall] = []

    def _identity(self, agent: Agent[Any]) -> tuple[Seat, Effort, str]:
        if agent is self._source_agent:
            return Seat.INSPECTOR, self._inspector_effort, self._inspector_phase
        if agent is self._target_agent:
            return Seat.PROSECUTOR, self._prosecutor_effort, "hypothesis-challenge"
        raise SDKException("analysis handoff invoked an agent outside the bounded graph")

    async def on_llm_start(
        self,
        context: Any,
        agent: Agent[Any],
        system_prompt: str | None,
        input_items: list[Any],
    ) -> None:
        del context, system_prompt, input_items
        seat, effort, phase = self._identity(agent)
        self.calls.append(
            _CapturedModelCall(
                agent=agent,
                seat=seat,
                effort=effort,
                phase=phase,
                started_at=time.perf_counter(),
            )
        )

    async def on_llm_end(
        self,
        context: Any,
        agent: Agent[Any],
        response: ModelResponse,
    ) -> None:
        del context
        for call in reversed(self.calls):
            if call.agent is agent and call.response is None:
                call.response = response
                call.finished_at = time.perf_counter()
                return
        raise SDKException("analysis handoff completed an untracked model call")


class AgentsSDKRuntime:
    """Use the Responses-path SDK while application code owns all authority."""

    def __init__(
        self,
        *,
        factory: AgentFactory,
        sessions: IncidentSessionStore,
        timeout_seconds: float = 240.0,
        stream_sink: StreamSink | None = None,
        telemetry_sink: TelemetrySink | None = None,
        runner: Any = Runner,
        mcp_manager_factory: Any = MCPServerManager,
        trace_factory: Any = trace,
    ) -> None:
        self._factory = factory
        self._sessions = sessions
        self._timeout_seconds = timeout_seconds
        self._stream_sink = stream_sink
        self._telemetry_sink = telemetry_sink
        self._runner = runner
        self._mcp_manager_factory = mcp_manager_factory
        self._trace_factory = trace_factory
        self._run_config = RunConfig(
            model_provider=OpenAIProvider(use_responses=True),
            trace_include_sensitive_data=False,
            workflow_name="CrossPatch incident review",
        )

    async def _notice(self, notice: StreamNotice) -> None:
        if self._stream_sink is None:
            return
        result = self._stream_sink(notice)
        if inspect.isawaitable(result):
            await result

    async def _telemetry(self, notice: ModelCallNotice) -> None:
        if self._telemetry_sink is None:
            return
        result = self._telemetry_sink(notice)
        if inspect.isawaitable(result):
            await result

    @staticmethod
    def _response_usage(
        response: ModelResponse | None,
    ) -> tuple[str | None, str | None, int, int, int, int]:
        if response is None:
            return None, None, 0, 0, 0, 0
        usage = getattr(response, "usage", None)
        details = getattr(usage, "input_tokens_details", None)
        return (
            getattr(response, "response_id", None),
            getattr(response, "request_id", None),
            int(getattr(usage, "input_tokens", 0) or 0),
            int(getattr(details, "cached_tokens", 0) or 0),
            int(getattr(usage, "output_tokens", 0) or 0),
            int(getattr(usage, "total_tokens", 0) or 0),
        )

    @classmethod
    def _usage(cls, result: Any) -> tuple[str | None, str | None, int, int, int, int]:
        responses = tuple(getattr(result, "raw_responses", ()))
        response_id: str | None = None
        request_id: str | None = None
        input_tokens = 0
        cached_tokens = 0
        output_tokens = 0
        total_tokens = 0
        for response in responses:
            current = cls._response_usage(response)
            response_id = current[0] or response_id
            request_id = current[1] or request_id
            input_tokens += current[2]
            cached_tokens += current[3]
            output_tokens += current[4]
            total_tokens += current[5]
        return response_id, request_id, input_tokens, cached_tokens, output_tokens, total_tokens

    async def _record_model_call(
        self,
        *,
        result: Any,
        incident_id: str,
        seat: Seat,
        effort: Effort,
        phase: str,
        started_at: float,
        schema_valid: bool,
        failure_outcome: str | None = None,
    ) -> None:
        response_id, request_id, inputs, cached, outputs, total = self._usage(result)
        await self._telemetry(
            ModelCallNotice(
                incident_id=incident_id,
                seat=seat,
                phase=phase,
                effort=effort,
                model=_SPEC_BY_SEAT[seat].model,
                response_id=response_id,
                request_id=request_id,
                latency_ms=max(0, round((time.perf_counter() - started_at) * 1000)),
                input_tokens=inputs,
                cached_input_tokens=cached,
                output_tokens=outputs,
                total_tokens=total,
                schema_valid=schema_valid,
                failure_outcome=failure_outcome,
            )
        )

    async def _record_handoff_model_calls(
        self,
        *,
        incident_id: str,
        calls: list[_CapturedModelCall],
        failure: Exception | None,
    ) -> None:
        failed_index = len(calls) - 1 if failure is not None and calls else None
        finished_at = time.perf_counter()
        for index, call in enumerate(calls):
            response_id, request_id, inputs, cached, outputs, total = self._response_usage(
                call.response
            )
            is_failed = index == failed_index
            await self._telemetry(
                ModelCallNotice(
                    incident_id=incident_id,
                    seat=call.seat,
                    phase=call.phase,
                    effort=call.effort,
                    model=_SPEC_BY_SEAT[call.seat].model,
                    response_id=response_id,
                    request_id=request_id,
                    latency_ms=max(
                        0,
                        round(((call.finished_at or finished_at) - call.started_at) * 1000),
                    ),
                    input_tokens=inputs,
                    cached_input_tokens=cached,
                    output_tokens=outputs,
                    total_tokens=total,
                    schema_valid=not is_failed,
                    failure_outcome=type(failure).__name__ if is_failed else None,
                )
            )

    @staticmethod
    def _assert_complete(result: Any) -> None:
        for response in getattr(result, "raw_responses", ()):
            for item in getattr(response, "output", ()):
                if getattr(item, "status", None) in {
                    "in_progress",
                    "incomplete",
                    "failed",
                }:
                    raise IncompleteResponse()
                for content in getattr(item, "content", ()):
                    if getattr(content, "type", None) == "refusal":
                        raise ModelRefusal()

    async def _run_once(
        self,
        *,
        incident_id: str,
        seat: Seat,
        effort: Effort,
        phase: str,
        model_input: str | RunState,
        use_session: bool,
        run_context: SDKRunContext,
        agent: Any | None = None,
        mcp_already_connected: bool = False,
    ) -> Any:
        agent = agent or self._factory.for_seat(
            seat,
            effort=effort,
            incident_id=incident_id,
        )
        session = self._sessions.for_seat(incident_id, seat) if use_session else None
        await self._notice(
            StreamNotice("UNTRUSTED_AGENT_STREAM", incident_id, seat, phase, "started")
        )
        started_at = time.perf_counter()
        result: Any | None = None
        try:
            with self._trace_factory(
                "CrossPatch incident review",
                group_id=incident_id,
                metadata={"incident_id": incident_id, "seat": seat.value, "phase": phase},
            ):
                manager = (
                    nullcontext()
                    if mcp_already_connected
                    else self._mcp_manager_factory(agent.mcp_servers, strict=True)
                )
                async with manager:
                    async with asyncio.timeout(self._timeout_seconds):
                        result = self._runner.run_streamed(
                            agent,
                            model_input,
                            context=(None if isinstance(model_input, RunState) else run_context),
                            session=session,
                            run_config=self._run_config,
                        )
                        # The SDK preserves top-level Responses terminal events
                        # only on its streaming path. Consume every event even
                        # without a UI sink so failed/incomplete responses cannot
                        # be erased before authority validation.
                        async for _ in result.stream_events():
                            pass
            self._assert_complete(result)
        except Exception as error:
            await self._record_model_call(
                result=result,
                incident_id=incident_id,
                seat=seat,
                effort=effort,
                phase=phase,
                started_at=started_at,
                schema_valid=False,
                failure_outcome=type(error).__name__,
            )
            raise
        assert result is not None
        final_output = getattr(result, "final_output", None)
        schema_valid = isinstance(final_output, BaseModel) or bool(
            getattr(result, "interruptions", ())
        )
        await self._record_model_call(
            result=result,
            incident_id=incident_id,
            seat=seat,
            effort=effort,
            phase=phase,
            started_at=started_at,
            schema_valid=schema_valid,
        )
        await self._notice(
            StreamNotice("UNTRUSTED_AGENT_STREAM", incident_id, seat, phase, "completed")
        )
        return result

    async def run_seat(
        self,
        *,
        seat: Seat,
        effort: Effort,
        phase: str,
        request: AgentRunInput,
    ) -> SeatOutput:
        if seat is Seat.BAILIFF:
            raise SDKException("Bailiff requires the approved-warrant resume path")
        result = await self._run_once(
            incident_id=request.incident_id,
            seat=seat,
            effort=effort,
            phase=phase,
            model_input=request.model_dump_json(),
            use_session=True,
            run_context=SDKRunContext(
                incident_id=request.incident_id,
                input_seat=seat,
                output_seat=seat,
                input_phase=phase,
            ),
        )
        if getattr(result, "interruptions", ()):
            raise SDKException("read-only analysis seat unexpectedly requested approval")
        output = getattr(result, "final_output", None)
        if output is None:
            raise InvalidSchema(f"{seat.value} returned no structured output")
        return output

    async def run_inspector_to_prosecutor(
        self,
        *,
        request: AgentRunInput,
        inspector_effort: Effort,
        prosecutor_effort: Effort,
        validate_inspector: InspectorValidator,
    ) -> InspectorProsecutorResult:
        """Run the only model-to-model handoff with application validation in between."""

        transition = self._factory.inspector_to_prosecutor(
            incident_id=request.incident_id,
            inspector_effort=inspector_effort,
            prosecutor_effort=prosecutor_effort,
        )
        run_context = InspectorProsecutorContext(
            incident_id=request.incident_id,
            input_seat=Seat.INSPECTOR,
            output_seat=Seat.PROSECUTOR,
            input_phase=request.phase,
            request=request,
            validate_inspector=validate_inspector,
        )
        session = self._sessions.for_transition(
            request.incident_id,
            Seat.INSPECTOR,
            Seat.PROSECUTOR,
        )
        telemetry_hooks = _HandoffTelemetryHooks(
            source_agent=transition.starting_agent,
            target_agent=transition.target_agent,
            inspector_effort=inspector_effort,
            prosecutor_effort=prosecutor_effort,
            inspector_phase=request.phase,
        )
        failure: Exception | None = None
        try:
            await self._notice(
                StreamNotice(
                    "UNTRUSTED_AGENT_STREAM",
                    request.incident_id,
                    Seat.INSPECTOR,
                    request.phase,
                    "started",
                )
            )
            with self._trace_factory(
                "CrossPatch incident review",
                group_id=request.incident_id,
                metadata={
                    "incident_id": request.incident_id,
                    "source_seat": Seat.INSPECTOR.value,
                    "target_seat": Seat.PROSECUTOR.value,
                    "phase": "inspector-to-prosecutor-handoff",
                },
            ):
                async with self._mcp_manager_factory(
                    transition.starting_agent.mcp_servers,
                    strict=True,
                ):
                    async with asyncio.timeout(self._timeout_seconds):
                        result = self._runner.run_streamed(
                            transition.starting_agent,
                            request.model_dump_json(),
                            context=run_context,
                            hooks=telemetry_hooks,
                            # Inspector may read evidence, perform the one permitted
                            # handoff, and Prosecutor may independently read evidence
                            # before returning its structured result. Keep that graph
                            # bounded without cutting off a valid tool-assisted handoff.
                            max_turns=8,
                            session=session,
                            run_config=self._run_config,
                        )
                        async for _ in result.stream_events():
                            pass
            self._assert_complete(result)
            if getattr(result, "interruptions", ()):
                raise SDKException("analysis handoff unexpectedly requested approval")
            if run_context.inspector_output is None:
                raise SDKException("Inspector did not produce a validated handoff payload")
            if getattr(result, "last_agent", None) is not transition.target_agent:
                raise SDKException("Inspector handoff did not terminate at Prosecutor")

            new_items = tuple(getattr(result, "new_items", ()))
            handoff_calls = tuple(
                item for item in new_items if isinstance(item, HandoffCallItem)
            )
            handoff_outputs = tuple(
                item for item in new_items if isinstance(item, HandoffOutputItem)
            )
            if len(handoff_calls) != 1 or len(handoff_outputs) != 1:
                raise SDKException("analysis run did not contain exactly one SDK handoff")
            if handoff_calls[0].raw_item.name != transition.handoff.tool_name:
                raise SDKException("analysis run invoked an unexpected handoff")
            if (
                handoff_outputs[0].source_agent is not transition.starting_agent
                or handoff_outputs[0].target_agent is not transition.target_agent
            ):
                raise SDKException("analysis handoff source or target changed")

            output = getattr(result, "final_output", None)
            if not isinstance(output, ProsecutorOutput):
                raise InvalidSchema(
                    "Prosecutor returned no valid structured output after handoff"
                )
            await self._notice(
                StreamNotice(
                    "UNTRUSTED_AGENT_STREAM",
                    request.incident_id,
                    Seat.PROSECUTOR,
                    "hypothesis-challenge",
                    "completed",
                )
            )
            return InspectorProsecutorResult(
                inspector=run_context.inspector_output,
                prosecutor=output,
            )
        except Exception as error:
            failure = error
            raise
        finally:
            await self._record_handoff_model_calls(
                incident_id=request.incident_id,
                calls=telemetry_hooks.calls,
                failure=failure,
            )

    @staticmethod
    def serialize_resume_state(state: RunState) -> str:
        return state.to_string(include_tracing_api_key=False)

    @staticmethod
    def validate_bailiff_interruptions(
        interruptions: tuple[Any, ...],
        *,
        warrant_id: str,
    ) -> None:
        if len(interruptions) != 1:
            raise SDKException("Bailiff must request exactly one broker approval")
        interruption = interruptions[0]
        if interruption.name != "execute_warrant":
            raise SDKException("resume state contains an unauthorized tool")

        def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate tool argument")
                result[key] = value
            return result

        try:
            arguments = json.loads(
                interruption.arguments or "{}",
                object_pairs_hook=strict_object,
            )
        except (json.JSONDecodeError, ValueError) as error:
            raise SDKException("resume state contains malformed tool arguments") from error
        if arguments != {"id": warrant_id}:
            raise SDKException("resume state warrant does not match approval")

    async def deserialize_resume_state(
        self,
        state: str,
        *,
        incident_id: str,
        warrant_id: str,
        run_context: SDKRunContext,
        agent: Any | None = None,
    ) -> RunState:
        agent = agent or self._factory.for_seat(
            Seat.BAILIFF,
            effort=Effort.NONE,
            incident_id=incident_id,
        )
        parsed = await RunState.from_string(
            agent,
            state,
            context_override=run_context,
            strict_context=True,
        )
        self.validate_bailiff_interruptions(
            tuple(parsed.get_interruptions()),
            warrant_id=warrant_id,
        )
        return parsed

    async def execute_approved_warrant(
        self,
        *,
        incident_id: str,
        warrant_id: str,
        approval_reference: str,
    ) -> BailiffOutput:
        if not approval_reference:
            raise PermissionError("human approval reference is required")
        initial = await self._run_once(
            incident_id=incident_id,
            seat=Seat.BAILIFF,
            effort=Effort.NONE,
            phase="execute-approved",
            model_input=BailiffRunInput(warrant_id=warrant_id).model_dump_json(),
            use_session=True,
            run_context=SDKRunContext(
                incident_id=incident_id,
                input_seat=Seat.BAILIFF,
                output_seat=Seat.BAILIFF,
                input_phase="execute-approved",
                warrant_id=warrant_id,
            ),
        )
        interruptions = tuple(getattr(initial, "interruptions", ()))
        self.validate_bailiff_interruptions(interruptions, warrant_id=warrant_id)
        state_text = self.serialize_resume_state(initial.to_state())
        resume_agent = self._factory.for_seat(
            Seat.BAILIFF,
            effort=Effort.NONE,
            incident_id=incident_id,
        )
        resume_context = SDKRunContext(
            incident_id=incident_id,
            input_seat=Seat.BAILIFF,
            output_seat=Seat.BAILIFF,
            input_phase="execute-approved-resume",
            warrant_id=warrant_id,
        )
        # MCP tools are discovered only while their manager is connected.  Restore
        # the interrupted state with that same capability topology available;
        # otherwise the serialized MCP ToolApprovalItem cannot be reconstructed
        # and a valid human approval fails closed before the broker sees it.
        async with self._mcp_manager_factory(resume_agent.mcp_servers, strict=True):
            state = await self.deserialize_resume_state(
                state_text,
                incident_id=incident_id,
                warrant_id=warrant_id,
                run_context=resume_context,
                agent=resume_agent,
            )
            for interruption in state.get_interruptions():
                state.approve(interruption)
            resumed = await self._run_once(
                incident_id=incident_id,
                seat=Seat.BAILIFF,
                effort=Effort.NONE,
                phase="execute-approved-resume",
                model_input=state,
                use_session=False,
                run_context=resume_context,
                agent=resume_agent,
                mcp_already_connected=True,
            )
        output = getattr(resumed, "final_output", None)
        if not isinstance(output, BailiffOutput) or output.warrant_id != warrant_id:
            raise InvalidSchema("Bailiff returned an invalid warrant receipt")
        return output
