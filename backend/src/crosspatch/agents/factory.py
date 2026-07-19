"""Exact OpenAI Agents SDK objects and capability topology."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from agents import Agent, ModelRetrySettings, ModelSettings
from agents.handoffs import Handoff
from agents.mcp import MCPServerStreamableHttp, create_static_tool_filter
from agents.model_settings import Reasoning

from crosspatch.agents.guardrails import (
    typed_model_input_guardrail,
    typed_model_output_guardrail,
)
from crosspatch.agents.handoffs import inspector_to_prosecutor_handoff
from crosspatch.agents.prompts import instructions_for, prompt_cache_key
from crosspatch.agents.schemas import (
    BailiffOutput,
    CounselOutput,
    InspectorOutput,
    MagistrateOutput,
    ProsecutorOutput,
)
from crosspatch.domain.enums import Effort, Seat
from crosspatch.domain.seats import SEAT_SPECS, SeatSpec
from crosspatch.mcp.broker_server import BROKER_TOOL_ALLOWLIST
from crosspatch.mcp.evidence_server import EVIDENCE_TOOL_ALLOWLIST

TokenProvider = Callable[[], str]
IncidentTokenProvider = Callable[[str], str]

_OUTPUT_TYPES = {
    Seat.PROSECUTOR: ProsecutorOutput,
    Seat.INSPECTOR: InspectorOutput,
    Seat.COUNSEL: CounselOutput,
    Seat.MAGISTRATE: MagistrateOutput,
    Seat.BAILIFF: BailiffOutput,
}
_SPECS_BY_SEAT = {spec.seat: spec for spec in SEAT_SPECS}
_BROKER_MCP_TIMEOUT_SECONDS = 180


@dataclass(frozen=True, slots=True)
class InspectorProsecutorAgents:
    starting_agent: Agent[Any]
    target_agent: Agent[Any]
    handoff: Handoff[Any, Agent[Any]]


class AgentFactory:
    def __init__(
        self,
        *,
        evidence_mcp_url: str,
        broker_mcp_url: str,
        evidence_token: IncidentTokenProvider,
        broker_token: TokenProvider,
        origin: str,
    ) -> None:
        self._evidence_mcp_url = evidence_mcp_url
        self._broker_mcp_url = broker_mcp_url
        self._evidence_token = evidence_token
        self._broker_token = broker_token
        self._origin = origin

    @property
    def agent_specs(self) -> tuple[SeatSpec, ...]:
        return SEAT_SPECS

    def _headers(self, provider: TokenProvider) -> dict[str, str]:
        token = provider()
        if not token.strip():
            raise ValueError("MCP service token must not be blank")
        return {"Authorization": f"Bearer {token}", "Origin": self._origin}

    def _evidence_server(self, incident_id: str) -> MCPServerStreamableHttp:
        if not incident_id:
            raise ValueError("Evidence MCP requires an incident binding")
        return MCPServerStreamableHttp(
            name="crosspatch-evidence",
            params={
                "url": self._evidence_mcp_url,
                "headers": self._headers(lambda: self._evidence_token(incident_id)),
                "terminate_on_close": True,
            },
            cache_tools_list=True,
            tool_filter=create_static_tool_filter(
                allowed_tool_names=list(EVIDENCE_TOOL_ALLOWLIST)
            ),
            use_structured_content=True,
            max_retry_attempts=0,
            require_approval="never",
        )

    def _broker_server(self) -> MCPServerStreamableHttp:
        return MCPServerStreamableHttp(
            name="crosspatch-broker",
            params={
                "url": self._broker_mcp_url,
                "headers": self._headers(self._broker_token),
                "terminate_on_close": True,
                "timeout": _BROKER_MCP_TIMEOUT_SECONDS,
            },
            cache_tools_list=True,
            tool_filter=create_static_tool_filter(
                allowed_tool_names=list(BROKER_TOOL_ALLOWLIST)
            ),
            use_structured_content=True,
            max_retry_attempts=0,
            require_approval="always",
            client_session_timeout_seconds=_BROKER_MCP_TIMEOUT_SECONDS,
        )

    def for_seat(
        self,
        seat: Seat,
        *,
        effort: Effort | None = None,
        incident_id: str | None = None,
    ) -> Agent:
        spec = _SPECS_BY_SEAT[seat]
        selected_effort = effort or spec.initial_effort
        if selected_effort not in spec.effort_ladder:
            raise ValueError(f"{selected_effort.value} is outside the {seat.value} effort policy")
        if seat is Seat.BAILIFF:
            mcp_servers = [self._broker_server()]
        else:
            if incident_id is None:
                raise ValueError("analysis seats require an incident-scoped credential")
            mcp_servers = [self._evidence_server(incident_id)]
        return Agent(
            name=seat.value,
            handoff_description=spec.role,
            instructions=instructions_for(seat),
            model=spec.model,
            model_settings=ModelSettings(
                max_tokens=spec.max_output_tokens,
                reasoning=Reasoning(effort=selected_effort.value),
                store=False,
                metadata={"crosspatch_seat": seat.value},
                extra_args={"prompt_cache_key": prompt_cache_key(incident_id)},
                retry=ModelRetrySettings(max_retries=0),
            ),
            output_type=_OUTPUT_TYPES[seat],
            tools=[],
            mcp_servers=mcp_servers,
            handoffs=[],
            input_guardrails=[typed_model_input_guardrail],
            output_guardrails=[typed_model_output_guardrail],
        )

    def inspector_to_prosecutor(
        self,
        *,
        incident_id: str,
        inspector_effort: Effort,
        prosecutor_effort: Effort,
    ) -> InspectorProsecutorAgents:
        """Build the sole handoff graph with one shared read-only MCP connection."""

        evidence_server = self._evidence_server(incident_id)
        target = self.for_seat(
            Seat.PROSECUTOR,
            effort=prosecutor_effort,
            incident_id=incident_id,
        ).clone(
            mcp_servers=[evidence_server],
        )
        target.model_settings = replace(
            target.model_settings,
            parallel_tool_calls=False,
        )
        handoff = inspector_to_prosecutor_handoff(target)
        starting = self.for_seat(
            Seat.INSPECTOR,
            effort=inspector_effort,
            incident_id=incident_id,
        ).clone(
            mcp_servers=[evidence_server],
            handoffs=[handoff],
            instructions=(
                f"{instructions_for(Seat.INSPECTOR)}\n\n"
                f"For this initial transition, call {handoff.tool_name} exactly once with only "
                "the material mechanism, evidence identifiers, and falsifiers."
            ),
        )
        starting.model_settings = replace(
            starting.model_settings,
            tool_choice=handoff.tool_name,
            parallel_tool_calls=False,
        )
        return InspectorProsecutorAgents(
            starting_agent=starting,
            target_agent=target,
            handoff=handoff,
        )

    @staticmethod
    def visible_mcp_tools(agent: Agent) -> tuple[str, ...]:
        names = tuple(server.name for server in agent.mcp_servers)
        if names == ("crosspatch-evidence",):
            return EVIDENCE_TOOL_ALLOWLIST
        if names == ("crosspatch-broker",):
            return BROKER_TOOL_ALLOWLIST
        return ()
