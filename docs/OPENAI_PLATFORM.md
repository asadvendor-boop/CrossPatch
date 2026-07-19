# OpenAI platform verification

Verified against the official OpenAI documentation on **2026-07-14** before the
runtime schemas were locked. This file records the external platform facts that
the application relies on; repository tests separately verify how CrossPatch
applies them.

## Models and effort values

The official [model catalog](https://developers.openai.com/api/docs/models)
lists these exact model IDs:

| CrossPatch seat | Model ID | Default effort | Allowed escalation path |
|---|---|---:|---|
| Prosecutor | `gpt-5.6-luna` | `low` | `low -> medium -> high` |
| Inspector | `gpt-5.6-terra` | `medium` | `medium -> high -> xhigh` |
| Counsel | `gpt-5.6-terra` | `medium` | `medium -> high -> xhigh` |
| Magistrate | `gpt-5.6-sol` | `medium` | `medium -> high -> xhigh` when explicitly remanded |
| Bailiff | `gpt-5.6-luna` | `none` | no reasoning escalation |

The catalog documents `none`, `low`, `medium`, `high`, `xhigh`, and `max` for
all three GPT-5.6 tiers. CrossPatch deliberately never selects `max`; the
product policy caps an incident at two one-step escalations per remanded seat.
`minimal` is not sent as a reasoning-effort value.

## Agents SDK and Responses API

The official [Agents SDK agent guide](https://openai.github.io/openai-agents-python/agents/)
states that OpenAI models use the Responses API by default and exposes agents,
structured output types, handoffs, guardrails, and `mcp_servers`. The
[model guide](https://openai.github.io/openai-agents-python/models/) documents
`ModelSettings(reasoning=Reasoning(effort=...))`. CrossPatch pins
`openai-agents` in `uv.lock`, configures every model and effort explicitly, and
does not depend on SDK model defaults.

The official [running agents guide](https://developers.openai.com/api/docs/guides/agents/running-agents)
documents SDK sessions, `Runner.run_streamed(...)`, incremental run events, and
resuming a paused run from retained state. The official
[guardrails and human review guide](https://developers.openai.com/api/docs/guides/agents/guardrails-approvals)
documents `needs_approval=True`, tool-call interruptions, approve or reject
decisions, and resuming the same run from its state. CrossPatch exercises these
SDK surfaces in its agent adapter and integration contracts. Its human warrant
approval and deterministic broker remain separate authority boundaries; SDK
approval is not sufficient to authorize mutation.

The SDK's [handoff guide](https://openai.github.io/openai-agents-python/handoffs/)
notes that handoffs remain within one run and that input/output guardrails apply
only to the first/final agent in a chain. Therefore CrossPatch treats SDK
guardrails as one layer only: deterministic schema, incident-local citation,
state-machine, warrant, approval, broker, and runner checks remain independent.

The [guardrail guide](https://openai.github.io/openai-agents-python/guardrails/)
also notes that hosted and MCP tools do not use the function-tool guardrail
pipeline. CrossPatch consequently enforces MCP authentication, exact tool
allowlists, sanitization, and authorization at each MCP server.

The SDK [release notes](https://openai.github.io/openai-agents-python/release/)
document explicit `ModelRefusalError` behavior in version 0.15.0 and later.
CrossPatch maps model refusal, cutoff, incomplete output, timeout, schema or
citation failure, guardrail tripwire, SDK error, and unknown outcome to the
first-class `ABSTAIN` result. None can become `CLEAR`.

## Usage and price telemetry

The [SDK usage guide](https://openai.github.io/openai-agents-python/usage/)
documents per-run and per-request token usage, including cached input tokens.
The official GPT-5.6 model pages list these text-token prices per one million
tokens on the verification date:

| Model | Input | Cached input | Output |
|---|---:|---:|---:|
| GPT-5.6 Sol | $5.00 | $0.50 | $30.00 |
| GPT-5.6 Terra | $2.50 | $0.25 | $15.00 |
| GPT-5.6 Luna | $1.00 | $0.10 | $6.00 |

The model pages also state that prompts above 272K input tokens have a 2x input
and 1.5x output multiplier, and cache writes cost 1.25x uncached input. Runtime
telemetry is therefore described as an **estimated text-token cost**, not an
invoice. The genuine-run gate rejects missing usage data and cached input but
does not claim to reproduce account billing adjustments.

## Trace privacy

The [tracing guide](https://openai.github.io/openai-agents-python/tracing/)
warns that model and tool inputs/outputs may contain sensitive data and are
included by default. The Compose runtime sets sensitive trace capture off while
retaining trace identifiers and local sanitized telemetry for auditability.
