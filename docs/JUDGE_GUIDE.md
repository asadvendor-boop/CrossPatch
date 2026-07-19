# Judge guide

CrossPatch is designed to be inspected, not merely watched. Judges can use the
hosted web incident room, a tiny HTTP/SSE CLI, a signed incident export, or the
read-only Judge MCP server from Codex or another Streamable HTTP MCP client.

## Fast path

1. Open the hosted URL supplied in the submission.
2. Open the featured payload-equivalence incident.
3. Keep the timeline visible while following `REMAND`, bounded escalation,
   `CLEAR`, human approval, and the trusted `1 / 1 / 1` receipt.
4. Inspect each specialist card for exact model, role, live effort, and
   escalation count.
5. Open the diff/test evidence and compare its artifact IDs to the timeline.
6. Inspect the pending warrant hash and bound fields. Approval is intentionally
   unavailable for `REMAND`, `BLOCK`, or `ABSTAIN`.
7. Use Judge MCP to ask the same questions independently.
8. Download the incident export and run the bundled verifier.

No demo feed is seeded. If the room is empty, use the sample setup command to
open a real incident; do not expect pre-authored timeline output.

## Judge MCP connection

Endpoint:

```text
https://HOST/mcp/judge
```

Transport: MCP Streamable HTTP. Authentication: `Authorization: Bearer TOKEN`.
The public Caddy route explicitly rewrites `/mcp/judge` to the private server's
`/mcp` endpoint. Port `8013` is not published to the host.

Example client configuration (adapt the field names to your MCP client):

```json
{
  "mcpServers": {
    "crosspatch-judge": {
      "type": "streamable-http",
      "url": "https://HOST/mcp/judge",
      "headers": {
        "Authorization": "Bearer TOKEN"
      }
    }
  }
}
```

The supplied token is read-only, revocable, audience scoped, and intended to
remain valid through at least `2026-08-13T07:00:00Z`. The hosted/default token is
publication-bounded: issue it with `crosspatch judge-token rotate`, and the same
bearer can list and read all explicitly published cases. It cannot read any
unpublished or in-flight incident. A private deployment may opt into
`CROSSPATCH_JUDGE_INCIDENT_SCOPED=1` and issue a narrower token with
`crosspatch judge-token rotate INCIDENT_ID`. Do not paste either token into a
public issue, recording, or repository.

The same registered bearer can establish replacement MCP sessions after a
client restart, clean disconnect, idle timeout, or lost initialization response.
Every session remains bound to the token identity and origin, and registry
revocation is checked on every request. This reuse applies only to Judge MCP;
Evidence and Broker bearer tokens remain single-session.

## Exact Judge MCP surface

Tools:

- `list_incidents()`
- `get_case_file(incident_id)`
- `get_verdicts(incident_id)`
- `search_evidence(incident_id, query)`
- `get_sanitized_evidence(incident_id, evidence_id)`
- `get_warrant_log(incident_id)`
- `verify_artifact_manifest(incident_id)`

Resource templates:

- `crosspatch://incidents/{id}/summary`
- `crosspatch://incidents/{id}/timeline`
- `crosspatch://incidents/{id}/verdicts`
- `crosspatch://incidents/{id}/warrants`

`list_incidents()` returns every explicitly published case in the default hosted
configuration. Every response comes only from the transactionally published,
sanitized projection. An unpublished/in-flight incident has no readable Judge
projection even when its ID is known. Optional incident-scoped mode filters this
published set to the one incident in the bearer.
Only terminal, verified operator incidents enter this set. A live trial remains
private after it reaches `VERIFIED`; it is visible only to its owning live-trial
credential and authorized control-plane operators, never to Judge MCP browsing.
Judge MCP cannot retrieve raw bytes or paths, reveal credentials, approve/reject
a warrant, run a test, invoke the Bailiff, mutate a worktree, or open a shell.

## Optional live trial

The submission may also provide a separate live-trial API bearer. It is not the
Judge MCP token. It can open only the bundled webhook-race trial, run the five
configured GPT-5.6 seats, and choose `APPROVE`, `REJECT` with a reason, or
`REQUEST_REVISION` with comments for its own incidents. Approval still consumes
an exact hash-bound warrant and execution stays inside the disposable sandbox.
A revision sanitizes the comment as untrusted evidence, escalates Counsel by one
configured effort step, reruns the challenge/verdict cycle, and requires a new
`CLEAR` before a fresh warrant appears.

Trial requests are per-credential rate limited and share one global deployment
spend ceiling (USD 20 by default). A clear 429 response means live model work is
closed for the limit; published Judge browsing remains available. Even a
successfully verified trial remains private and never appears in
`list_incidents()` on Judge MCP.

## Suggested interrogation

Use these prompts from your own client:

1. “List published incidents and identify the webhook-race incident.”
2. “For incident ID X, summarize the causal mechanism and cite the evidence IDs.”
3. “Show every Prosecutor rival outcome. Did it argue a supported rival or record
   `NO_SUPPORTED_RIVAL`?”
4. “List all failed deterministic tests, their timestamps, and the revision that
   followed each failure.”
5. “Show each effort escalation and verify it was triggered only by `REMAND` or a
   deterministic test failure.”
6. “Compare the semantic fingerprints before and after each retry and identify
   duplicate higher-effort output.”
7. “Show the Magistrate verdict history. Confirm refusals/incomplete output would
   be `ABSTAIN` and produce no warrant.”
8. “List every field bound into the approved warrant and show its single-use
   execution log.”
9. “Verify the published artifact manifest and report any missing or mismatched
   hashes.”
10. “Can this MCP server approve, execute, access raw evidence, or run tests?
    Enumerate the actual tools as evidence.”

## CLI access

The CLI uses the same authenticated REST/SSE surface as the UI. Its API reader
token is a separate credential from the Judge MCP bearer: the reader token is
sent to `/api/*`, while the Judge MCP bearer is audience-bound to
`/mcp/judge`. The judge handoff must provide both without reusing either value.

```bash
export CROSSPATCH_API_URL=https://HOST
export CROSSPATCH_TOKEN=API_READER_TOKEN
uv run crosspatch room stream INCIDENT_ID
uv run crosspatch case export INCIDENT_ID --output crosspatch-incident.zip
```

Read-only credentials cannot open an incident or approve/reject a warrant. The
CLI never connects to PostgreSQL or a runner.

## Run locally

Prerequisites: Docker Desktop with Compose v2, Git, Node.js 22.12 or newer, and
`uv`. An OpenAI API key with access to the configured GPT-5.6 tiers is required
only for new live specialist runs; keyless replay and verification remain
available without it.

Verified platforms are macOS on Apple Silicon and Ubuntu Linux on x86-64 (the
latter is exercised by CI). Native Windows is unverified. Use WSL2 only after
testing Docker, filesystem permissions, and the full `make judge` gate there.

```bash
git clone REPOSITORY_URL
cd CrossPatch
cp .env.example .env
# Set OPENAI_API_KEY in .env for live specialist runs.
docker compose up --build
./scripts/setup-sample-incident.sh
```

Open <https://localhost>. A local self-signed certificate warning is expected.
Without an OpenAI key, the app remains inspectable but orchestration fails closed
to `ABSTAIN`; it does not create substitute output.

## Verify the release

```bash
./scripts/verify-release.sh --strict
```

Then inspect:

- `artifacts/verification/release-summary.json`
- `artifacts/verification/demo-readiness.json`
- `artifacts/verification/hosted-acceptance.json`
- `artifacts/verification/github-license.json`
- `docs/CLAIM_MAP.json`

Each material claim points to a non-empty machine-generated artifact and exact
SHA-256. `BLOCKED` is an honest state for unavailable external authority; it is
not treated as a pass.

### Verify a downloaded export with its recorded key lineage

The hosted UI links the same additive public-key set directly:

- `/verification/production-export-public-key.json` for production exports,
  fingerprint `9fc05d3c32c1b276a3e59f699ad73b8f9f332cc608ece3c8f5fd2cb2b665bc7d`;
- `/verification/sealed-cohort-export-public-key.json` for the historical paced
  cohort, fingerprint
  `949bed254068654a5d5c125079c4631055709fafcac92e097b02a08cd87f9875`;
- `/verification/export-public-keys.json` for the source-artifact SHA, runtime
  Git SHA, and verified runtime proof provenance behind both public files.

Pin the expected fingerprint before calling `crosspatch.export.verify_export`.
The two keys intentionally differ: adding the production key preserves, rather
than replaces, sealed-cohort verification. No private signing material is
distributed.

## What the demonstrated failure-first run shows

- The affected revision is observed through signed HTTP and PostgreSQL as real
  `1 receipt / 2 jobs / 2 deliveries` state.
- The Inspector cites sanitized evidence; the Prosecutor challenges the causal
  account; the Counsel supplies a minimal diff.
- The deterministic runner—not a model—tests the candidate externally.
- A genuine `REMAND` blocks authority and moves the responsible seat exactly one
  effort step higher before a materially different proposal returns for review.
- The Magistrate returns one exact verdict. Any refusal/cutoff is `ABSTAIN`.
- `CLEAR` creates a pending warrant but nothing changes until explicit human
  approval of its displayed hash.
- The Bailiff supplies only the warrant ID; the broker validates every predicate
  and performs the fixed operation once.
- Judge MCP and the signed export let you verify the same incident independently.

The post-approval fail→repair path is implemented and test-pinned, but no
candidate failed after approval in the sealed ten-run cohort. CrossPatch does not
manufacture that failure for a demo.

## Known external dependencies

The owner must keep hosting, DNS, TLS, monitoring, token access, repository judge
sharing, and credits active through the judging window. Consult
[DEPLOYMENT.md](DEPLOYMENT.md) for the exact operational acceptance checks and
[SECURITY.md](../SECURITY.md) for trust boundaries.
