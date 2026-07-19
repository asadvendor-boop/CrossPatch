# CrossPatch security policy

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could expose tokens, raw
evidence, another incident, or mutation authority. Send the repository owner a
private report containing the affected commit, a minimal reproduction, impact,
and suggested containment. Revoke affected judge/operator credentials and stop
new approvals while the report is investigated.

CrossPatch is a hackathon prototype, not a managed production incident-response
service. Use only disposable repositories and data in the shipped sandbox.

## Security invariants

These are acceptance conditions, not aspirations:

1. A model never writes a worktree, runs a test, selects argv, opens a shell, or
   performs a mutation.
2. The Bailiff exposes exactly one tool: `execute_warrant(id)`.
3. Only a Magistrate `CLEAR` can produce a warrant. Refusal, cutoff, incomplete
   output, timeout, schema/citation failure, SDK error, guardrail stop, and unknown
   output are `ABSTAIN` and cannot create one.
4. Approval is explicit, single-use, expiring, and bound to the complete canonical
   warrant. Any byte-level drift invalidates it.
5. Validation and nonce consumption occur atomically against database time. The
   broker stays fail closed during concurrency, restart, or dependency failure.
6. Candidate code runs as an irreversibly demoted UID/GID 10002 child with no
   supplementary groups or capabilities and a read-only workspace. It shares
   the disposable executor container's private PID namespace; the whole
   container is recycled per attempt, and no receipt is released before an
   authenticated replacement boot. The child has no container-runtime or
   control-socket authority, trusted context, or trusted receipt path.
7. Raw evidence is never provided to a model, API DTO, export, Evidence MCP, or
   Judge MCP. Public/read-only surfaces expose sanitized published projections.
8. Every control-plane incident lookup is incident-authorized. Judge MCP uses a
   separate publication boundary and can never query an unpublished projection.
   There is no wildcard control-plane incident principal.
9. Event history is append-only and hash chained. Published incident snapshots
   and signed exports bind their timeline head.
10. Judge MCP remains read-only and private behind Caddy. It cannot approve,
    execute, run tests, retrieve secrets, or fetch raw evidence.

## Log-based prompt injection

Every raw evidence source is untrusted, including log lines, source code,
comments, diffs, test output, database values, webhook payloads, and timeline text.
An attacker may place text such as “ignore previous instructions,” encoded tool
requests, fake system messages, Unicode direction overrides, or secrets in those
channels. This **log-based prompt injection** attack surface is documented and
tested explicitly.

The evidence pipeline separates raw bytes from model-safe views. It normalizes
Unicode control/bidi/zero-width characters, redacts configured and patterned
secrets, detects direct and encoded instruction-like spans, applies byte/line
limits, and replaces suspect ranges with tags. Models receive a typed
`UNTRUSTED_EVIDENCE` envelope with provenance and sanitized hashes. Raw evidence
is content-addressed under a separate private namespace with no generic read-by-
hash API.

### Sanitizer limitations

No sanitizer can establish that arbitrary natural language is safe. Expected
limitations include unseen encodings, multilingual or domain-specific phrasing,
semantic instructions that look like legitimate logs, instructions distributed
across artifacts, and future model behavior. Sanitization therefore does not
grant authority. Typed outputs, citation validation, strict tool allowlists,
incident authorization, deterministic test execution, canonical warrant checks,
and human approval remain independent controls.

## MCP trust zones

### Evidence MCP

Private, read-only, and restricted to the orchestrator identity and
`crosspatch-evidence` audience. Its allowlist exposes sanitized incident evidence,
source views, fixed test catalog/results, and timeline views. Each request and
reconnect validates token audience, subject, expiry, replay identifier, Host,
Origin, and session/principal binding.

### Broker MCP

Private and restricted to the Bailiff identity and `crosspatch-broker` audience.
The complete surface is `execute_warrant(id)`. The service accepts no patch,
path, command, test, or shell input from the model; it resolves the already
approved canonical document and immutable execution catalog internally.

### Judge MCP

Read-only, restricted to `crosspatch-judge` tokens, and reachable publicly only
through Caddy at `/mcp/judge` over TLS. It reads transactionally published
projections: incident summaries, timeline, verdicts, sanitized evidence, warrant
log, and manifest verification. It exposes no raw evidence, token material,
approval, mutation, runner, or shell capability. Judge tokens are stored as
hashes, support overlapping rotation and immediate revocation, and must remain
operational through at least `2026-08-13T07:00:00Z`. The hosted default bearer
intentionally lists and reads every sanitized projection whose durable
`published` bit was set after an **operator** incident reached terminal
`VERIFIED`. Live-trial incidents remain unpublished even after sandbox
verification and therefore never enter this shared browse set. Guessed IDs for unpublished or
in-flight incidents cannot resolve. Optional
`CROSSPATCH_JUDGE_INCIDENT_SCOPED=1` further restricts that already-published set
to one incident; it is not the hosted default.

### Live-trial API

Live-trial bearers are distinct from Judge MCP and operator credentials. An
approver issues or revokes them through the existing Origin/CSRF/step-up-gated
rotation surface. A bearer can open only the bundled webhook-race scenario and
can read or decide only incidents durably owned by that subject. `APPROVE`
remains exact-warrant-hash bound, `REJECT` requires a bounded sanitized reason,
and `REQUEST_REVISION` stores the bounded comment as untrusted sanitized
evidence before rerunning Counsel, Prosecutor, and Magistrate. All executions
remain confined to the existing disposable candidate/victim sandbox.

Every credential has its own request window, but all credentials reserve and
charge against one database-locked global model-spend counter (USD 20 by
default). Exhausting either limit fails new live model work closed without
affecting the read-only Judge MCP. A live trial never sets the Judge publication
bit, including after `VERIFIED`.

## Human approval boundary

The browser and CLI require an approver role, an allowed exact Origin, CSRF token,
and time-limited step-up token. The decision includes the displayed
`warrant_sha256`; stale UI state cannot approve a changed document. `CLEAR` only
opens the approval state—it does not call the Bailiff.

The canonical warrant binds:

- incident and selected candidate identifiers;
- Magistrate verdict ID/hash and reviewed timeline/evidence head;
- base Git SHA and repository manifest;
- literal patch bytes/hash and diff-derived path set;
- immutable test and mutation plan identifiers;
- environment, runner, and catalog digests;
- approver, expiry, nonce, and schema version.

The broker verifies all fields again at execution and consumes the approval once.
Expired, revoked, altered, reused, partially missing, or internally inconsistent
documents are rejected before any operation.

## Isolation and residual risk

The trusted runner owns the oracle context, PostgreSQL observations, fixed-plan
selection, tree snapshots, and signed/hashed result receipt. A root-owned,
immutable bootstrap prepares protected Unix sockets, then demotes the disposable
executor to UID 10003 with only `KILL`, `SETGID`, and `SETUID`. Before importing
candidate code, the executor irreversibly drops the child to UID/GID 10002 with
no supplementary groups or capabilities and `no-new-privileges`. Caddy runs as
UID 0 with only `NET_BIND_SERVICE`; every other hardened service drops every
Linux capability. Application services use numeric non-root runtime identities,
and all hardened services use read-only roots and mount no Docker, Podman, or
containerd socket. The candidate child shares the executor container's private
PID namespace; container replacement, not a claimed child-only namespace, is the
teardown boundary.

The local Docker daemon, host kernel, image registry, OpenAI service, DNS/TLS
provider, and repository owner remain trusted dependencies. Container isolation
is not a defense against a compromised host. The included mutation target should
be a disposable sandbox checkout, never a production repository.

## Secrets and operational response

- Never commit `.env`, generated tokens, private signing keys, raw artifacts, or
  database dumps.
- Generate runtime secrets into the persistent secret volume with mode `0600`.
- Store judge tokens only as cryptographic hashes; return plaintext only once at
  issuance.
- Rotate with an overlap so existing judge access remains available, then revoke
  the old token explicitly after readback succeeds.
- On suspected compromise: disable approvals, revoke tokens, preserve the
  append-only timeline and audit artifacts, rotate signing/operator credentials,
  rebuild from pinned sources, and run the full release verifier.
- Backups contain sensitive incident metadata and must be encrypted and access
  controlled. Test restore into an isolated environment.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for data flows and abuse cases,
and [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for token rotation, backup, restore,
TLS, and availability procedures.
