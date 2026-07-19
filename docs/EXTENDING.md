# Extending CrossPatch

This document describes the integration work required by the code that ships.
It is not a claim that CrossPatch has a general scenario SDK or dynamic loading
system. Exactly two bundled scenarios ship and are fully verified:
`webhook-race` and `webhook-payload-equivalence`.
There is no scenario plug-in registry. Live trials remain `webhook-race`-only.

The race scenario exercises a real duplicate-delivery failure. Its trusted
reproducer observes persisted `receipts/jobs/deliveries = 1/2/2` at the affected
revision, and its trusted candidate verifier accepts only `1/1/1`. Those values
come from HTTP and PostgreSQL observations, not metadata, seeded output, or a
model assertion.

The payload-equivalence scenario keeps raw-byte HMAC authentication unchanged
and exercises a distinct business-idempotency failure. The affected receiver
returns `202/409` for a first delivery and an equivalent, correctly signed retry
whose JSON differs only in ordering or whitespace. The trusted candidate oracle
requires `202/200/409` for first delivery, equivalent retry, and genuinely
different payload, plus persisted `receipts/jobs/deliveries = 1/1/1`. Its signed
production case and trusted external observation are record-derived; no
authentication bypass, forged signature, seeded outcome, or model assertion is
part of the proof.

## What a scenario must provide

Adding another scenario is a code-and-test change across explicit boundaries.
Every item below must be implemented before the identifier is accepted by the
API.

### 1. A closed scenario identifier and control-plane route

The accepted identifiers are checked directly in
`backend/src/crosspatch/api/routes/incidents.py` and
`backend/src/crosspatch/runtime/control.py`. Operator entry accepts both shipped
identifiers; live-trial entry accepts only `webhook-race`. A new identifier
therefore needs explicit validation in both paths, a deterministic default
title, and tests proving an unknown identifier still fails closed.

Incident creation also binds the current Git base SHA, repository manifest, and
immutable execution-catalog hash. Do not insert an incident row or fabricate a
timeline around that path; use the same control service and durable event store.

### 2. A deterministic reproducer with observable success criteria

`backend/src/crosspatch/runner/reproduction.py` defines the shipped
`ReproductionResult`: outcome, observed lock state, persisted counts, response
statuses, and diagnostics. The webhook reproducer coordinates the race from
outside the victim and uses PostgreSQL lock state instead of sleeps or a
test-only synchronization hook.

A scenario reproducer must likewise:

- exercise the real service boundary;
- define positive affected-revision observations;
- distinguish a product failure from `INFRA_INCONCLUSIVE`;
- return only measured values; and
- be deterministic enough for repeated release verification.

The affected-revision test and candidate test are separate contracts. The
former must positively prove the real failure; the latter must positively prove
the repaired invariant.

### 3. A launcher that turns real bytes into incident evidence

`backend/src/crosspatch/runtime/incidents.py` contains
`WebhookRaceIncidentLauncher`. It records reproduction lifecycle events, runs
the reproducer, captures the actual source files used by the incident, and then
starts the five-seat coordinator only when the evidence supports analysis.

Every raw log, source file, trace, receipt, issue comment, and diagnostic is
untrusted. Feed its bytes and provenance through `EvidenceService`; never place
raw content directly in an agent prompt. `EvidenceService` returns an
`UNTRUSTED_EVIDENCE` envelope after sanitization and stores the pair in raw and
sanitized artifact namespaces. The raw reference remains incident-bound and is
not exposed through the API, model-facing Evidence MCP, Judge MCP, or export.

A launcher must also define which repository files are captured as source
evidence. The shipped launcher lists four victim source paths explicitly. A new
scenario must not use generated model text or a hand-authored evidence fixture
as a substitute for those reads.

### 4. Server-owned test intentions and immutable execution plans

`backend/src/crosspatch/runner/catalog.py` is the complete production catalog.
Its immutable execution plans resolve a plan ID to fixed argv, working
directory, timeout, expected observations, and SHA-256. Models may select an ID;
they cannot supply or amend argv.

Add every required baseline, regression, safety, and candidate plan to that
compile-time catalog. Pin each node to a real test that exists inside the runner
image, assert the catalog digest, and prove arbitrary command material is
rejected. Do not treat `expected_counts` metadata as verification; the process
or external oracle must produce the measured result.

### 5. A scenario-specific candidate boundary and external oracle

The current candidate path is deliberately specific to the two bundled victim
scenarios.
`backend/src/crosspatch/runner/candidate_service.py` imports the candidate's
victim application from a read-only worktree and launches it as the untrusted
candidate UID. The candidate cannot see the trusted context, write the source
tree, mint a receipt, or decide whether it passed.

`backend/src/crosspatch/runner/supervisor.py` snapshots the worktree and context,
launches the isolated attempt, asks a trusted black-box verifier to observe the
service and database from outside the candidate process, and rechecks the
snapshots afterward. Candidate exit zero and stdout are diagnostic only.

A new scenario must supply an equivalent service adapter and trusted black-box
verifier. The verifier must own its challenge, measure the scenario invariant,
and emit a trusted receipt. If the required UID, read-only mount, process
boundary, database role, or external observation cannot be established, the
candidate plan must fail closed.

### 6. Durable state and repair behavior

The launcher must use the existing typed state transitions rather than writing
an end state. A failed candidate consumes its warrant, records the real failed
receipt, re-enters patching through the repair cycle, and requires a fresh
warrant and approval. Infrastructure failures and invalid model output must
remain distinguishable from product test failures.

If a scenario's proof differs from the webhook counts, update its public proof
projection and UI decoder so every visible status remains derived from a hashed
event or trusted receipt. Never add a display-only success path.

## What the platform supplies after integration

Once the scenario-specific pieces above are wired and verified, the shared
CrossPatch layers provide these controls:

- incident-scoped content-addressed evidence storage, sanitizer tagging, and
  read-only Evidence MCP access to `UNTRUSTED_EVIDENCE`;
- the five fixed specialist seats, structured outputs, citation checks,
  fail-closed `ABSTAIN`, durable sessions, bounded handoff, tracing, and the
  reasoning-effort escalation ladder with semantic duplicate detection;
- canonical warrant construction bound to the incident, verdict, reviewed
  evidence and timeline, base SHA, repository manifest, literal patch bytes,
  allowed paths, immutable execution plans, runner and environment digests,
  approver, expiry, and nonce;
- human approval of the exact canonical bytes before the Bailiff can call the
  one broker tool;
- atomic claim and consumption of a single-use warrant before worktree creation
  or process execution;
- ephemeral worktree creation, path-policy enforcement, candidate isolation,
  trusted receipt persistence, and fail-closed broker statuses; and
- append-only timeline records, sanitized published projections, signed case
  export, and read-only Judge MCP access at the operator-only `VERIFIED`
  publication boundary.

These shared controls do not supply a scenario's reproducer, test catalog,
candidate adapter, external oracle, or expected invariant. Those remain
scenario-owned code and evidence.

## Required verification

An extension is not complete until its tests demonstrate all of the following:

1. The API and CLI accept the new closed identifier, while unknown identifiers
   and unsupported live-trial use remain rejected.
2. The real affected revision reproduces the documented failure, and
   infrastructure loss reports `INFRA_INCONCLUSIVE` rather than a product result.
3. Every catalog node resolves and executes from its fixed absolute runner path;
   supplied argv and unknown IDs are rejected.
4. Hostile evidence is sanitized and tagged, raw bytes do not leak through the
   API, MCP surfaces, or case export, and a failed paired write cannot publish raw
   evidence alone.
5. Warrant tampering across patch bytes, base SHA, paths, plans, expiry, runner
   digest, and environment digest is rejected before a worktree or process
   exists.
6. The candidate cannot read trusted context, write its worktree, forge a
   receipt, or turn exit zero into success; the trusted black-box verifier alone
   proves the repaired invariant.
7. A failed candidate produces a real failed receipt and a fresh
   review/warrant/approval cycle; a valid candidate reaches `VERIFIED` only from
   its trusted receipt.
8. Published case and UI claims remain record-derived, and the release gate
   preserves machine-generated artifacts for the exact scenario run.

Run focused scenario contracts first, then the repository's strict local release
gate. A passing unit fixture is not evidence that the scenario works in the
Compose topology.
