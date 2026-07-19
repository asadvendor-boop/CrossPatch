import { createHash } from "node:crypto";

import { DEFAULT_SEATS } from "@/lib/tokens";

const hash = (character: string) => character.repeat(64);

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "number") {
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value.normalize("NFC"));
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value !== "object") throw new TypeError("unsupported canonical fixture value");
  const entries = Object.entries(value as Record<string, unknown>)
    .map(([key, item]) => [key.normalize("NFC"), item] as const)
    .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0);
  return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`).join(",")}}`;
}

export function sealPublicCaseEnvelope<T extends { projection: Record<string, unknown> }>(
  envelope: T,
  canonicalProjectionJson = canonicalJson(envelope.projection),
): T & { manifest_sha256: string; canonical_projection_json: string } {
  return {
    ...envelope,
    manifest_sha256: createHash("sha256").update(canonicalProjectionJson).digest("hex"),
    canonical_projection_json: canonicalProjectionJson,
  };
}

export function canonicalFixtureWithPythonNumberVectors(
  projection: Record<string, unknown>,
): string {
  const javascriptNumbers =
    '"canonical_number_vectors":{"large_exponent":100000000000000000000,"negative_zero":0,"one":1,"small_exponent":1e-7,"zero":0}';
  const pythonNumbers =
    '"canonical_number_vectors":{"large_exponent":1e+20,"negative_zero":-0.0,"one":1.0,"small_exponent":1e-07,"zero":0.0}';
  const canonical = canonicalJson(projection);
  if (!canonical.includes(javascriptNumbers)) {
    throw new TypeError("canonical number vector fixture is missing");
  }
  return canonical.replace(javascriptNumbers, pythonNumbers);
}

function event(
  sequence: number,
  type: string,
  actor: string,
  createdAt: string,
  details: Record<string, unknown> = {},
) {
  return {
    id: `evt-public-${sequence}`,
    incident_id: "inc-public-1",
    sequence,
    type,
    actor,
    summary: type.replaceAll("_", " "),
    details,
    event_hash: hash(sequence.toString(16).slice(-1)),
    created_at: createdAt,
    published: true,
  };
}

export function publicCaseSummary(overrides: Record<string, unknown> = {}) {
  return {
    incident_id: "inc-public-1",
    title: "Webhook receipt race",
    state: "VERIFIED",
    scenario: "webhook-race",
    created_at: "2026-07-14T10:50:00Z",
    updated_at: "2026-07-14T10:54:28Z",
    revision: 3,
    manifest_sha256: hash("a"),
    verdict_path: ["REMAND", "CLEAR"],
    recorded_cost_usd: 0.0168,
    duration_seconds: 268,
    evidence_to_verified_seconds: 255,
    human_gate_dwell_seconds: 60,
    execution_verification_seconds: 20,
    seat_spend: [
      {
        seat: "Inspector",
        effort: "medium",
        escalation_count: 0,
        cost_usd: 0.0123,
      },
      {
        seat: "Magistrate",
        effort: "high",
        escalation_count: 1,
        cost_usd: 0.0045,
      },
    ],
    ...overrides,
  };
}

export function publicWarrantHistory() {
  const publicWarrant = {
    allowed_paths: ["victim/src/victim/db.py"],
    approver_identity: "approver-public-1",
    authority_snapshot_sha256: hash("8"),
    base_sha: "b".repeat(40),
    canonical_warrant_sha256: hash("1"),
    environment_digest: hash("a"),
    expires_at: "2026-07-14T11:08:00+00:00",
    format: "crosspatch-public-warrant-anatomy-v1",
    incident_id: "inc-public-1",
    nonce_sha256: hash("2"),
    patch_sha256: hash("3"),
    plan_ids: ["victim.duplicate-race.candidate"],
    repository_manifest_sha256: hash("c"),
    reviewed_evidence_manifest_sha256: hash("4"),
    reviewed_timeline_head: hash("5"),
    runner_digest: hash("6"),
    test_plan_sha256: hash("7"),
    verdict_sha256: hash("9"),
    warrant_id: "war-public-1",
  };
  const publicWarrantBytes = canonicalJson(publicWarrant);
  return {
    warrant_id: "war-public-1",
    canonical_sha256: hash("1"),
    public_warrant_bytes: publicWarrantBytes,
    public_warrant_sha256: createHash("sha256").update(publicWarrantBytes).digest("hex"),
    nonce_sha256: hash("2"),
    binding_hashes: {
      authority_snapshot_sha256: hash("8"),
      base_sha: "b".repeat(40),
      environment_digest: hash("a"),
      patch_sha256: hash("3"),
      repository_manifest_sha256: hash("c"),
      reviewed_evidence_manifest_sha256: hash("4"),
      reviewed_timeline_head: hash("5"),
      runner_digest: hash("6"),
      test_plan_sha256: hash("7"),
      verdict_sha256: hash("9"),
    },
    approval_status: "APPROVED",
    approval_id: "apr-public-1",
    consumption_status: "CONSUMED",
    execution_status: "EXECUTED",
    receipt_ids: ["test-public-1"],
    created_at: "2026-07-14T10:53:00Z",
    expires_at: "2026-07-14T11:08:00+00:00",
    consumed_at: "2026-07-14T10:54:00Z",
  };
}

export function publicCaseWithWarrantEnvelope() {
  const envelope = structuredClone(publicCaseEnvelope());
  const projection: Omit<typeof envelope.projection, "warrants"> & {
    warrants: ReturnType<typeof publicWarrantHistory>[];
  } = {
    ...envelope.projection,
    warrants: [publicWarrantHistory()],
  };
  return sealPublicCaseEnvelope({ ...envelope, projection });
}

export function publicCaseWithHypothesesEnvelope() {
  const envelope = structuredClone(publicCaseEnvelope());
  const projection = envelope.projection as unknown as {
    events: Array<ReturnType<typeof event>>;
    specialist_summaries: Array<Record<string, unknown>>;
    artifacts: { tests: Array<Record<string, unknown>> };
  };
  const inspectorOutput = hash("b");
  const prosecutorOutput = hash("c");
  projection.events = [
    event(1, "INCIDENT_OPENED", "operator", "2026-07-14T10:50:00Z"),
    event(2, "EVIDENCE_CAPTURED", "runner", "2026-07-14T10:50:05Z"),
    event(3, "AGENT_OUTPUT_RECORDED", "Inspector", "2026-07-14T10:50:20Z", {
      seat: "Inspector",
      phase: "analysis",
      effort: "medium",
      output_sha256: inspectorOutput,
      semantic_sha256: hash("d"),
    }),
    event(4, "AGENT_OUTPUT_RECORDED", "Prosecutor", "2026-07-14T10:50:35Z", {
      seat: "Prosecutor",
      phase: "challenge",
      effort: "low",
      output_sha256: prosecutorOutput,
      semantic_sha256: hash("e"),
    }),
    event(5, "VERDICT", "Magistrate", "2026-07-14T10:51:00Z", {
      verdict: "REMAND",
      remand_target: "Counsel",
    }),
    event(6, "VERDICT", "Magistrate", "2026-07-14T10:52:00Z", { verdict: "CLEAR" }),
    event(7, "MODEL_METRICS_RECORDED", "runtime", "2026-07-14T10:52:20Z", {
      seat: "Inspector",
      cost_usd: 0.0123,
      latency_ms: 3554,
    }),
    event(8, "MODEL_METRICS_RECORDED", "runtime", "2026-07-14T10:53:20Z", {
      seat: "Prosecutor",
      cost_usd: 0.0045,
      latency_ms: 1921,
    }),
    event(9, "VERIFIED", "broker", "2026-07-14T10:54:20Z", {
      receipt_id: "test-public-1",
    }),
    event(10, "BAILIFF_COMPLETED", "Bailiff", "2026-07-14T10:54:28Z", {
      status: "EXECUTED",
    }),
  ];
  projection.specialist_summaries = [
    {
      kind: "INSPECTOR",
      seat: "Inspector",
      run_id: "run-inspector-public",
      model: "gpt-5.6-terra",
      effort: "medium",
      escalation_count: 0,
      phase: "analysis",
      output_sha256: inspectorOutput,
      semantic_sha256: hash("d"),
      created_at: "2026-07-14T10:50:20Z",
      mechanism: "CHECK_THEN_INSERT_RACE",
      evidence_ids: ["ev-public-baseline"],
      falsifiers: ["A uniqueness control rejects the duplicate delivery."],
      sanitization_tags: [],
    },
    {
      kind: "PROSECUTOR",
      seat: "Prosecutor",
      run_id: "run-prosecutor-public",
      model: "gpt-5.6-luna",
      effort: "low",
      escalation_count: 0,
      phase: "challenge",
      output_sha256: prosecutorOutput,
      semantic_sha256: hash("e"),
      created_at: "2026-07-14T10:50:35Z",
      outcome: "SUPPORTED_RIVAL",
      rival_mechanism: "WORKER_RETRY_DUPLICATION",
      counterexample_ids: ["ev-public-baseline"],
      test_ids: ["victim.duplicate-race.baseline"],
      evidence_ids: ["ev-public-baseline"],
      sanitization_tags: [],
    },
  ];
  projection.artifacts.tests.push({
    id: "test-public-baseline",
    label: "victim.duplicate-race.baseline",
    state: "passed",
    duration_ms: 842,
    detail: "VULNERABLE_INVARIANT_1_2_2_CONFIRMED",
    receipt_sha256: hash("6"),
  });
  return sealPublicCaseEnvelope(envelope);
}

export function publicCaseEnvelope(overrides: Record<string, unknown> = {}) {
  const envelope = {
    incident_id: "inc-public-1",
    revision: 3,
    display_title: "Webhook receipt race",
    projection: {
      incident: {
        id: "inc-public-1",
        title: "Webhook receipt race",
        state: "VERIFIED",
        severity: "SEV-2",
        scenario: "webhook-race",
        base_sha: "b".repeat(40),
        created_at: "2026-07-14T10:50:00Z",
        updated_at: "2026-07-14T10:54:28Z",
      },
      seats: DEFAULT_SEATS.map((seat) => ({
        name: seat.name,
        effort: seat.effort,
        escalation_count: seat.name === "Counsel" ? 1 : 0,
        state: "complete",
      })),
      events: [
        event(1, "INCIDENT_OPENED", "operator", "2026-07-14T10:50:00Z"),
        event(2, "EVIDENCE_CAPTURED", "runner", "2026-07-14T10:50:05Z"),
        event(3, "VERDICT", "Magistrate", "2026-07-14T10:51:00Z", {
          verdict: "REMAND",
          remand_target: "Counsel",
        }),
        event(4, "VERDICT", "Magistrate", "2026-07-14T10:52:00Z", {
          verdict: "CLEAR",
        }),
        event(5, "MODEL_METRICS_RECORDED", "runtime", "2026-07-14T10:52:20Z", {
          seat: "Inspector",
          cost_usd: 0.0123,
          latency_ms: 3554,
        }),
        event(6, "MODEL_METRICS_RECORDED", "runtime", "2026-07-14T10:53:20Z", {
          seat: "Magistrate",
          cost_usd: 0.0045,
          latency_ms: 4921,
        }),
        event(7, "VERIFIED", "broker", "2026-07-14T10:54:20Z", {
          receipt_id: "test-public-1",
        }),
        event(8, "BAILIFF_COMPLETED", "Bailiff", "2026-07-14T10:54:28Z", {
          status: "EXECUTED",
        }),
      ],
      verdicts: [
        {
          id: "verdict-public-1",
          incident_id: "inc-public-1",
          verdict: "REMAND",
          verdict_sha256: hash("8"),
          source: "Magistrate",
          created_at: "2026-07-14T10:51:00Z",
        },
        {
          id: "verdict-public-2",
          incident_id: "inc-public-1",
          verdict: "CLEAR",
          verdict_sha256: hash("9"),
          source: "Magistrate",
          created_at: "2026-07-14T10:52:00Z",
        },
      ],
      specialist_summaries: [],
      warrants: [],
      artifacts: {
        evidence: [{
          classification: "UNTRUSTED_EVIDENCE",
          id: "ev-public-baseline",
          incident_id: "inc-public-1",
          kind: "test_output",
          provenance: "deterministic webhook race reproduction",
          text: JSON.stringify({ counts: { receipts: 1, jobs: 2, deliveries: 2 } }),
          sanitized_sha256: hash("e"),
          captured_at: "2026-07-14T10:50:05Z",
          tags: [],
        }],
        diff: null,
        tests: [{
          id: "test-public-1",
          label: "victim.duplicate-race.candidate",
          state: "passed",
          duration_ms: 12675,
          detail: "TRUSTED_HTTP_POSTGRES_INVARIANT_MATCHED",
          receipt_sha256: hash("f"),
        }],
        warrant: null,
      },
      pending_warrant: null,
    },
  };
  return { ...sealPublicCaseEnvelope(envelope), ...overrides };
}

export function publicPayloadEquivalenceEnvelope(
  planId = "victim.payload-equivalence.candidate",
  counts = { receipts: 1, jobs: 1, deliveries: 1 },
) {
  const envelope = structuredClone(publicCaseEnvelope());
  envelope.display_title = "Equivalent webhook retry rejected";
  envelope.projection.incident.title = "Equivalent webhook retry rejected";
  envelope.projection.incident.scenario = "webhook-payload-equivalence";

  const baseline = envelope.projection.artifacts.evidence[0];
  baseline.provenance = "deterministic webhook payload-equivalence reproduction";
  baseline.text = JSON.stringify({
    counts: { receipts: 1, jobs: 1, deliveries: 1 },
    response_statuses: [202, 409, 409],
  });

  const receipt = envelope.projection.artifacts.tests[0] as (
    typeof envelope.projection.artifacts.tests[number] & {
      trusted_observation?: {
        counts: { receipts: number; jobs: number; deliveries: number };
        response_statuses: number[];
      };
    }
  );
  receipt.label = planId;
  receipt.trusted_observation = {
    counts,
    response_statuses: [202, 200, 409],
  };

  return sealPublicCaseEnvelope(envelope);
}
