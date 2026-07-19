import { createHash } from "node:crypto";

import { decodeIncidentRoom } from "@/lib/api";
import { DEFAULT_SEATS } from "@/lib/tokens";
import type { IncidentRoomSnapshot } from "@/lib/types";

const hash = (character: string) => character.repeat(64);

function event(
  sequence: number,
  type: string,
  actor: string,
  details: Record<string, unknown> = {},
) {
  return {
    id: `evt-${String(sequence).padStart(2, "0")}`,
    incident_id: "inc-recorded",
    sequence,
    type,
    actor,
    summary: type.replaceAll("_", " "),
    details,
    event_hash: hash(sequence.toString(16).slice(-1)),
    created_at: `2026-07-14T00:00:${String(sequence).padStart(2, "0")}Z`,
    published: true,
  };
}

export function recordedRoomSnapshot(): IncidentRoomSnapshot {
  const inspectorOutput = hash("a");
  const prosecutorOutput = hash("b");
  const counselOutput = hash("c");
  const warrantHash = hash("d");
  const receiptHash = hash("e");
  const nonceSha256 = hash("0");
  const publicWarrantBytes = JSON.stringify({
    allowed_paths: ["victim/src/victim/db.py"],
    approver_identity: "approver-1",
    authority_snapshot_sha256: hash("6"),
    base_sha: "f".repeat(40),
    canonical_warrant_sha256: warrantHash,
    environment_digest: hash("7"),
    expires_at: "2026-07-14T00:15:09Z",
    format: "crosspatch-public-warrant-anatomy-v1",
    incident_id: "inc-recorded",
    nonce_sha256: nonceSha256,
    patch_sha256: hash("2"),
    plan_ids: ["victim.duplicate-race.candidate"],
    repository_manifest_sha256: hash("8"),
    reviewed_evidence_manifest_sha256: hash("9"),
    reviewed_timeline_head: hash("a"),
    runner_digest: hash("b"),
    test_plan_sha256: hash("c"),
    verdict_sha256: hash("d"),
    warrant_id: "war-recorded",
  });

  return decodeIncidentRoom({
    viewer_role: "operator",
    incident: {
      id: "inc-recorded",
      title: "Webhook receipt race",
      state: "VERIFIED",
      severity: "SEV-2",
      scenario: "webhook-race",
      base_sha: "f".repeat(40),
      created_at: "2026-07-14T00:00:00Z",
      updated_at: "2026-07-14T00:01:00Z",
    },
    seats: DEFAULT_SEATS.map((seat) => ({
      name: seat.name,
      effort: seat.name === "Counsel" ? "high" : seat.effort,
      escalation_count: seat.name === "Counsel" ? 1 : 0,
      state: "complete",
    })),
    events: [
      event(1, "INCIDENT_OPENED", "operator"),
      event(2, "EVIDENCE_CAPTURED", "deterministic-runner", {
        evidence_id: "ev-baseline",
        outcome: "FAILED",
        sanitized_sha256: hash("1"),
      }),
      event(3, "AGENT_OUTPUT_RECORDED", "Inspector", { output_sha256: inspectorOutput }),
      event(4, "AGENT_OUTPUT_RECORDED", "Prosecutor", { output_sha256: prosecutorOutput }),
      event(5, "PATCH_PROPOSED", "Counsel", { patch_sha256: hash("2") }),
      event(6, "AGENT_OUTPUT_RECORDED", "Counsel", { output_sha256: counselOutput }),
      event(7, "VERDICT", "Magistrate", { verdict: "REMAND", remand_target: "Counsel" }),
      event(8, "REASONING_ESCALATED", "Counsel", {
        seat: "Counsel",
        effort: "high",
        escalation_count: 1,
        reason: "remand",
      }),
      event(9, "VERDICT", "Magistrate", { verdict: "CLEAR" }),
      event(10, "WARRANT_APPROVED", "approver-1", { warrant_sha256: warrantHash }),
      event(11, "EXECUTION_STARTED", "broker", { warrant_id: "war-recorded" }),
      event(12, "VERIFIED", "broker", {
        warrant_id: "war-recorded",
        receipt_id: "test-recorded",
        evidence_id: "ev-candidate",
      }),
      event(13, "BAILIFF_COMPLETED", "Bailiff", {
        warrant_id: "war-recorded",
        status: "EXECUTED",
      }),
    ],
    specialist_summaries: [
      {
        kind: "INSPECTOR",
        seat: "Inspector",
        run_id: "run-inspector",
        model: "gpt-5.6-terra",
        effort: "medium",
        escalation_count: 0,
        phase: "analysis",
        output_sha256: inspectorOutput,
        semantic_sha256: hash("3"),
        created_at: "2026-07-14T00:00:03Z",
        mechanism: "The receipt check and insert are not atomic.",
        evidence_ids: ["ev-baseline"],
        falsifiers: ["A uniqueness constraint rejects the second delivery."],
      },
      {
        kind: "PROSECUTOR",
        seat: "Prosecutor",
        run_id: "run-prosecutor",
        model: "gpt-5.6-luna",
        effort: "low",
        escalation_count: 0,
        phase: "challenge",
        output_sha256: prosecutorOutput,
        semantic_sha256: hash("4"),
        created_at: "2026-07-14T00:00:04Z",
        outcome: "NO_SUPPORTED_RIVAL",
        rival_mechanism: null,
        counterexample_ids: ["counterexample-1"],
        test_ids: ["victim.duplicate-race.baseline"],
        evidence_ids: ["ev-baseline"],
      },
      {
        kind: "COUNSEL",
        seat: "Counsel",
        run_id: "run-counsel",
        model: "gpt-5.6-terra",
        effort: "high",
        escalation_count: 1,
        phase: "repair",
        output_sha256: counselOutput,
        semantic_sha256: hash("5"),
        created_at: "2026-07-14T00:00:06Z",
        candidate_id: "candidate-recorded",
        patch_sha256: hash("2"),
        patch_defense: "One atomic insert replaces the check-then-insert window.",
        evidence_ids: ["ev-baseline"],
        test_intentions: [{
          catalog_id: "victim.duplicate-race.candidate",
          purpose: "Prove exactly one receipt, job, and delivery remain.",
        }],
      },
    ],
    warrants: [{
      warrant_id: "war-recorded",
      canonical_sha256: warrantHash,
      public_warrant_bytes: publicWarrantBytes,
      public_warrant_sha256: createHash("sha256").update(publicWarrantBytes).digest("hex"),
      nonce_sha256: nonceSha256,
      binding_hashes: {
        authority_snapshot_sha256: hash("6"),
        base_sha: "f".repeat(40),
        environment_digest: hash("7"),
        patch_sha256: hash("2"),
        repository_manifest_sha256: hash("8"),
        reviewed_evidence_manifest_sha256: hash("9"),
        reviewed_timeline_head: hash("a"),
        runner_digest: hash("b"),
        test_plan_sha256: hash("c"),
        verdict_sha256: hash("d"),
      },
      approval_status: "APPROVED",
      approval_id: "apr-recorded",
      consumption_status: "CONSUMED",
      execution_status: "EXECUTED",
      receipt_ids: ["test-recorded"],
      created_at: "2026-07-14T00:00:09Z",
      expires_at: "2026-07-14T00:15:09Z",
      consumed_at: "2026-07-14T00:00:12Z",
    }],
    artifacts: {
      evidence: [
        {
          classification: "UNTRUSTED_EVIDENCE",
          id: "ev-baseline",
          incident_id: "inc-recorded",
          kind: "test_output",
          provenance: "deterministic webhook race reproduction",
          text: JSON.stringify({
            counts: { receipts: 1, jobs: 2, deliveries: 2 },
            outcome: "FAILED",
          }),
          sanitized_sha256: hash("1"),
          captured_at: "2026-07-14T00:00:02Z",
          tags: [],
        },
        {
          classification: "UNTRUSTED_EVIDENCE",
          id: "ev-candidate",
          incident_id: "inc-recorded",
          kind: "test_output",
          provenance: "deterministic mutation broker receipt",
          text: JSON.stringify({
            status: "EXECUTED",
            verification_code: "TRUSTED_HTTP_POSTGRES_INVARIANT_MATCHED",
          }),
          sanitized_sha256: hash("f"),
          captured_at: "2026-07-14T00:00:12Z",
          tags: [],
        },
      ],
      diff: {
        classification: "UNTRUSTED_EVIDENCE",
        text: "@@ -1 +1 @@\n-check then insert\n+insert on conflict do nothing",
      },
      tests: [{
        id: "test-recorded",
        label: "victim.duplicate-race.candidate",
        state: "passed",
        duration_ms: 1200,
        detail: "TRUSTED_HTTP_POSTGRES_INVARIANT_MATCHED",
        receipt_sha256: receiptHash,
        trusted_observation: {
          counts: { receipts: 1, jobs: 1, deliveries: 1 },
          response_statuses: [202, 200],
        },
      }],
      warrant: null,
    },
    pending_warrant: null,
  });
}
