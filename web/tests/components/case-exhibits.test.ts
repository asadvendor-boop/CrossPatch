import { describe, expect, it } from "vitest";

import {
  deriveAuthorityLifecycle,
  deriveCaseMetrics,
  deriveCompetingHypotheses,
  derivePublishedSummaryMetrics,
  derivePublishedSetMetrics,
  derivePayloadEquivalenceComparison,
  deriveSummaryWhatHappened,
  deriveWhatHappened,
  projectRecordedPrefix,
} from "@/lib/case-exhibits";
import type {
  IncidentRoomSnapshot,
  PublishedCaseSummary,
  TimelineEvent,
  WarrantHistoryItem,
} from "@/lib/types";
import { recordedRoomSnapshot } from "../fixtures/recorded-room";

const hash = (character: string) => character.repeat(64);

function event(
  sequence: number,
  kind: string,
  occurredAt: string,
  details: Record<string, unknown> = {},
): TimelineEvent {
  return {
    id: `evt-derived-${sequence}`,
    eventHash: hash(sequence.toString(16).slice(-1)),
    rawPublicJson: JSON.stringify({ sequence, kind, occurredAt, details }),
    sequence,
    kind,
    actor: kind === "VERDICT" ? "Magistrate" : "runtime",
    occurredAt,
    summary: kind,
    details,
    state: kind === "VERIFIED" ? "verified" : "neutral",
  };
}

function warrant(overrides: Partial<WarrantHistoryItem> = {}): WarrantHistoryItem {
  return {
    warrantId: "war-derived-1",
    canonicalSha256: hash("a"),
    bindingHashes: {
      authoritySnapshotSha256: hash("1"),
      baseSha: "b".repeat(40),
      environmentDigest: hash("2"),
      patchSha256: hash("3"),
      repositoryManifestSha256: hash("4"),
      reviewedEvidenceManifestSha256: hash("5"),
      reviewedTimelineHead: hash("6"),
      runnerDigest: hash("7"),
      testPlanSha256: hash("8"),
      verdictSha256: hash("9"),
    },
    approvalStatus: "APPROVED",
    approvalId: "apr-derived-1",
    consumptionStatus: "CONSUMED",
    executionStatus: "EXECUTED",
    receiptIds: ["receipt-derived-1"],
    createdAt: "2026-07-16T10:00:05Z",
    expiresAt: "2026-07-16T10:15:05Z",
    consumedAt: "2026-07-16T10:00:07Z",
    ...overrides,
  };
}

function metricSnapshot(): IncidentRoomSnapshot {
  const snapshot = recordedRoomSnapshot();
  const events = [
    event(1, "EVIDENCE_CAPTURED", "2026-07-16T10:00:00Z"),
    event(2, "MODEL_METRICS_RECORDED", "2026-07-16T10:00:01Z", {
      seat: "Inspector",
      effort: "medium",
      cost_usd: 0.01,
    }),
    event(3, "REASONING_ESCALATED", "2026-07-16T10:00:02Z", {
      seat: "Inspector",
      effort: "high",
      escalation_count: 1,
    }),
    event(4, "MODEL_METRICS_RECORDED", "2026-07-16T10:00:03Z", {
      seat: "Inspector",
      effort: "high",
      cost_usd: 0.02,
    }),
    event(5, "VERDICT", "2026-07-16T10:00:04Z", { verdict: "CLEAR" }),
    event(6, "WARRANT_APPROVED", "2026-07-16T10:00:06Z", {
      warrant_sha256: hash("a"),
      approver_identity: "operator-1",
    }),
    event(7, "EXECUTION_STARTED", "2026-07-16T10:00:07Z", {
      warrant_id: "war-derived-1",
    }),
    event(8, "VERIFIED", "2026-07-16T10:00:10Z", {
      warrant_id: "war-derived-1",
      receipt_id: "receipt-derived-1",
    }),
  ];
  return { ...snapshot, events, warrants: [warrant()] };
}

function supportedRivalSnapshot(): IncidentRoomSnapshot {
  const snapshot = recordedRoomSnapshot();
  const inspector = snapshot.specialistSummaries.find((summary) => summary.kind === "INSPECTOR");
  const prosecutor = snapshot.specialistSummaries.find((summary) => summary.kind === "PROSECUTOR");
  if (!inspector || inspector.kind !== "INSPECTOR" || !prosecutor || prosecutor.kind !== "PROSECUTOR") {
    throw new Error("recorded fixture is missing hypothesis specialists");
  }
  snapshot.specialistSummaries = snapshot.specialistSummaries.map((summary) => {
    if (summary.kind === "INSPECTOR") {
      return {
        ...summary,
        mechanism: "CHECK_THEN_INSERT_RACE",
        falsifiers: ["A database uniqueness control rejects the duplicate."],
      };
    }
    if (summary.kind === "PROSECUTOR") {
      return {
        ...summary,
        outcome: "SUPPORTED_RIVAL" as const,
        rivalMechanism: "WORKER_RETRY_DUPLICATION",
        counterexampleIds: ["ev-baseline"],
        testIds: ["victim.duplicate-race.baseline"],
      };
    }
    return summary;
  });
  snapshot.artifacts.tests.push({
    id: "test-baseline-control",
    label: "victim.duplicate-race.baseline",
    state: "passed",
    durationMs: 842,
    detail: "VULNERABLE_INVARIANT_1_2_2_CONFIRMED",
    receiptSha256: hash("6"),
  });
  return snapshot;
}

function payloadEquivalenceSnapshot(planId = "victim.payload-equivalence.candidate") {
  const snapshot = recordedRoomSnapshot();
  snapshot.artifacts.evidence[0] = {
    ...snapshot.artifacts.evidence[0],
    content: JSON.stringify({
      counts: { receipts: 1, jobs: 1, deliveries: 1 },
      response_statuses: [202, 409, 409],
    }),
  };
  snapshot.artifacts.tests[0] = {
    ...snapshot.artifacts.tests[0],
    label: planId,
    trustedObservation: {
      counts: { receipts: 1, jobs: 1, deliveries: 1 },
      responseStatuses: [202, 200, 409],
    },
  };
  return snapshot;
}

describe("record-derived case exhibits", () => {
  it("explains a case-index summary using only recorded summary fields", () => {
    const summary: PublishedCaseSummary = {
      incidentId: "inc-summary",
      title: "Webhook receipt race",
      state: "VERIFIED",
      scenario: "webhook-race",
      createdAt: "2026-07-16T10:00:00Z",
      updatedAt: "2026-07-16T10:04:28Z",
      revision: 1,
      manifestSha256: hash("f"),
      verdictPath: ["REMAND", "CLEAR"],
      recordedCostUsd: 0.0168,
      durationSeconds: 268,
      evidenceToVerifiedSeconds: null,
      humanGateDwellSeconds: null,
      executionVerificationSeconds: null,
      seatSpend: [],
    };

    expect(deriveSummaryWhatHappened(summary)).toEqual([
      "The recorded decision returned CLEAR after 1 REMAND.",
      "The repair reached VERIFIED in 4m 28s.",
      "Recorded model spend was $0.0168.",
    ]);

    expect(deriveSummaryWhatHappened({
      ...summary,
      verdictPath: ["CLEAR"],
      durationSeconds: null,
      recordedCostUsd: null,
    })).toEqual(["The recorded decision returned CLEAR without a REMAND."]);
  });

  it("explains only recorded baseline, verdict, and trusted proof with count units", () => {
    const result = deriveWhatHappened(recordedRoomSnapshot());

    expect(result).toEqual([
      "The baseline recorded 1 receipt, 2 jobs, and 2 deliveries.",
      "The Magistrate returned CLEAR after 1 REMAND.",
      "Trusted verification recorded 1 receipt, 1 job, and 1 delivery.",
    ]);
  });

  it("states the exact recorded payload-equivalence response sequence and counts", () => {
    expect(deriveWhatHappened(payloadEquivalenceSnapshot())).toEqual([
      "The baseline recorded 1 receipt, 1 job, and 1 delivery.",
      "The Magistrate returned CLEAR after 1 REMAND.",
      "Trusted verification recorded HTTP 202 / 200 / 409 with 1 receipt, 1 job, and 1 delivery.",
    ]);
  });

  it("derives the payload-equivalence comparison from sanitized evidence and the trusted receipt", () => {
    expect(derivePayloadEquivalenceComparison(payloadEquivalenceSnapshot())).toEqual({
      affected: {
        responseStatuses: [202, 409, 409],
        counts: { receipts: 1, jobs: 1, deliveries: 1 },
        source: {
          id: "ev-baseline",
          sha256: hash("1"),
        },
      },
      repaired: {
        responseStatuses: [202, 200, 409],
        counts: { receipts: 1, jobs: 1, deliveries: 1 },
        source: {
          id: "test-recorded",
          sha256: hash("e"),
        },
      },
    });
  });

  it.each([
    ["an unknown plan", (snapshot: IncidentRoomSnapshot) => {
      snapshot.artifacts.tests[0] = {
        ...snapshot.artifacts.tests[0],
        label: "victim.unknown.candidate",
      };
    }],
    ["a malformed affected status triplet", (snapshot: IncidentRoomSnapshot) => {
      snapshot.artifacts.evidence[0] = {
        ...snapshot.artifacts.evidence[0],
        content: JSON.stringify({
          counts: { receipts: 1, jobs: 1, deliveries: 1 },
          response_statuses: [202, 409],
        }),
      };
    }],
    ["an unsupported evidence hash", (snapshot: IncidentRoomSnapshot) => {
      snapshot.artifacts.evidence[0] = {
        ...snapshot.artifacts.evidence[0],
        sha256: "not-a-sha256",
      };
    }],
    ["a missing trusted receipt", (snapshot: IncidentRoomSnapshot) => {
      snapshot.artifacts.tests = [];
    }],
    ["a missing VERIFIED linkage", (snapshot: IncidentRoomSnapshot) => {
      snapshot.events = snapshot.events.filter((item) => item.kind !== "VERIFIED");
    }],
    ["an inconclusive reproduction", (snapshot: IncidentRoomSnapshot) => {
      snapshot.events = snapshot.events.map((item) => item.kind === "EVIDENCE_CAPTURED"
        ? { ...item, details: { ...item.details, outcome: "INFRA_INCONCLUSIVE" } }
        : item);
    }],
  ])("omits the payload-equivalence comparison for %s", (_label, mutate) => {
    const snapshot = payloadEquivalenceSnapshot();
    mutate(snapshot);

    expect(derivePayloadEquivalenceComparison(snapshot)).toBeNull();
  });

  it("omits the trusted proof sentence when recorded statuses or counts are missing", () => {
    const snapshot = payloadEquivalenceSnapshot();
    snapshot.artifacts.tests[0] = {
      ...snapshot.artifacts.tests[0],
      trustedObservation: null,
    };

    expect(deriveWhatHappened(snapshot)).not.toContain(expect.stringMatching(/Trusted verification/));
  });

  it("renders an unknown plan ID as a neutral raw-record label without a verified claim", () => {
    const result = deriveWhatHappened(payloadEquivalenceSnapshot("victim.unknown.candidate"));

    expect(result).toContain("Recorded plan: victim.unknown.candidate.");
    expect(result).not.toContain(expect.stringMatching(/Trusted verification/));
  });

  it("omits a narrative sentence when its source record is absent", () => {
    const snapshot = recordedRoomSnapshot();
    snapshot.artifacts.evidence = [];

    const result = deriveWhatHappened(snapshot);

    expect(result).not.toContain(expect.stringMatching(/baseline/i));
    expect(result).toHaveLength(2);
  });

  it("derives the eliminated rival only from linked specialist, evidence, control, and verdict records", () => {
    const result = deriveCompetingHypotheses(supportedRivalSnapshot());

    expect(result).toMatchObject({
      inspector: {
        mechanism: "CHECK_THEN_INSERT_RACE",
        evidence: [{ id: "ev-baseline" }],
      },
      prosecutor: {
        rivalMechanism: "WORKER_RETRY_DUPLICATION",
        outcome: "SUPPORTED_RIVAL",
        evidence: [{ id: "ev-baseline" }],
      },
      eliminated: {
        side: "PROSECUTOR_RIVAL",
        mechanism: "WORKER_RETRY_DUPLICATION",
      },
      verdict: {
        value: "CLEAR",
        eventId: "evt-09",
      },
    });
    expect(result?.negativeControls.map((control) => control.reference)).toEqual([
      "ev-baseline",
      "victim.duplicate-race.baseline",
    ]);
    expect(result?.negativeControls[1]).toMatchObject({
      kind: "test",
      state: "passed",
      receiptSha256: hash("6"),
    });
  });

  it.each([
    ["unsupported Inspector provenance", (snapshot: IncidentRoomSnapshot) => {
      const summary = snapshot.specialistSummaries.find((item) => item.kind === "INSPECTOR");
      if (summary) summary.rawPublicJson = "not-json";
    }],
    ["missing specialist output event", (snapshot: IncidentRoomSnapshot) => {
      snapshot.events = snapshot.events.filter((item) => item.actor !== "Prosecutor");
    }],
    ["no supported rival", (snapshot: IncidentRoomSnapshot) => {
      snapshot.specialistSummaries = snapshot.specialistSummaries.map((summary) => summary.kind === "PROSECUTOR"
        ? { ...summary, outcome: "NO_SUPPORTED_RIVAL" as const, rivalMechanism: null }
        : summary);
    }],
    ["dangling evidence", (snapshot: IncidentRoomSnapshot) => {
      snapshot.artifacts.evidence = [];
    }],
    ["missing negative control", (snapshot: IncidentRoomSnapshot) => {
      snapshot.artifacts.tests = snapshot.artifacts.tests.filter(
        (item) => item.label !== "victim.duplicate-race.baseline",
      );
    }],
    ["non-CLEAR final verdict", (snapshot: IncidentRoomSnapshot) => {
      snapshot.events = snapshot.events.map((item) => item.id === "evt-09"
        ? { ...item, details: { verdict: "BLOCK" } }
        : item);
    }],
  ])("omits the competing-hypothesis exhibit for %s", (_name, mutate) => {
    const snapshot = supportedRivalSnapshot();
    mutate(snapshot);

    expect(deriveCompetingHypotheses(snapshot)).toBeNull();
  });

  it("derives timing and spend from matching recorded events and escalation history", () => {
    const metrics = deriveCaseMetrics(metricSnapshot());

    expect(metrics).toMatchObject({
      evidenceToVerifiedMs: 10_000,
      humanGateDwellMs: 1_000,
      executionVerificationMs: 3_000,
      totalSpendUsd: 0.03,
    });
    expect(metrics.seatSpend).toEqual([
      { seat: "Inspector", effort: "medium", escalationCount: 0, costUsd: 0.01 },
      { seat: "Inspector", effort: "high", escalationCount: 1, costUsd: 0.02 },
    ]);
  });

  it("omits malformed or reversed timing intervals instead of approximating them", () => {
    const snapshot = metricSnapshot();
    snapshot.events = snapshot.events.map((item) => item.kind === "VERIFIED"
      ? { ...item, occurredAt: "2026-07-16T09:59:59Z" }
      : item);

    const metrics = deriveCaseMetrics(snapshot);

    expect(metrics.evidenceToVerifiedMs).toBeNull();
    expect(metrics.executionVerificationMs).toBeNull();
  });

  it("calculates published-set medians only from available recorded intervals", () => {
    const first = metricSnapshot();
    const second = metricSnapshot();
    second.events = second.events.map((item) => item.kind === "VERIFIED"
      ? { ...item, occurredAt: "2026-07-16T10:00:20Z" }
      : item);
    const incomplete = metricSnapshot();
    incomplete.events = incomplete.events.filter((item) => item.kind !== "VERIFIED");

    expect(derivePublishedSetMetrics([first, second, incomplete])).toMatchObject({
      caseCount: 3,
      measuredEvidenceToVerifiedCount: 2,
      medianEvidenceToVerifiedMs: 15_000,
    });
  });

  it("calculates public-index medians and spend without inventing missing measurements", () => {
    const summary = (overrides: Partial<PublishedCaseSummary>): PublishedCaseSummary => ({
      incidentId: "inc-summary",
      title: "Webhook receipt race",
      state: "VERIFIED",
      scenario: "webhook-race",
      createdAt: "2026-07-16T10:00:00Z",
      updatedAt: "2026-07-16T10:04:28Z",
      revision: 1,
      manifestSha256: hash("f"),
      verdictPath: ["CLEAR"],
      recordedCostUsd: 0.01,
      durationSeconds: 268,
      evidenceToVerifiedSeconds: 10,
      humanGateDwellSeconds: 4,
      executionVerificationSeconds: 2,
      seatSpend: [{
        seat: "Inspector",
        effort: "medium",
        escalationCount: 0,
        costUsd: 0.01,
      }],
      ...overrides,
    });

    expect(derivePublishedSummaryMetrics([
      summary({}),
      summary({
        incidentId: "inc-summary-2",
        recordedCostUsd: 0.02,
        evidenceToVerifiedSeconds: 20,
        humanGateDwellSeconds: 8,
        executionVerificationSeconds: null,
        seatSpend: [{
          seat: "Counsel",
          effort: "high",
          escalationCount: 1,
          costUsd: 0.02,
        }],
      }),
    ])).toEqual({
      caseCount: 2,
      measuredEvidenceToVerifiedCount: 2,
      medianEvidenceToVerifiedMs: 15_000,
      measuredHumanGateDwellCount: 2,
      medianHumanGateDwellMs: 6_000,
      measuredExecutionVerificationCount: 1,
      medianExecutionVerificationMs: 2_000,
      totalSpendUsd: 0.03,
      seatSpend: [
        { seat: "Inspector", effort: "medium", escalationCount: 0, costUsd: 0.01 },
        { seat: "Counsel", effort: "high", escalationCount: 1, costUsd: 0.02 },
      ],
    });
  });

  it("derives consumed authority and a failed warrant successor from persisted history", () => {
    const snapshot = metricSnapshot();
    const failed = warrant({
      executionStatus: "TEST_FAILED",
      receiptIds: ["receipt-failed"],
    });
    const successor = warrant({
      warrantId: "war-derived-2",
      canonicalSha256: hash("b"),
      approvalId: null,
      approvalStatus: "PENDING_APPROVAL",
      consumptionStatus: "NOT_MATERIALIZED",
      executionStatus: "NOT_EXECUTED",
      receiptIds: [],
      createdAt: "2026-07-16T10:00:11Z",
      consumedAt: null,
    });
    snapshot.warrants = [failed, successor];
    snapshot.events = [
      ...snapshot.events.filter((item) => item.kind !== "VERIFIED"),
      event(8, "TEST_FAILED", "2026-07-16T10:00:10Z", {
        warrant_id: failed.warrantId,
        test_run_id: "receipt-failed",
      }),
    ];

    const lifecycle = deriveAuthorityLifecycle(snapshot);

    expect(lifecycle[0]).toMatchObject({
      warrantId: failed.warrantId,
      issuedAt: failed.createdAt,
      approvedAt: "2026-07-16T10:00:06Z",
      consumedAt: failed.consumedAt,
      failureAt: "2026-07-16T10:00:10Z",
      successorWarrantId: successor.warrantId,
      successorCanonicalSha256: successor.canonicalSha256,
    });
    expect(lifecycle[1]).toMatchObject({
      warrantId: successor.warrantId,
      approvedAt: null,
      consumedAt: null,
      successorWarrantId: null,
    });
  });

  it("projects a deterministic event prefix without leaking future artifacts or mutating source", () => {
    const snapshot = recordedRoomSnapshot();
    const original = JSON.stringify(snapshot);

    const prefix = projectRecordedPrefix(snapshot, 2);
    const terminal = projectRecordedPrefix(snapshot, snapshot.events.length);

    expect(prefix).not.toBeNull();
    expect(prefix?.events).toHaveLength(2);
    expect(prefix?.incident.state).toBe("EVIDENCE_READY");
    expect(prefix?.specialistSummaries).toEqual([]);
    expect(prefix?.warrants).toEqual([]);
    expect(prefix?.artifacts.diff).toBeNull();
    expect(prefix?.artifacts.tests).toEqual([]);
    expect(terminal?.incident.state).toBe("VERIFIED");
    expect(terminal?.events).toHaveLength(snapshot.events.length);
    expect(JSON.stringify(snapshot)).toBe(original);
    expect(projectRecordedPrefix(snapshot, -1)).toBeNull();
    expect(projectRecordedPrefix(snapshot, snapshot.events.length + 1)).toBeNull();
  });
});
