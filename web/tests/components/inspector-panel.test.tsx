import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { InspectorPanel } from "@/components/InspectorPanel";
import type {
  IncidentArtifacts,
  SpecialistSummary,
  WarrantHistoryItem,
} from "@/lib/types";

const artifacts: IncidentArtifacts = {
  evidence: [
    {
      classification: "UNTRUSTED_EVIDENCE",
      id: "ev-1",
      label: "Sanitized worker log",
      kind: "log",
      sha256: "c".repeat(64),
      capturedAt: "2026-07-14T00:00:00Z",
      content: "delivery id accepted twice",
      tags: ["instruction-like-content-removed"],
    },
  ],
  diff: "@@ -1 +1 @@\n-vulnerable\n+atomic",
  tests: [
    {
      id: "victim.candidate-race",
      label: "candidate race",
      state: "passed",
      durationMs: 812,
      receiptSha256: "d".repeat(64),
    },
  ],
  warrant: null,
};

const summaries: SpecialistSummary[] = [
  {
    kind: "INSPECTOR",
    runId: "run-inspector",
    rawPublicJson: '{"run_id":"run-inspector"}',
    seat: "Inspector",
    model: "gpt-5.6-terra",
    effort: "medium",
    escalationCount: 0,
    phase: "mechanism-analysis",
    outputSha256: "1".repeat(64),
    semanticSha256: "2".repeat(64),
    createdAt: "2026-07-14T00:00:00Z",
    mechanism: "CHECK_THEN_INSERT_RACE",
    evidenceIds: ["ev-1"],
    falsifiers: ["serialize receipt and outbox insertion"],
  },
  {
    kind: "PROSECUTOR",
    runId: "run-prosecutor",
    rawPublicJson: '{"run_id":"run-prosecutor"}',
    seat: "Prosecutor",
    model: "gpt-5.6-luna",
    effort: "low",
    escalationCount: 0,
    phase: "hypothesis-challenge",
    outputSha256: "3".repeat(64),
    semanticSha256: "4".repeat(64),
    createdAt: "2026-07-14T00:00:01Z",
    outcome: "NO_SUPPORTED_RIVAL",
    rivalMechanism: null,
    counterexampleIds: ["duplicate-delivery"],
    testIds: ["victim.duplicate-race.candidate"],
    evidenceIds: ["ev-1"],
  },
  {
    kind: "COUNSEL",
    runId: "run-counsel",
    rawPublicJson: '{"run_id":"run-counsel"}',
    seat: "Counsel",
    model: "gpt-5.6-terra",
    effort: "high",
    escalationCount: 1,
    phase: "test-failure-repair",
    outputSha256: "5".repeat(64),
    semanticSha256: "6".repeat(64),
    createdAt: "2026-07-14T00:00:02Z",
    candidateId: "candidate-2",
    patchSha256: "7".repeat(64),
    patchDefense: "Atomic receipt and outbox insertion.",
    evidenceIds: ["ev-1"],
    testIntentions: [
      {
        catalogId: "victim.duplicate-race.candidate",
        purpose: "prove exactly-once delivery",
      },
    ],
  },
];

const warrants: WarrantHistoryItem[] = [
  {
    warrantId: "war-failed",
    canonicalSha256: "8".repeat(64),
    bindingHashes: {
      patchSha256: "7".repeat(64),
      baseSha: "b".repeat(40),
      repositoryManifestSha256: "9".repeat(64),
      reviewedEvidenceManifestSha256: "a".repeat(64),
      reviewedTimelineHead: "c".repeat(64),
      verdictSha256: "d".repeat(64),
      authoritySnapshotSha256: "e".repeat(64),
      testPlanSha256: "f".repeat(64),
      runnerDigest: "1".repeat(64),
      environmentDigest: "2".repeat(64),
    },
    approvalStatus: "APPROVED",
    approvalId: "apr-failed",
    consumptionStatus: "CONSUMED",
    executionStatus: "TEST_FAILED",
    receiptIds: ["test-failed-1"],
    createdAt: "2026-07-14T00:01:00Z",
    expiresAt: "2099-07-14T00:16:00Z",
    consumedAt: "2026-07-14T00:02:00Z",
  },
  {
    warrantId: "war-revision",
    canonicalSha256: "3".repeat(64),
    bindingHashes: {
      patchSha256: "4".repeat(64),
      baseSha: "b".repeat(40),
      repositoryManifestSha256: "9".repeat(64),
      reviewedEvidenceManifestSha256: "a".repeat(64),
      reviewedTimelineHead: "5".repeat(64),
      verdictSha256: "6".repeat(64),
      authoritySnapshotSha256: "7".repeat(64),
      testPlanSha256: "f".repeat(64),
      runnerDigest: "1".repeat(64),
      environmentDigest: "2".repeat(64),
    },
    approvalStatus: "PENDING_APPROVAL",
    approvalId: null,
    consumptionStatus: "NOT_MATERIALIZED",
    executionStatus: "NOT_EXECUTED",
    receiptIds: [],
    createdAt: "2026-07-14T00:03:00Z",
    expiresAt: "2099-07-14T00:18:00Z",
    consumedAt: null,
  },
];

describe("InspectorPanel", () => {
  it("exposes evidence, diff, tests, and warrant as keyboard-operable tabs", async () => {
    const user = userEvent.setup();
    render(<InspectorPanel artifacts={artifacts} summaries={summaries} warrants={warrants} />);

    const evidenceTab = screen.getByRole("tab", { name: "Evidence" });
    const evidencePanel = screen.getByRole("tabpanel");
    expect(evidenceTab).toHaveAttribute("aria-selected", "true");
    expect(evidencePanel).toHaveAttribute("tabindex", "0");
    evidenceTab.focus();
    await user.tab();
    expect(evidencePanel).toHaveFocus();
    expect(screen.getByText("Sanitized worker log")).toBeVisible();
    expect(screen.getByText("Untrusted evidence")).toBeVisible();
    expect(screen.getByLabelText("Sanitized worker log sanitized evidence content")).toHaveAttribute(
      "tabindex",
      "0",
    );
    await user.click(screen.getByRole("tab", { name: "Diff" }));
    expect(screen.getByLabelText("Candidate patch diff")).toHaveAttribute("tabindex", "0");
    expect(screen.getByText(/atomic/)).toBeVisible();
    await user.click(screen.getByRole("tab", { name: "Tests" }));
    expect(screen.getByText("candidate race")).toBeVisible();
    expect(screen.getByText("d".repeat(64))).toBeVisible();
    await user.click(screen.getByRole("tab", { name: "Warrants" }));
    expect(screen.getByText("war-failed")).toBeVisible();
  });

  it("renders only typed specialist facts in accessible expandable summaries", async () => {
    render(<InspectorPanel artifacts={artifacts} summaries={summaries} warrants={warrants} />);

    await userEvent.click(screen.getByRole("tab", { name: "Specialists" }));
    const inspector = screen.getByTestId("specialist-summary-run-inspector");
    expect(within(inspector).getByText("Check then insert race")).toBeVisible();
    expect(within(inspector).getByText("ev-1")).toBeVisible();
    const prosecutor = screen.getByTestId("specialist-summary-run-prosecutor");
    expect(within(prosecutor).getByText("No supported rival")).toBeVisible();
    expect(within(prosecutor).getByText("victim.duplicate-race.candidate")).toBeVisible();
    const counsel = screen.getByTestId("specialist-summary-run-counsel");
    expect(within(counsel).getByText("Atomic receipt and outbox insertion.")).toBeVisible();
    expect(within(counsel).getByText("candidate-2")).toBeVisible();
    expect(within(counsel).getByText("7".repeat(64))).toBeVisible();
    expect(screen.getAllByRole("group", { name: /specialist summary/i })).toHaveLength(3);
  });

  it("keeps failed and replacement warrants with safe bindings and receipt identity", async () => {
    render(<InspectorPanel artifacts={artifacts} summaries={summaries} warrants={warrants} />);

    await userEvent.click(screen.getByRole("tab", { name: "Warrants" }));
    const failed = screen.getByTestId("warrant-history-war-failed");
    expect(failed).toHaveTextContent("Test failed");
    expect(failed).toHaveTextContent("Consumed");
    expect(failed).toHaveTextContent("test-failed-1");
    expect(failed).toHaveTextContent("8".repeat(64));
    expect(failed).toHaveTextContent("7".repeat(64));
    const replacement = screen.getByTestId("warrant-history-war-revision");
    expect(replacement).toHaveTextContent("Pending approval");
    expect(replacement).toHaveTextContent("Not materialized");
    expect(screen.getByRole("tabpanel")).not.toHaveTextContent(/nonce|secret/i);
  });
});
