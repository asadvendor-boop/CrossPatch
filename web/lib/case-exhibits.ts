import { hasSupportedProvenance, proofFromSnapshot } from "./room-story";
import { presentRecordedPlan } from "./scenarios";
import { DEFAULT_SEATS, SEAT_ORDER } from "./tokens";
import type {
  Effort,
  EvidenceItem,
  IncidentRoomSnapshot,
  IncidentState,
  PublishedCaseSummary,
  SeatName,
  SpecialistSummary,
  TestResult,
  TimelineEvent,
  WarrantHistoryItem,
} from "./types";

export interface SeatSpendMetric {
  seat: SeatName;
  effort: Effort;
  escalationCount: number;
  costUsd: number;
}

export interface CaseMetrics {
  evidenceToVerifiedMs: number | null;
  humanGateDwellMs: number | null;
  executionVerificationMs: number | null;
  totalSpendUsd: number | null;
  seatSpend: SeatSpendMetric[];
}

export interface PublishedSetMetrics {
  caseCount: number;
  measuredEvidenceToVerifiedCount: number;
  medianEvidenceToVerifiedMs: number | null;
  measuredHumanGateDwellCount: number;
  medianHumanGateDwellMs: number | null;
  measuredExecutionVerificationCount: number;
  medianExecutionVerificationMs: number | null;
  totalSpendUsd: number | null;
  seatSpend: SeatSpendMetric[];
}

export interface AuthorityLifecycleItem {
  warrantId: string;
  canonicalSha256: string;
  issuedAt: string;
  approvedAt: string | null;
  approver: string | null;
  consumedAt: string | null;
  failureAt: string | null;
  receiptIds: readonly string[];
  executionStatus: string;
  successorWarrantId: string | null;
  successorCanonicalSha256: string | null;
}

export interface HypothesisEvidenceCitation {
  id: string;
  label: string;
  sha256: string;
}

export interface HypothesisControlCitation {
  reference: string;
  kind: "evidence" | "test";
  label: string;
  sha256: string;
  state: "passed" | "failed" | null;
  receiptSha256: string | null;
}

export interface CompetingHypotheses {
  inspector: {
    runId: string;
    outputSha256: string;
    mechanism: string;
    evidence: readonly HypothesisEvidenceCitation[];
    falsifiers: readonly string[];
  };
  prosecutor: {
    runId: string;
    outputSha256: string;
    outcome: "SUPPORTED_RIVAL";
    rivalMechanism: string;
    evidence: readonly HypothesisEvidenceCitation[];
  };
  negativeControls: readonly HypothesisControlCitation[];
  eliminated: {
    side: "PROSECUTOR_RIVAL";
    mechanism: string;
  };
  verdict: {
    value: "CLEAR";
    eventId: string;
    eventSha256: string;
  };
}

interface Counts {
  receipts: number;
  jobs: number;
  deliveries: number;
}

const EFFORTS = new Set<Effort>(["none", "low", "medium", "high", "xhigh"]);
const VERDICTS = new Set(["CLEAR", "REMAND", "BLOCK", "ABSTAIN"]);
const SHA256 = /^[0-9a-f]{64}$/;

function object(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function text(value: unknown): string | null {
  return typeof value === "string" && value ? value : null;
}

function timestamp(value: string | null | undefined): number | null {
  if (!value) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function interval(start: string | null | undefined, end: string | null | undefined): number | null {
  const startTime = timestamp(start);
  const endTime = timestamp(end);
  if (startTime === null || endTime === null || endTime < startTime) return null;
  return endTime - startTime;
}

function recordedEvents(snapshot: IncidentRoomSnapshot): TimelineEvent[] {
  return [...snapshot.events]
    .filter((event) => hasSupportedProvenance(event.eventHash, event.rawPublicJson))
    .sort((left, right) => left.sequence - right.sequence || left.id.localeCompare(right.id));
}

function validCount(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}

function countsFromEvidence(snapshot: IncidentRoomSnapshot): Counts | null {
  for (const evidence of snapshot.artifacts.evidence) {
    if (!evidence.content) continue;
    try {
      const counts = object(object(JSON.parse(evidence.content)).counts);
      if (
        validCount(counts.receipts)
        && validCount(counts.jobs)
        && validCount(counts.deliveries)
      ) {
        return {
          receipts: counts.receipts,
          jobs: counts.jobs,
          deliveries: counts.deliveries,
        };
      }
    } catch {
      // Sanitized evidence is untrusted; malformed content is not a source.
    }
  }
  return null;
}

function countPhrase(counts: Counts): string {
  const unit = (value: number, singular: string, plural = `${singular}s`) => (
    `${value} ${value === 1 ? singular : plural}`
  );
  return [
    unit(counts.receipts, "receipt"),
    unit(counts.jobs, "job"),
    `and ${unit(counts.deliveries, "delivery", "deliveries")}`,
  ].join(", ");
}

function durationPhrase(seconds: number): string {
  const rounded = Math.round(seconds);
  const hours = Math.floor(rounded / 3600);
  const minutes = Math.floor((rounded % 3600) / 60);
  const remainder = rounded % 60;
  return [
    hours ? `${hours}h` : null,
    minutes ? `${minutes}m` : null,
    remainder || (!hours && !minutes) ? `${remainder}s` : null,
  ].filter((part): part is string => part !== null).join(" ");
}

export function deriveSummaryWhatHappened(summary: PublishedCaseSummary): string[] {
  const sentences: string[] = [];
  if (summary.verdictPath.at(-1) === "CLEAR") {
    const remands = summary.verdictPath.filter((verdict) => verdict === "REMAND").length;
    sentences.push(
      remands
        ? `The recorded decision returned CLEAR after ${remands} REMAND${remands === 1 ? "" : "s"}.`
        : "The recorded decision returned CLEAR without a REMAND.",
    );
  }
  if (summary.state === "VERIFIED" && summary.durationSeconds !== null) {
    sentences.push(`The repair reached VERIFIED in ${durationPhrase(summary.durationSeconds)}.`);
  }
  if (summary.recordedCostUsd !== null) {
    sentences.push(`Recorded model spend was $${summary.recordedCostUsd.toFixed(4)}.`);
  }
  return sentences;
}

export function deriveWhatHappened(snapshot: IncidentRoomSnapshot): string[] {
  const events = recordedEvents(snapshot);
  const sentences: string[] = [];
  const baseline = countsFromEvidence(snapshot);
  if (baseline) sentences.push(`The baseline recorded ${countPhrase(baseline)}.`);

  const verdicts = events
    .filter((event) => event.kind === "VERDICT")
    .map((event) => text(object(event.details).verdict))
    .filter((verdict): verdict is string => verdict !== null && VERDICTS.has(verdict));
  if (verdicts.at(-1) === "CLEAR") {
    const remands = verdicts.filter((verdict) => verdict === "REMAND").length;
    sentences.push(
      remands
        ? `The Magistrate returned CLEAR after ${remands} REMAND${remands === 1 ? "" : "s"}.`
        : "The Magistrate returned CLEAR without a REMAND.",
    );
  }

  const proof = proofFromSnapshot(snapshot);
  const plan = proof.planId ? presentRecordedPlan(proof.planId) : null;
  if (plan && !plan.known) {
    sentences.push(`${plan.label}.`);
  } else if (proof.state === "verified" && proof.counts && plan) {
    if (plan.scenario === "webhook-payload-equivalence" && proof.responseStatuses) {
      sentences.push(
        `Trusted verification recorded HTTP ${proof.responseStatuses.join(" / ")} with ${countPhrase(proof.counts)}.`,
      );
    } else if (plan.scenario === "webhook-race") {
      sentences.push(`Trusted verification recorded ${countPhrase(proof.counts)}.`);
    }
  }
  return sentences;
}

function linkedSpecialistEvent(
  summary: SpecialistSummary,
  events: readonly TimelineEvent[],
): TimelineEvent | null {
  if (!hasSupportedProvenance(summary.outputSha256, summary.rawPublicJson)) return null;
  return [...events].reverse().find((event) => {
    if (event.kind !== "AGENT_OUTPUT_RECORDED") return false;
    const details = object(event.details);
    return details.output_sha256 === summary.outputSha256
      && (details.seat ?? event.actor) === summary.seat;
  }) ?? null;
}

function latestLinkedSummary<T extends SpecialistSummary["kind"]>(
  snapshot: IncidentRoomSnapshot,
  events: readonly TimelineEvent[],
  kind: T,
): { summary: Extract<SpecialistSummary, { kind: T }>; event: TimelineEvent } | null {
  const candidates = snapshot.specialistSummaries.flatMap((summary) => {
    if (summary.kind !== kind) return [];
    const event = linkedSpecialistEvent(summary, events);
    return event ? [{ summary, event }] : [];
  }).sort((left, right) => left.event.sequence - right.event.sequence);
  return candidates.at(-1) as {
    summary: Extract<SpecialistSummary, { kind: T }>;
    event: TimelineEvent;
  } | null;
}

function evidenceCitations(
  evidence: readonly EvidenceItem[],
  ids: readonly string[],
  recordedBefore: string,
): HypothesisEvidenceCitation[] | null {
  if (!ids.length || new Set(ids).size !== ids.length) return null;
  const cutoff = timestamp(recordedBefore);
  if (cutoff === null) return null;
  const citations: HypothesisEvidenceCitation[] = [];
  for (const id of ids) {
    const item = evidence.find((candidate) => candidate.id === id);
    const captured = timestamp(item?.capturedAt);
    if (!item || !SHA256.test(item.sha256) || captured === null || captured > cutoff) return null;
    citations.push({ id: item.id, label: item.label, sha256: item.sha256 });
  }
  return citations;
}

function controlFromEvidence(
  evidence: readonly EvidenceItem[],
  reference: string,
  recordedBefore: string,
): HypothesisControlCitation | null {
  const cutoff = timestamp(recordedBefore);
  const item = evidence.find((candidate) => candidate.id === reference);
  const captured = timestamp(item?.capturedAt);
  if (
    cutoff === null
    || !item
    || !SHA256.test(item.sha256)
    || captured === null
    || captured > cutoff
  ) return null;
  return {
    reference,
    kind: "evidence",
    label: item.label,
    sha256: item.sha256,
    state: null,
    receiptSha256: null,
  };
}

function controlFromTest(
  tests: readonly TestResult[],
  reference: string,
): HypothesisControlCitation | null {
  const item = tests.find((candidate) => candidate.id === reference || candidate.label === reference);
  if (
    !item
    || (item.state !== "passed" && item.state !== "failed")
    || !item.receiptSha256
    || !SHA256.test(item.receiptSha256)
  ) return null;
  return {
    reference,
    kind: "test",
    label: item.label,
    sha256: item.receiptSha256,
    state: item.state,
    receiptSha256: item.receiptSha256,
  };
}

export function deriveCompetingHypotheses(
  snapshot: IncidentRoomSnapshot,
): CompetingHypotheses | null {
  const events = recordedEvents(snapshot);
  const inspectorPair = latestLinkedSummary(snapshot, events, "INSPECTOR");
  const prosecutorPair = latestLinkedSummary(snapshot, events, "PROSECUTOR");
  if (!inspectorPair || !prosecutorPair) return null;
  const inspector = inspectorPair.summary;
  const prosecutor = prosecutorPair.summary;
  if (
    !inspector.mechanism
    || !inspector.falsifiers.length
    || inspector.falsifiers.some((value) => !value)
    || prosecutor.outcome !== "SUPPORTED_RIVAL"
    || !prosecutor.rivalMechanism
    || !prosecutor.counterexampleIds.length
    || !prosecutor.testIds.length
  ) return null;

  const inspectorEvidence = evidenceCitations(
    snapshot.artifacts.evidence,
    inspector.evidenceIds,
    inspector.createdAt,
  );
  const prosecutorEvidence = evidenceCitations(
    snapshot.artifacts.evidence,
    prosecutor.evidenceIds,
    prosecutor.createdAt,
  );
  if (!inspectorEvidence || !prosecutorEvidence) return null;

  const negativeControls: HypothesisControlCitation[] = [];
  for (const reference of prosecutor.counterexampleIds) {
    const control = controlFromEvidence(
      snapshot.artifacts.evidence,
      reference,
      prosecutor.createdAt,
    ) ?? controlFromTest(snapshot.artifacts.tests, reference);
    if (!control) return null;
    negativeControls.push(control);
  }
  for (const reference of prosecutor.testIds) {
    const control = controlFromTest(snapshot.artifacts.tests, reference);
    if (!control) return null;
    negativeControls.push(control);
  }
  if (
    new Set(negativeControls.map((control) => `${control.kind}:${control.reference}`)).size
      !== negativeControls.length
    || !negativeControls.some((control) => control.kind === "test")
  ) return null;

  const verdict = events.filter((event) => event.kind === "VERDICT").at(-1);
  if (
    !verdict
    || object(verdict.details).verdict !== "CLEAR"
    || verdict.sequence <= inspectorPair.event.sequence
    || verdict.sequence <= prosecutorPair.event.sequence
  ) return null;

  return {
    inspector: {
      runId: inspector.runId,
      outputSha256: inspector.outputSha256,
      mechanism: inspector.mechanism,
      evidence: inspectorEvidence,
      falsifiers: [...inspector.falsifiers],
    },
    prosecutor: {
      runId: prosecutor.runId,
      outputSha256: prosecutor.outputSha256,
      outcome: "SUPPORTED_RIVAL",
      rivalMechanism: prosecutor.rivalMechanism,
      evidence: prosecutorEvidence,
    },
    negativeControls,
    eliminated: {
      side: "PROSECUTOR_RIVAL",
      mechanism: prosecutor.rivalMechanism,
    },
    verdict: {
      value: "CLEAR",
      eventId: verdict.id,
      eventSha256: verdict.eventHash,
    },
  };
}

function firstEvent(events: readonly TimelineEvent[], kind: string): TimelineEvent | null {
  return events.find((event) => event.kind === kind) ?? null;
}

function matchingOutcome(
  events: readonly TimelineEvent[],
  kind: string,
  warrantId: string,
): TimelineEvent | null {
  return events.find((event) => (
    event.kind === kind && object(event.details).warrant_id === warrantId
  )) ?? null;
}

function spendMetrics(events: readonly TimelineEvent[]): SeatSpendMetric[] {
  const result: SeatSpendMetric[] = [];
  const escalationBySeat = new Map<SeatName, number>();
  for (const event of events) {
    const details = object(event.details);
    const eventSeat = text(details.seat);
    if (event.kind === "REASONING_ESCALATED" && SEAT_ORDER.includes(eventSeat as SeatName)) {
      const declared = details.escalation_count;
      const prior = escalationBySeat.get(eventSeat as SeatName) ?? 0;
      escalationBySeat.set(
        eventSeat as SeatName,
        typeof declared === "number" && Number.isInteger(declared) && declared >= prior
          ? declared
          : prior + 1,
      );
      continue;
    }
    if (event.kind !== "MODEL_METRICS_RECORDED" || !SEAT_ORDER.includes(eventSeat as SeatName)) {
      continue;
    }
    const cost = details.cost_usd;
    const effort = text(details.effort);
    if (
      typeof cost !== "number"
      || !Number.isFinite(cost)
      || cost < 0
      || !effort
      || !EFFORTS.has(effort as Effort)
    ) {
      continue;
    }
    result.push({
      seat: eventSeat as SeatName,
      effort: effort as Effort,
      escalationCount: escalationBySeat.get(eventSeat as SeatName) ?? 0,
      costUsd: cost,
    });
  }
  return result;
}

export function deriveCaseMetrics(snapshot: IncidentRoomSnapshot): CaseMetrics {
  const events = recordedEvents(snapshot);
  const evidence = firstEvent(events, "EVIDENCE_CAPTURED");
  const verified = firstEvent(events, "VERIFIED");
  const execution = verified
    ? matchingOutcome(events, "EXECUTION_STARTED", text(object(verified.details).warrant_id) ?? "")
    : null;

  let humanGateDwellMs: number | null = null;
  for (const warrant of snapshot.warrants) {
    const approval = events.find((event) => {
      if (event.kind !== "WARRANT_APPROVED") return false;
      const details = object(event.details);
      return details.warrant_id === warrant.warrantId
        || details.warrant_sha256 === warrant.canonicalSha256;
    });
    const measured = interval(warrant.createdAt, approval?.occurredAt);
    if (measured !== null) {
      humanGateDwellMs = measured;
      break;
    }
  }

  const seatSpend = spendMetrics(events);
  return {
    evidenceToVerifiedMs: interval(evidence?.occurredAt, verified?.occurredAt),
    humanGateDwellMs,
    executionVerificationMs: interval(execution?.occurredAt, verified?.occurredAt),
    totalSpendUsd: seatSpend.length
      ? Number(seatSpend.reduce((sum, item) => sum + item.costUsd, 0).toFixed(12))
      : null,
    seatSpend,
  };
}

function median(values: readonly number[]): number | null {
  if (!values.length) return null;
  const ordered = [...values].sort((left, right) => left - right);
  const middle = Math.floor(ordered.length / 2);
  return ordered.length % 2
    ? ordered[middle] ?? null
    : ((ordered[middle - 1] ?? 0) + (ordered[middle] ?? 0)) / 2;
}

export function derivePublishedSetMetrics(
  snapshots: readonly IncidentRoomSnapshot[],
): PublishedSetMetrics {
  const metrics = snapshots.map(deriveCaseMetrics);
  const evidenceToVerified = metrics.flatMap((item) => (
    item.evidenceToVerifiedMs === null ? [] : [item.evidenceToVerifiedMs]
  ));
  const gateDwell = metrics.flatMap((item) => (
    item.humanGateDwellMs === null ? [] : [item.humanGateDwellMs]
  ));
  const execution = metrics.flatMap((item) => (
    item.executionVerificationMs === null ? [] : [item.executionVerificationMs]
  ));
  const seatSpend = metrics.flatMap((item) => item.seatSpend);
  return {
    caseCount: snapshots.length,
    measuredEvidenceToVerifiedCount: evidenceToVerified.length,
    medianEvidenceToVerifiedMs: median(evidenceToVerified),
    measuredHumanGateDwellCount: gateDwell.length,
    medianHumanGateDwellMs: median(gateDwell),
    measuredExecutionVerificationCount: execution.length,
    medianExecutionVerificationMs: median(execution),
    totalSpendUsd: seatSpend.length
      ? Number(seatSpend.reduce((sum, item) => sum + item.costUsd, 0).toFixed(12))
      : null,
    seatSpend,
  };
}

export function derivePublishedSummaryMetrics(
  summaries: readonly PublishedCaseSummary[],
): PublishedSetMetrics {
  const evidenceToVerified = summaries.flatMap((summary) => (
    summary.evidenceToVerifiedSeconds === null
      ? []
      : [summary.evidenceToVerifiedSeconds * 1_000]
  ));
  const gateDwell = summaries.flatMap((summary) => (
    summary.humanGateDwellSeconds === null
      ? []
      : [summary.humanGateDwellSeconds * 1_000]
  ));
  const execution = summaries.flatMap((summary) => (
    summary.executionVerificationSeconds === null
      ? []
      : [summary.executionVerificationSeconds * 1_000]
  ));
  const costs = summaries.flatMap((summary) => (
    summary.recordedCostUsd === null ? [] : [summary.recordedCostUsd]
  ));
  return {
    caseCount: summaries.length,
    measuredEvidenceToVerifiedCount: evidenceToVerified.length,
    medianEvidenceToVerifiedMs: median(evidenceToVerified),
    measuredHumanGateDwellCount: gateDwell.length,
    medianHumanGateDwellMs: median(gateDwell),
    measuredExecutionVerificationCount: execution.length,
    medianExecutionVerificationMs: median(execution),
    totalSpendUsd: costs.length === summaries.length && summaries.length > 0
      ? Number(costs.reduce((sum, cost) => sum + cost, 0).toFixed(12))
      : null,
    seatSpend: summaries.flatMap((summary) => summary.seatSpend),
  };
}

function matchingApproval(
  events: readonly TimelineEvent[],
  warrant: WarrantHistoryItem,
): TimelineEvent | null {
  return events.find((event) => {
    if (event.kind !== "WARRANT_APPROVED") return false;
    const details = object(event.details);
    return details.warrant_id === warrant.warrantId
      || details.warrant_sha256 === warrant.canonicalSha256;
  }) ?? null;
}

export function deriveAuthorityLifecycle(
  snapshot: IncidentRoomSnapshot,
): AuthorityLifecycleItem[] {
  const events = recordedEvents(snapshot);
  const warrants = [...snapshot.warrants].sort((left, right) => (
    (timestamp(left.createdAt) ?? Number.MAX_SAFE_INTEGER)
    - (timestamp(right.createdAt) ?? Number.MAX_SAFE_INTEGER)
    || left.warrantId.localeCompare(right.warrantId)
  ));
  return warrants.map((warrant, index) => {
    const approval = matchingApproval(events, warrant);
    const failure = matchingOutcome(events, "TEST_FAILED", warrant.warrantId);
    const successor = warrant.executionStatus === "TEST_FAILED"
      ? warrants[index + 1] ?? null
      : null;
    return {
      warrantId: warrant.warrantId,
      canonicalSha256: warrant.canonicalSha256,
      issuedAt: warrant.createdAt,
      approvedAt: approval?.occurredAt ?? null,
      approver: text(object(approval?.details).approver_identity),
      consumedAt: warrant.consumedAt,
      failureAt: failure?.occurredAt ?? null,
      receiptIds: warrant.receiptIds,
      executionStatus: warrant.executionStatus,
      successorWarrantId: successor?.warrantId ?? null,
      successorCanonicalSha256: successor?.canonicalSha256 ?? null,
    };
  });
}

function stateForPrefix(events: readonly TimelineEvent[]): IncidentState {
  let state: IncidentState = "OPEN";
  for (const event of events) {
    const details = object(event.details);
    if (event.kind === "REPRODUCTION_STARTED") state = "REPRODUCING";
    else if (event.kind === "EVIDENCE_CAPTURED") state = "EVIDENCE_READY";
    else if (event.kind === "ANALYSIS_STARTED" || event.kind === "AGENT_OUTPUT_RECORDED") {
      state = "ANALYZING";
    } else if (event.kind === "PATCH_PROPOSED") state = "PATCHING";
    else if (event.kind === "REASONING_ESCALATED") state = "REMANDED";
    else if (event.kind === "VERDICT") {
      const verdict = details.verdict;
      state = verdict === "CLEAR"
        ? "APPROVAL_PENDING"
        : verdict === "REMAND"
          ? "REMANDED"
          : verdict === "BLOCK"
            ? "BLOCKED"
            : verdict === "ABSTAIN"
              ? "ABSTAINED"
              : state;
    } else if (event.kind === "WARRANT_APPROVED") state = "APPROVED";
    else if (event.kind === "EXECUTION_STARTED") state = "EXECUTING";
    else if (event.kind === "TEST_FAILED") state = "TEST_FAILED";
    else if (event.kind === "VERIFIED") state = "VERIFIED";
  }
  return state;
}

export function projectRecordedPrefix(
  snapshot: IncidentRoomSnapshot,
  eventCount: number,
): IncidentRoomSnapshot | null {
  if (!Number.isInteger(eventCount) || eventCount < 0 || eventCount > snapshot.events.length) {
    return null;
  }
  const events = snapshot.events.slice(0, eventCount);
  const terminal = eventCount === snapshot.events.length;
  const cutoff = timestamp(events.at(-1)?.occurredAt);
  const hasKind = (kind: string) => events.some((event) => event.kind === kind);
  const outputHashes = new Set(
    events
      .filter((event) => event.kind === "AGENT_OUTPUT_RECORDED")
      .map((event) => text(object(event.details).output_sha256))
      .filter((value): value is string => value !== null),
  );
  const specialistSummaries = snapshot.specialistSummaries.filter((summary) => (
    outputHashes.has(summary.outputSha256)
    && (cutoff === null || (timestamp(summary.createdAt) ?? Number.MAX_SAFE_INTEGER) <= cutoff)
  ));
  const receiptIds = new Set(
    events.flatMap((event) => {
      if (event.kind !== "TEST_FAILED" && event.kind !== "VERIFIED") return [];
      const details = object(event.details);
      return [text(details.test_run_id) ?? text(details.receipt_id)].filter(
        (value): value is string => value !== null,
      );
    }),
  );
  const warrants = snapshot.warrants.filter((warrant) => (
    cutoff !== null && (timestamp(warrant.createdAt) ?? Number.MAX_SAFE_INTEGER) <= cutoff
  ));
  const seats = snapshot.seats.map((seat) => {
    const defaults = DEFAULT_SEATS.find((item) => item.name === seat.name) ?? seat;
    const escalation = events
      .filter((event) => (
        event.kind === "REASONING_ESCALATED" && object(event.details).seat === seat.name
      ))
      .at(-1);
    const escalationDetails = object(escalation?.details);
    const count = escalationDetails.escalation_count;
    const effort = text(escalationDetails.effort);
    const completed = specialistSummaries.some((summary) => summary.seat === seat.name)
      || (seat.name === "Magistrate" && hasKind("VERDICT"))
      || (seat.name === "Bailiff" && hasKind("BAILIFF_COMPLETED"));
    return {
      ...seat,
      effort: effort && EFFORTS.has(effort as Effort) ? effort as Effort : defaults.effort,
      escalationCount: typeof count === "number" && Number.isInteger(count) ? count : 0,
      state: completed ? "complete" as const : "idle" as const,
    };
  });
  const evidence = snapshot.artifacts.evidence.filter((item) => (
    cutoff !== null && (timestamp(item.capturedAt) ?? Number.MAX_SAFE_INTEGER) <= cutoff
  ));

  return {
    ...snapshot,
    incident: {
      ...snapshot.incident,
      state: terminal ? snapshot.incident.state : stateForPrefix(events),
      updatedAt: events.at(-1)?.occurredAt ?? snapshot.incident.createdAt,
    },
    seats,
    events,
    specialistSummaries,
    warrants,
    artifacts: {
      evidence,
      diff: hasKind("PATCH_PROPOSED") ? snapshot.artifacts.diff : null,
      tests: snapshot.artifacts.tests.filter((test) => receiptIds.has(test.id)),
      warrant: null,
    },
    pendingWarrant: null,
  };
}
