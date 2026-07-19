import { SEAT_ORDER } from "./tokens";
import { presentRecordedPlan } from "./scenarios";
import type {
  EventVisualState,
  IncidentRoomSnapshot,
  SeatName,
  SpecialistSummary,
  TimelineEvent,
} from "./types";

const SHA256 = /^[0-9a-f]{64}$/;
const STORY_EVENT_KINDS = new Set([
  "INCIDENT_OPENED",
  "REPRODUCTION_STARTED",
  "EVIDENCE_CAPTURED",
  "TEST_FAILED",
  "VERDICT",
  "REASONING_ESCALATED",
  "WARRANT_APPROVED",
  "EXECUTION_STARTED",
  "VERIFIED",
  "BAILIFF_COMPLETED",
]);

export interface RecordedSource {
  kind: "event" | "specialist";
  id: string;
  sha256: string;
  rawPublicJson: string;
}

export interface RoomMoment {
  id: string;
  sequence: number;
  kind: string;
  actor: string;
  seat: SeatName | null;
  occurredAt: string;
  headline: string;
  prose: string;
  state: EventVisualState;
  verdict: string | null;
  mention: SeatName | null;
  evidenceIds: readonly string[];
  source: RecordedSource;
}

export interface StoryOmission {
  id: string;
  reason: "INVALID_SOURCE_HASH" | "UNMATCHED_SPECIALIST_OUTPUT" | "INVALID_PUBLIC_JSON";
}

export interface ProofState {
  state: "pending" | "verified" | "unavailable";
  counts: { receipts: number; jobs: number; deliveries: number } | null;
  responseStatuses: number[] | null;
  planId: string | null;
  planLabel: string | null;
  receiptId: string | null;
  receiptSha256: string | null;
}

export interface RoomStory {
  events: readonly TimelineEvent[];
  moments: readonly RoomMoment[];
  omissions: readonly StoryOmission[];
  eventHead: string;
  eventCount: number;
  activeSeat: SeatName | null;
  stage: "evidence" | "analysis" | "repair" | "review" | "approval" | "execution" | "verified";
  barrierState: "sealed" | "pending" | "unlocked";
  baselineCounts: { receipts: number; jobs: number; deliveries: number } | null;
  proof: ProofState;
}

function object(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function text(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function validPublicJson(value: string): boolean {
  try {
    const parsed: unknown = JSON.parse(value);
    return value.length > 1 && parsed !== null && typeof parsed === "object" && !Array.isArray(parsed);
  } catch {
    return false;
  }
}

export function hasSupportedProvenance(sha256: string, rawPublicJson: string): boolean {
  return SHA256.test(sha256) && validPublicJson(rawPublicJson);
}

function seat(value: string): SeatName | null {
  return SEAT_ORDER.includes(value as SeatName) ? value as SeatName : null;
}

function recordedMention(event: TimelineEvent): SeatName | null {
  const details = object(event.details);
  const target = text(details.remand_target) || text(details.handoff_target) || text(details.target_seat);
  return seat(target);
}

function specialistProse(summary: SpecialistSummary): string {
  if (summary.kind === "INSPECTOR") return summary.mechanism;
  if (summary.kind === "COUNSEL") return summary.patchDefense;
  return summary.rivalMechanism ?? summary.outcome;
}

function specialistMoment(event: TimelineEvent, summary: SpecialistSummary): RoomMoment | null {
  if (!hasSupportedProvenance(summary.outputSha256, summary.rawPublicJson)) return null;
  return {
    id: summary.runId,
    sequence: event.sequence,
    kind: summary.kind,
    actor: summary.seat,
    seat: summary.seat,
    occurredAt: summary.createdAt || event.occurredAt,
    headline: summary.phase || summary.kind,
    prose: specialistProse(summary),
    state: "verified",
    verdict: null,
    mention: null,
    evidenceIds: summary.evidenceIds,
    source: {
      kind: "specialist",
      id: summary.runId,
      sha256: summary.outputSha256,
      rawPublicJson: summary.rawPublicJson,
    },
  };
}

function eventProse(event: TimelineEvent): string {
  const details = object(event.details);
  if (event.kind === "VERDICT") return text(details.verdict);
  if (event.kind === "REASONING_ESCALATED") {
    return event.explanation || event.detail || event.summary;
  }
  if (event.detail) return event.detail;
  return event.summary;
}

function eventMoment(event: TimelineEvent): RoomMoment | null {
  if (!hasSupportedProvenance(event.eventHash, event.rawPublicJson)) return null;
  const details = object(event.details);
  return {
    id: event.id,
    sequence: event.sequence,
    kind: event.kind,
    actor: event.actor,
    seat: seat(event.actor),
    occurredAt: event.occurredAt,
    headline: event.summary,
    prose: eventProse(event),
    state: event.state,
    verdict: text(details.verdict) || null,
    mention: recordedMention(event),
    evidenceIds: event.evidenceIds ?? [],
    source: {
      kind: "event",
      id: event.id,
      sha256: event.eventHash,
      rawPublicJson: event.rawPublicJson,
    },
  };
}

function recordedCounts(value: unknown): ProofState["counts"] {
  const counts = object(value);
  const receipts = counts.receipts;
  const jobs = counts.jobs;
  const deliveries = counts.deliveries;
  if (![receipts, jobs, deliveries].every((item) => (
    typeof item === "number" && Number.isInteger(item) && item >= 0
  ))) {
    return null;
  }
  return {
    receipts: Number(receipts),
    jobs: Number(jobs),
    deliveries: Number(deliveries),
  };
}

function recordedStatuses(value: unknown): number[] | null {
  if (
    !Array.isArray(value)
    || !value.length
    || !value.every((item) => (
      typeof item === "number" && Number.isInteger(item) && item >= 100 && item <= 599
    ))
  ) {
    return null;
  }
  return [...value];
}

function countsFromEvidence(snapshot: IncidentRoomSnapshot) {
  for (const evidence of snapshot.artifacts.evidence) {
    if (!evidence.content) continue;
    try {
      const counts = recordedCounts(object(JSON.parse(evidence.content)).counts);
      if (counts) return counts;
    } catch {
      // Sanitized evidence is untrusted and malformed JSON is not a proof source.
    }
  }
  return null;
}

export function proofFromSnapshot(snapshot: IncidentRoomSnapshot): ProofState {
  const verified = snapshot.events.find((event) =>
    event.kind === "VERIFIED" && hasSupportedProvenance(event.eventHash, event.rawPublicJson));
  const details = object(verified?.details);
  const receiptId = text(details.receipt_id);
  const result = snapshot.artifacts.tests.find((test) => test.id === receiptId);
  if (!verified || !result) {
    return {
      state: "pending",
      counts: null,
      responseStatuses: null,
      planId: null,
      planLabel: null,
      receiptId: null,
      receiptSha256: null,
    };
  }
  const presentation = presentRecordedPlan(result.label);
  const unavailable: ProofState = {
    state: "unavailable",
    counts: null,
    responseStatuses: null,
    planId: presentation.planId,
    planLabel: presentation.label,
    receiptId: result.id,
    receiptSha256: null,
  };
  if (
    result.state !== "passed" ||
    result.detail !== "TRUSTED_HTTP_POSTGRES_INVARIANT_MATCHED" ||
    !result.receiptSha256 ||
    !SHA256.test(result.receiptSha256)
  ) {
    return unavailable;
  }
  const counts = recordedCounts(result.trustedObservation?.counts);
  const responseStatuses = recordedStatuses(result.trustedObservation?.responseStatuses);
  if (
    !presentation.known
    || !counts
    || (presentation.scenario === "webhook-payload-equivalence" && !responseStatuses)
  ) return unavailable;
  return {
    state: "verified",
    counts,
    responseStatuses,
    planId: presentation.planId,
    planLabel: presentation.label,
    receiptId: result.id,
    receiptSha256: result.receiptSha256,
  };
}

function stageFromEvents(events: readonly TimelineEvent[], proof: ProofState): RoomStory["stage"] {
  const kinds = new Set(events.map((event) => event.kind));
  if (proof.state === "verified" || kinds.has("VERIFIED")) return "verified";
  if (kinds.has("EXECUTION_STARTED")) return "execution";
  if (kinds.has("WARRANT_APPROVED") || kinds.has("VERDICT")) return "approval";
  if (kinds.has("REASONING_ESCALATED")) return "review";
  if (kinds.has("PATCH_PROPOSED")) return "repair";
  if (kinds.has("AGENT_OUTPUT_RECORDED")) return "analysis";
  return "evidence";
}

export function buildRoomStory(snapshot: IncidentRoomSnapshot): RoomStory {
  const events = [...snapshot.events].sort((left, right) =>
    left.sequence - right.sequence || left.id.localeCompare(right.id));
  const supportedEvents = events.filter((event) =>
    hasSupportedProvenance(event.eventHash, event.rawPublicJson));
  const specialists = new Map(snapshot.specialistSummaries.map((summary) => [summary.outputSha256, summary]));
  const moments: RoomMoment[] = [];
  const omissions: StoryOmission[] = [];

  for (const event of events) {
    if (event.kind === "AGENT_OUTPUT_RECORDED") {
      const outputSha256 = text(object(event.details).output_sha256);
      const summary = specialists.get(outputSha256);
      if (!summary) {
        omissions.push({ id: event.id, reason: "UNMATCHED_SPECIALIST_OUTPUT" });
        continue;
      }
      const moment = specialistMoment(event, summary);
      if (moment) moments.push(moment);
      else omissions.push({ id: summary.runId, reason: SHA256.test(summary.outputSha256)
        ? "INVALID_PUBLIC_JSON"
        : "INVALID_SOURCE_HASH" });
      continue;
    }
    if (!STORY_EVENT_KINDS.has(event.kind)) continue;
    const moment = eventMoment(event);
    if (moment) moments.push(moment);
    else omissions.push({ id: event.id, reason: SHA256.test(event.eventHash)
      ? "INVALID_PUBLIC_JSON"
      : "INVALID_SOURCE_HASH" });
  }

  const proof = proofFromSnapshot(snapshot);
  const tail = events.at(-1);
  const eventHead = tail && hasSupportedProvenance(tail.eventHash, tail.rawPublicJson)
    ? tail.eventHash
    : "";
  const stage = stageFromEvents(supportedEvents, proof);
  const activeSeat = stage === "verified"
    ? null
    : [...moments].reverse().find((moment) => moment.seat)?.seat ?? null;
  const approved = supportedEvents.some((event) => event.kind === "WARRANT_APPROVED");

  return {
    events,
    moments,
    omissions,
    eventHead,
    eventCount: events.length,
    activeSeat,
    stage,
    barrierState: approved ? "unlocked" : snapshot.pendingWarrant ? "pending" : "sealed",
    baselineCounts: countsFromEvidence(snapshot),
    proof,
  };
}
