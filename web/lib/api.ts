import { DEFAULT_SEATS, SEAT_ORDER } from "./tokens";
import { readAccessToken, readApprovalCredentials } from "./session";
import type { EvidenceProfile, OperatorScenario } from "./scenarios";
import type {
  Effort,
  EvidenceItem,
  IncidentArtifacts,
  IncidentRoomSnapshot,
  IncidentState,
  PendingWarrant,
  PublicWarrantAnatomy,
  PublishedCaseDetail,
  PublishedCaseSummary,
  PublishedCaseVerdictStep,
  PublishedSeatSpend,
  SeatRunState,
  SeatView,
  SpecialistSummary,
  TestResult,
  TimelineEvent,
  TrustedObservation,
  WarrantHistoryItem,
} from "./types";

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

export interface OpenedIncident {
  id: string;
  title: string;
  scenario: OperatorScenario;
  state: IncidentState;
}

type JsonObject = Record<string, unknown>;

function object(value: unknown): JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonObject)
    : {};
}

function value(record: JsonObject, camel: string, snake: string = camel): unknown {
  return record[camel] ?? record[snake];
}

function text(record: JsonObject, camel: string, snake: string = camel, fallback = ""): string {
  const item = value(record, camel, snake);
  return typeof item === "string" || typeof item === "number" ? String(item) : fallback;
}

function number(record: JsonObject, camel: string, snake: string = camel, fallback = 0): number {
  const item = value(record, camel, snake);
  return typeof item === "number" && Number.isFinite(item) ? item : fallback;
}

function strings(input: unknown): string[] {
  return Array.isArray(input) ? input.filter((item): item is string => typeof item === "string") : [];
}

const EFFORTS = new Set<Effort>(["none", "low", "medium", "high", "xhigh"]);
const SEAT_RUN_STATES = new Set<SeatRunState>([
  "idle",
  "working",
  "complete",
  "failed",
  "abstained",
  "unavailable",
]);
const SHA256_HEX = /^[0-9a-f]{64}$/;
const GIT_SHA = /^[0-9a-f]{40}$/;
const PUBLIC_SEAT_NAMES = new Set(SEAT_ORDER);
const PUBLIC_VERDICT_STEPS = new Set<PublishedCaseVerdictStep>([
  "CLEAR",
  "REMAND",
  "BLOCK",
  "ABSTAIN",
]);
const PUBLIC_REMAND_TARGETS = new Set(["Prosecutor", "Inspector", "Counsel"]);
const PUBLIC_WARRANT_ANATOMY_KEYS = [
  "allowed_paths",
  "approver_identity",
  "authority_snapshot_sha256",
  "base_sha",
  "canonical_warrant_sha256",
  "environment_digest",
  "expires_at",
  "format",
  "incident_id",
  "nonce_sha256",
  "patch_sha256",
  "plan_ids",
  "repository_manifest_sha256",
  "reviewed_evidence_manifest_sha256",
  "reviewed_timeline_head",
  "runner_digest",
  "test_plan_sha256",
  "verdict_sha256",
  "warrant_id",
] as const;

function validIsoDate(value: string): boolean {
  return Boolean(value) && Number.isFinite(Date.parse(value));
}

function validAwareIsoDate(value: string): boolean {
  return validIsoDate(value) && /(?:Z|[+-]\d{2}:\d{2})$/.test(value);
}

async function canonicalPublicSha256(canonicalProjectionJson: string): Promise<string> {
  const bytes = new TextEncoder().encode(canonicalProjectionJson);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function sameJsonValue(left: unknown, right: unknown): boolean {
  if (typeof left === "number" && typeof right === "number") return left === right;
  if (left === null || right === null || typeof left !== "object" || typeof right !== "object") {
    return left === right;
  }
  if (Array.isArray(left) || Array.isArray(right)) {
    return Array.isArray(left) && Array.isArray(right) && left.length === right.length &&
      left.every((item, index) => sameJsonValue(item, right[index]));
  }
  const leftRecord = left as JsonObject;
  const rightRecord = right as JsonObject;
  const leftKeys = Object.keys(leftRecord);
  const rightKeys = Object.keys(rightRecord);
  return leftKeys.length === rightKeys.length &&
    leftKeys.every((key) => Object.hasOwn(rightRecord, key) && (
      sameJsonValue(leftRecord[key], rightRecord[key])
    ));
}

function requiredString(record: JsonObject, camel: string, snake: string = camel): string | null {
  const item = value(record, camel, snake);
  return typeof item === "string" && item.trim() ? item : null;
}

function publishedValidationError(scope: "index" | "detail"): never {
  throw new ApiError(
    scope === "index"
      ? "Published case index failed validation"
      : "Published case failed validation",
    502,
  );
}

function effort(input: unknown, fallback: Effort): Effort {
  return typeof input === "string" && EFFORTS.has(input as Effort)
    ? (input as Effort)
    : fallback;
}

function seatRunState(input: unknown): SeatRunState {
  return typeof input === "string" && SEAT_RUN_STATES.has(input as SeatRunState)
    ? (input as SeatRunState)
    : "idle";
}

function escalationCount(input: unknown): number {
  return typeof input === "number" && Number.isInteger(input) && input >= 0 && input <= 2
    ? input
    : 0;
}

function decodeDiff(input: unknown): string | null {
  if (typeof input === "string") return input || null;
  const record = object(input);
  if (record.classification !== "UNTRUSTED_EVIDENCE") return null;
  return typeof record.text === "string" && record.text ? record.text : null;
}

function visualState(kind: string, state: unknown): TimelineEvent["state"] {
  const normalized = typeof state === "string" ? state.toLowerCase() : "";
  if (["failed", "failure", "error", "abstain", "abstained", "block", "blocked"].includes(normalized)) {
    return "failed";
  }
  if (["verified", "passed", "complete", "completed", "clear"].includes(normalized)) {
    return "verified";
  }
  if (["warning", "remand", "remanded", "pending"].includes(normalized)) return "warning";
  if (["active", "running", "started", "working"].includes(normalized)) return "active";
  if (/FAILED|ABSTAIN|BLOCK/.test(kind)) return "failed";
  if (/VERIFIED|PASSED|CLEAR/.test(kind)) return "verified";
  if (/REMAND|ESCALAT/.test(kind)) return "warning";
  return "neutral";
}

export function decodeTimelineEvent(input: unknown): TimelineEvent {
  const record = object(input);
  const payload = object(record.payload);
  const details = object(value(record, "details"));
  const kind = text(record, "kind", "event_type", text(record, "type", "type", "UNKNOWN"));
  const event: TimelineEvent = {
    id: text(record, "id", "event_id"),
    eventHash: text(record, "eventHash", "event_hash"),
    rawPublicJson: JSON.stringify(input, null, 2),
    sequence: number(record, "sequence"),
    kind,
    actor: text(record, "actor", "actor", "system"),
    occurredAt: text(record, "occurredAt", "created_at", new Date(0).toISOString()),
    summary: text(record, "summary", "summary", text(payload, "summary", "summary", kind)),
    detail: text(record, "detail", "detail", text(payload, "detail", "detail")) || null,
    details,
    state: visualState(kind, value(details, "verdict") ?? value(record, "state")),
    evidenceIds: strings(value(record, "evidenceIds", "evidence_ids")),
  };
  event.explanation = text(record, "explanation") || null;
  return event;
}

function warrantApprovalState(input: string): PendingWarrant["approvalState"] {
  const normalized = input.trim().toUpperCase();
  if (normalized === "PENDING" || normalized === "PENDING_APPROVAL") return "pending";
  if (normalized === "APPROVED") return "approved";
  if (normalized === "REJECTED") return "rejected";
  if (normalized === "EXPIRED") return "expired";
  return "unavailable";
}

export function decodeWarrant(input: unknown): PendingWarrant | null {
  if (input === null || input === undefined) return null;
  const record = object(input);
  const id = text(record, "id", "warrant_id");
  if (!id) return null;
  const canonicalValue = value(record, "canonicalDocument", "canonical_document");
  const canonicalDocument = typeof canonicalValue === "string" ? canonicalValue : "";
  let canonical: JsonObject = object(canonicalValue);
  if (typeof canonicalValue === "string") {
    try {
      canonical = object(JSON.parse(canonicalValue) as unknown);
    } catch {
      canonical = {};
    }
  }
  const plans = value(canonical, "executionPlans", "execution_plans");
  const expiresAt = text(record, "expiresAt", "expires_at", text(canonical, "expiresAt", "expires_at"));
  let approvalState = warrantApprovalState(text(record, "approvalState", "status"));
  if (expiresAt && Date.parse(expiresAt) <= Date.now()) approvalState = "expired";
  return {
    id,
    incidentId: text(record, "incidentId", "incident_id", text(canonical, "incidentId", "incident_id")),
    warrantHash: text(record, "warrantHash", "warrant_sha256"),
    canonicalDocument,
    patchHash: text(canonical, "patchHash", "patch_sha256", text(record, "warrantSha256", "warrant_sha256")),
    baseSha: text(canonical, "baseSha", "base_sha"),
    paths: strings(value(canonical, "paths", "allowed_paths")),
    commands: Array.isArray(plans)
      ? plans.map((plan) => text(object(plan), "planId", "plan_id")).filter(Boolean)
      : [],
    expiresAt,
    approvalState,
  };
}

function decodeEvidence(input: unknown): EvidenceItem[] {
  if (!Array.isArray(input)) return [];
  return input.flatMap((item): EvidenceItem[] => {
    const record = object(item);
    if (text(record, "classification") !== "UNTRUSTED_EVIDENCE") return [];
    return [{
      classification: "UNTRUSTED_EVIDENCE",
      id: text(record, "id", "evidence_id"),
      label: text(record, "label", "provenance", "Sanitized evidence"),
      kind: text(record, "kind", "kind", "evidence"),
      sha256: text(record, "sha256", "sanitized_sha256"),
      capturedAt: text(record, "capturedAt", "captured_at"),
      content: text(record, "content", "text") || null,
      tags: strings(record.tags),
    }];
  });
}

function decodeTrustedObservation(input: unknown): TrustedObservation | null {
  const record = object(input);
  const counts = object(record.counts);
  const receipts = counts.receipts;
  const jobs = counts.jobs;
  const deliveries = counts.deliveries;
  const responseStatuses = value(record, "responseStatuses", "response_statuses");
  if (
    ![receipts, jobs, deliveries].every((item) => (
      typeof item === "number" && Number.isInteger(item) && item >= 0
    ))
    || !Array.isArray(responseStatuses)
    || responseStatuses.length === 0
    || responseStatuses.length > 32
    || !responseStatuses.every((item) => (
      typeof item === "number" && Number.isInteger(item) && item >= 100 && item <= 599
    ))
  ) {
    return null;
  }
  return {
    counts: {
      receipts: Number(receipts),
      jobs: Number(jobs),
      deliveries: Number(deliveries),
    },
    responseStatuses: [...responseStatuses],
  };
}

function decodeTests(input: unknown): TestResult[] {
  if (!Array.isArray(input)) return [];
  return input.map((item) => {
    const record = object(item);
    return {
      id: text(record, "id", "test_id"),
      label: text(record, "label", "label", text(record, "id", "test_id")),
      state: text(record, "state", "state", "pending") as TestResult["state"],
      durationMs: number(record, "durationMs", "duration_ms") || null,
      detail: text(record, "detail") || null,
      receiptSha256: text(record, "receiptSha256", "receipt_sha256") || null,
      trustedObservation: decodeTrustedObservation(
        value(record, "trustedObservation", "trusted_observation"),
      ),
    };
  });
}

function decodeSeats(input: unknown): SeatView[] {
  if (!Array.isArray(input)) return [];
  return input.flatMap((item): SeatView[] => {
    const record = object(item);
    const name = text(record, "name") as SeatView["name"];
    if (!SEAT_ORDER.includes(name)) return [];
    const baseline = DEFAULT_SEATS.find((seat) => seat.name === name);
    if (!baseline) return [];
    return [{
      ...baseline,
      effort: effort(value(record, "effort"), baseline.effort),
      escalationCount: escalationCount(value(record, "escalationCount", "escalation_count")),
      state: seatRunState(value(record, "state")),
    }];
  });
}

function specialistBase(record: JsonObject) {
  return {
    runId: text(record, "runId", "run_id"),
    rawPublicJson: JSON.stringify(record, null, 2),
    model: text(record, "model"),
    effort: text(record, "effort", "effort", "medium") as Effort,
    escalationCount: number(record, "escalationCount", "escalation_count"),
    phase: text(record, "phase"),
    outputSha256: text(record, "outputSha256", "output_sha256"),
    semanticSha256: text(record, "semanticSha256", "semantic_sha256"),
    createdAt: text(record, "createdAt", "created_at"),
    sanitizationTags: strings(value(record, "sanitizationTags", "sanitization_tags")),
  };
}

function decodeSpecialistSummaries(input: unknown): SpecialistSummary[] {
  if (!Array.isArray(input)) return [];
  return input.flatMap((item): SpecialistSummary[] => {
    const record = object(item);
    const kind = text(record, "kind").toUpperCase();
    const base = specialistBase(record);
    if (kind === "INSPECTOR" && text(record, "seat") === "Inspector") {
      return [{
        ...base,
        kind: "INSPECTOR",
        seat: "Inspector",
        mechanism: text(record, "mechanism"),
        evidenceIds: strings(value(record, "evidenceIds", "evidence_ids")),
        falsifiers: strings(record.falsifiers),
      }];
    }
    if (kind === "PROSECUTOR" && text(record, "seat") === "Prosecutor") {
      const outcome = text(record, "outcome");
      if (outcome !== "SUPPORTED_RIVAL" && outcome !== "NO_SUPPORTED_RIVAL") return [];
      return [{
        ...base,
        kind: "PROSECUTOR",
        seat: "Prosecutor",
        outcome,
        rivalMechanism: text(record, "rivalMechanism", "rival_mechanism") || null,
        counterexampleIds: strings(value(record, "counterexampleIds", "counterexample_ids")),
        testIds: strings(value(record, "testIds", "test_ids")),
        evidenceIds: strings(value(record, "evidenceIds", "evidence_ids")),
      }];
    }
    if (kind === "COUNSEL" && text(record, "seat") === "Counsel") {
      const intentions = value(record, "testIntentions", "test_intentions");
      return [{
        ...base,
        kind: "COUNSEL",
        seat: "Counsel",
        candidateId: text(record, "candidateId", "candidate_id") || null,
        patchSha256: text(record, "patchSha256", "patch_sha256"),
        patchDefense: text(record, "patchDefense", "patch_defense"),
        evidenceIds: strings(value(record, "evidenceIds", "evidence_ids")),
        testIntentions: Array.isArray(intentions)
          ? intentions.map((intention) => {
              const itemRecord = object(intention);
              return {
                catalogId: text(itemRecord, "catalogId", "catalog_id"),
                purpose: text(itemRecord, "purpose"),
              };
            })
          : [],
      }];
    }
    return [];
  });
}

function decodeWarrantHistory(input: unknown): WarrantHistoryItem[] {
  if (!Array.isArray(input)) return [];
  return input.flatMap((item): WarrantHistoryItem[] => {
    const record = object(item);
    const binding = object(value(record, "bindingHashes", "binding_hashes"));
    const warrantId = text(record, "warrantId", "warrant_id");
    const publicWarrantBytes = text(record, "publicWarrantBytes", "public_warrant_bytes");
    const publicWarrantSha256 = text(record, "publicWarrantSha256", "public_warrant_sha256");
    const nonceSha256 = text(record, "nonceSha256", "nonce_sha256");
    const publicWarrant = decodePublicWarrant(publicWarrantBytes);
    if (!warrantId) return [];
    return [{
      warrantId,
      canonicalSha256: text(record, "canonicalSha256", "canonical_sha256"),
      ...(publicWarrantBytes ? { publicWarrantBytes } : {}),
      ...(publicWarrantSha256 ? { publicWarrantSha256 } : {}),
      ...(nonceSha256 ? { nonceSha256 } : {}),
      ...(publicWarrant ? { publicWarrant } : {}),
      bindingHashes: {
        authoritySnapshotSha256: text(binding, "authoritySnapshotSha256", "authority_snapshot_sha256"),
        baseSha: text(binding, "baseSha", "base_sha"),
        environmentDigest: text(binding, "environmentDigest", "environment_digest"),
        patchSha256: text(binding, "patchSha256", "patch_sha256"),
        repositoryManifestSha256: text(binding, "repositoryManifestSha256", "repository_manifest_sha256"),
        reviewedEvidenceManifestSha256: text(binding, "reviewedEvidenceManifestSha256", "reviewed_evidence_manifest_sha256"),
        reviewedTimelineHead: text(binding, "reviewedTimelineHead", "reviewed_timeline_head"),
        runnerDigest: text(binding, "runnerDigest", "runner_digest"),
        testPlanSha256: text(binding, "testPlanSha256", "test_plan_sha256"),
        verdictSha256: text(binding, "verdictSha256", "verdict_sha256"),
      },
      approvalStatus: text(record, "approvalStatus", "approval_status") as WarrantHistoryItem["approvalStatus"],
      approvalId: text(record, "approvalId", "approval_id") || null,
      consumptionStatus: text(record, "consumptionStatus", "consumption_status") as WarrantHistoryItem["consumptionStatus"],
      executionStatus: text(record, "executionStatus", "execution_status"),
      receiptIds: strings(value(record, "receiptIds", "receipt_ids")),
      createdAt: text(record, "createdAt", "created_at"),
      expiresAt: text(record, "expiresAt", "expires_at"),
      consumedAt: text(record, "consumedAt", "consumed_at") || null,
    }];
  });
}

function decodePublicWarrant(input: string): PublicWarrantAnatomy | null {
  if (!input) return null;
  let parsed: JsonObject;
  try {
    parsed = object(JSON.parse(input) as unknown);
  } catch {
    return null;
  }
  if (text(parsed, "format") !== "crosspatch-public-warrant-anatomy-v1") return null;
  return {
    format: "crosspatch-public-warrant-anatomy-v1",
    warrantId: text(parsed, "warrant_id"),
    incidentId: text(parsed, "incident_id"),
    canonicalWarrantSha256: text(parsed, "canonical_warrant_sha256"),
    authoritySnapshotSha256: text(parsed, "authority_snapshot_sha256"),
    verdictSha256: text(parsed, "verdict_sha256"),
    repositoryManifestSha256: text(parsed, "repository_manifest_sha256"),
    reviewedEvidenceManifestSha256: text(parsed, "reviewed_evidence_manifest_sha256"),
    reviewedTimelineHead: text(parsed, "reviewed_timeline_head"),
    baseSha: text(parsed, "base_sha"),
    patchSha256: text(parsed, "patch_sha256"),
    allowedPaths: strings(parsed.allowed_paths),
    planIds: strings(parsed.plan_ids),
    runnerDigest: text(parsed, "runner_digest"),
    environmentDigest: text(parsed, "environment_digest"),
    testPlanSha256: text(parsed, "test_plan_sha256"),
    expiresAt: text(parsed, "expires_at"),
    approverIdentity: text(parsed, "approver_identity"),
    nonceSha256: text(parsed, "nonce_sha256"),
  };
}

export function decodeIncidentRoom(input: unknown): IncidentRoomSnapshot {
  const root = object(input);
  const incident = object(root.incident ?? root);
  const artifactsRecord = object(root.artifacts);
  const pendingWarrant = decodeWarrant(value(root, "pendingWarrant", "pending_warrant"));
  const artifacts: IncidentArtifacts = {
    evidence: decodeEvidence(artifactsRecord.evidence ?? root.evidence),
    diff: decodeDiff(artifactsRecord.diff ?? root.diff),
    tests: decodeTests(artifactsRecord.tests ?? root.tests),
    warrant: decodeWarrant(artifactsRecord.warrant) ?? pendingWarrant,
  };
  return {
    viewerRole: text(root, "viewerRole", "viewer_role", "read_only") as IncidentRoomSnapshot["viewerRole"],
    incident: {
      id: text(incident, "id", "incident_id"),
      title: text(incident, "title", "title", "Untitled incident"),
      state: text(incident, "state", "state", "OPEN") as IncidentState,
      severity: text(incident, "severity", "severity", "UNSET"),
      service: text(incident, "service", "scenario", "Unassigned service"),
      baseSha: text(incident, "baseSha", "base_sha"),
      createdAt: text(incident, "createdAt", "created_at"),
      updatedAt: text(incident, "updatedAt", "updated_at"),
    },
    seats: decodeSeats(root.seats),
    events: Array.isArray(root.events) ? root.events.map(decodeTimelineEvent) : [],
    specialistSummaries: decodeSpecialistSummaries(
      value(root, "specialistSummaries", "specialist_summaries"),
    ),
    warrants: decodeWarrantHistory(root.warrants),
    artifacts,
    pendingWarrant,
  };
}

function decodePublishedCaseSummary(input: unknown): PublishedCaseSummary {
  const record = object(input);
  const incidentId = requiredString(record, "incidentId", "incident_id");
  const title = requiredString(record, "title");
  const state = requiredString(record, "state");
  const scenario = requiredString(record, "scenario");
  const createdAt = requiredString(record, "createdAt", "created_at");
  const updatedAt = requiredString(record, "updatedAt", "updated_at");
  const revision = value(record, "revision");
  const manifestSha256 = requiredString(record, "manifestSha256", "manifest_sha256");
  const verdictPathValue = value(record, "verdictPath", "verdict_path");
  const recordedCostUsd = value(record, "recordedCostUsd", "recorded_cost_usd");
  const durationSeconds = value(record, "durationSeconds", "duration_seconds");
  const evidenceToVerifiedSeconds = value(
    record,
    "evidenceToVerifiedSeconds",
    "evidence_to_verified_seconds",
  );
  const humanGateDwellSeconds = value(
    record,
    "humanGateDwellSeconds",
    "human_gate_dwell_seconds",
  );
  const executionVerificationSeconds = value(
    record,
    "executionVerificationSeconds",
    "execution_verification_seconds",
  );
  const seatSpendValue = value(record, "seatSpend", "seat_spend");
  const verdictPath = Array.isArray(verdictPathValue) && verdictPathValue.every(
    (step): step is PublishedCaseVerdictStep => (
      typeof step === "string" && PUBLIC_VERDICT_STEPS.has(step as PublishedCaseVerdictStep)
    ),
  )
    ? verdictPathValue
    : null;
  const nullableMetric = (metric: unknown): metric is number | null => (
    metric === null
    || metric === undefined
    || (typeof metric === "number" && Number.isFinite(metric) && metric >= 0)
  );
  const seatSpend = Array.isArray(seatSpendValue)
    ? seatSpendValue.map((item): PublishedSeatSpend | null => {
      const spend = object(item);
      const seat = requiredString(spend, "seat");
      const effort = requiredString(spend, "effort");
      const escalationCount = value(spend, "escalationCount", "escalation_count");
      const costUsd = value(spend, "costUsd", "cost_usd");
      if (
        !seat
        || !PUBLIC_SEAT_NAMES.has(seat as PublishedSeatSpend["seat"])
        || !effort
        || !EFFORTS.has(effort as Effort)
        || typeof escalationCount !== "number"
        || !Number.isInteger(escalationCount)
        || escalationCount < 0
        || escalationCount > 2
        || typeof costUsd !== "number"
        || !Number.isFinite(costUsd)
        || costUsd < 0
      ) {
        return null;
      }
      return {
        seat: seat as PublishedSeatSpend["seat"],
        effort: effort as Effort,
        escalationCount,
        costUsd,
      };
    })
    : seatSpendValue === undefined
      ? []
      : null;

  if (
    !incidentId ||
    !title ||
    state !== "VERIFIED" ||
    !scenario ||
    !createdAt ||
    !updatedAt ||
    !validIsoDate(createdAt) ||
    !validIsoDate(updatedAt) ||
    Date.parse(updatedAt) < Date.parse(createdAt) ||
    typeof revision !== "number" ||
    !Number.isInteger(revision) ||
    revision < 1 ||
    !manifestSha256 ||
    !SHA256_HEX.test(manifestSha256) ||
    !verdictPath ||
    verdictPath.length < 1 ||
    verdictPath.at(-1) !== "CLEAR" ||
    !(
      recordedCostUsd === null ||
      (
        typeof recordedCostUsd === "number" &&
        Number.isFinite(recordedCostUsd) &&
        recordedCostUsd >= 0
      )
    ) ||
    !(
      durationSeconds === null ||
      (
        typeof durationSeconds === "number" &&
        Number.isFinite(durationSeconds) &&
        durationSeconds >= 0
      )
    ) ||
    !nullableMetric(evidenceToVerifiedSeconds) ||
    !nullableMetric(humanGateDwellSeconds) ||
    !nullableMetric(executionVerificationSeconds) ||
    !seatSpend ||
    seatSpend.some((item) => item === null)
  ) {
    publishedValidationError("index");
  }

  return {
    incidentId,
    title,
    state,
    scenario,
    createdAt,
    updatedAt,
    revision,
    manifestSha256,
    verdictPath,
    recordedCostUsd,
    durationSeconds,
    evidenceToVerifiedSeconds: evidenceToVerifiedSeconds ?? null,
    humanGateDwellSeconds: humanGateDwellSeconds ?? null,
    executionVerificationSeconds: executionVerificationSeconds ?? null,
    seatSpend: seatSpend as PublishedSeatSpend[],
  };
}

export function decodePublishedCaseIndex(input: unknown): PublishedCaseSummary[] {
  const root = object(input);
  if (!Array.isArray(root.cases)) publishedValidationError("index");
  return root.cases.map((item) => decodePublishedCaseSummary(item));
}

function validPublicSeat(input: unknown): boolean {
  const record = object(input);
  const name = requiredString(record, "name");
  const runState = requiredString(record, "state");
  const effortValue = requiredString(record, "effort");
  const escalations = value(record, "escalationCount", "escalation_count");
  return Boolean(
    name &&
    PUBLIC_SEAT_NAMES.has(name as SeatView["name"]) &&
    runState &&
    SEAT_RUN_STATES.has(runState as SeatRunState) &&
    effortValue &&
    EFFORTS.has(effortValue as Effort) &&
    typeof escalations === "number" &&
    Number.isInteger(escalations) &&
    escalations >= 0 &&
    escalations <= 2
  );
}

function validPublicEvent(input: unknown, incidentId: string): boolean {
  const record = object(input);
  const details = object(record.details);
  const kind = requiredString(record, "type", "type") ?? requiredString(record, "kind");
  const sequence = value(record, "sequence");
  const eventIncidentId = requiredString(record, "incidentId", "incident_id");
  const eventHash = requiredString(record, "eventHash", "event_hash");
  const occurredAt = requiredString(record, "occurredAt", "created_at");
  if (
    !requiredString(record, "id", "event_id") ||
    eventIncidentId !== incidentId ||
    typeof sequence !== "number" ||
    !Number.isInteger(sequence) ||
    sequence < 1 ||
    !kind ||
    !requiredString(record, "actor") ||
    !eventHash ||
    !SHA256_HEX.test(eventHash) ||
    !occurredAt ||
    !validAwareIsoDate(occurredAt) ||
    record.published !== true
  ) {
    return false;
  }
  if (kind === "MODEL_METRICS_RECORDED") {
    const cost = value(details, "costUsd", "cost_usd");
    return typeof cost === "number" && Number.isFinite(cost) && cost >= 0;
  }
  return true;
}

function validPublicSpecialist(input: unknown): boolean {
  const record = object(input);
  const kind = requiredString(record, "kind")?.toUpperCase();
  const expectedSeat = kind === "INSPECTOR"
    ? "Inspector"
    : kind === "PROSECUTOR"
      ? "Prosecutor"
      : kind === "COUNSEL"
        ? "Counsel"
        : null;
  const effortValue = requiredString(record, "effort");
  const escalations = value(record, "escalationCount", "escalation_count");
  const outputSha256 = requiredString(record, "outputSha256", "output_sha256");
  const semanticSha256 = requiredString(record, "semanticSha256", "semantic_sha256");
  const createdAt = requiredString(record, "createdAt", "created_at");
  return Boolean(
    expectedSeat &&
    requiredString(record, "seat") === expectedSeat &&
    requiredString(record, "runId", "run_id") &&
    requiredString(record, "model") &&
    effortValue &&
    EFFORTS.has(effortValue as Effort) &&
    typeof escalations === "number" &&
    Number.isInteger(escalations) &&
    escalations >= 0 &&
    escalations <= 2 &&
    requiredString(record, "phase") &&
    outputSha256 &&
    SHA256_HEX.test(outputSha256) &&
    semanticSha256 &&
    SHA256_HEX.test(semanticSha256) &&
    createdAt &&
    validIsoDate(createdAt)
  );
}

function validPublishedArtifacts(input: unknown): boolean {
  const artifacts = object(input);
  if (!Array.isArray(artifacts.evidence) || !Array.isArray(artifacts.tests)) return false;
  const evidenceValid = artifacts.evidence.every((item) => {
    const record = object(item);
    const sha = requiredString(record, "sha256", "sanitized_sha256");
    const capturedAt = requiredString(record, "capturedAt", "captured_at");
    return record.classification === "UNTRUSTED_EVIDENCE" &&
      Boolean(requiredString(record, "id", "evidence_id")) &&
      Boolean(sha && SHA256_HEX.test(sha)) &&
      Boolean(capturedAt && validIsoDate(capturedAt));
  });
  const testsValid = artifacts.tests.every((item) => {
    const record = object(item);
    const state = requiredString(record, "state");
    const receiptSha256 = requiredString(record, "receiptSha256", "receipt_sha256");
    return Boolean(requiredString(record, "id", "test_id")) &&
      Boolean(state && ["pending", "running", "passed", "failed"].includes(state)) &&
      (!receiptSha256 || SHA256_HEX.test(receiptSha256));
  });
  return evidenceValid && testsValid;
}

async function validPublicWarrantHistory(input: unknown, incidentId: string): Promise<boolean> {
  const record = object(input);
  const binding = object(value(record, "bindingHashes", "binding_hashes"));
  const publicWarrantBytes = requiredString(
    record,
    "publicWarrantBytes",
    "public_warrant_bytes",
  );
  const publicWarrantSha256 = requiredString(
    record,
    "publicWarrantSha256",
    "public_warrant_sha256",
  );
  const nonceSha256 = requiredString(record, "nonceSha256", "nonce_sha256");
  const warrantId = requiredString(record, "warrantId", "warrant_id");
  const canonicalSha256 = requiredString(record, "canonicalSha256", "canonical_sha256");
  const createdAt = requiredString(record, "createdAt", "created_at");
  const expiresAt = requiredString(record, "expiresAt", "expires_at");
  const consumedAt = requiredString(record, "consumedAt", "consumed_at");
  const approvalIdValue = value(record, "approvalId", "approval_id");
  const receiptIds = value(record, "receiptIds", "receipt_ids");
  const bindingHashes = [
    requiredString(binding, "authoritySnapshotSha256", "authority_snapshot_sha256"),
    requiredString(binding, "environmentDigest", "environment_digest"),
    requiredString(binding, "patchSha256", "patch_sha256"),
    requiredString(binding, "repositoryManifestSha256", "repository_manifest_sha256"),
    requiredString(
      binding,
      "reviewedEvidenceManifestSha256",
      "reviewed_evidence_manifest_sha256",
    ),
    requiredString(binding, "reviewedTimelineHead", "reviewed_timeline_head"),
    requiredString(binding, "runnerDigest", "runner_digest"),
    requiredString(binding, "testPlanSha256", "test_plan_sha256"),
    requiredString(binding, "verdictSha256", "verdict_sha256"),
  ];
  const baseSha = requiredString(binding, "baseSha", "base_sha");
  if (
    !publicWarrantBytes ||
    !publicWarrantSha256 ||
    !SHA256_HEX.test(publicWarrantSha256) ||
    await canonicalPublicSha256(publicWarrantBytes) !== publicWarrantSha256 ||
    !nonceSha256 ||
    !SHA256_HEX.test(nonceSha256) ||
    !warrantId ||
    !canonicalSha256 ||
    !SHA256_HEX.test(canonicalSha256) ||
    !baseSha ||
    !GIT_SHA.test(baseSha) ||
    bindingHashes.some((hash) => !hash || !SHA256_HEX.test(hash)) ||
    !createdAt ||
    !validAwareIsoDate(createdAt) ||
    !expiresAt ||
    !validAwareIsoDate(expiresAt) ||
    Date.parse(expiresAt) <= Date.parse(createdAt) ||
    (consumedAt !== null && !validAwareIsoDate(consumedAt)) ||
    (approvalIdValue !== null && typeof approvalIdValue !== "string") ||
    !Array.isArray(receiptIds) ||
    !receiptIds.every((receipt) => typeof receipt === "string" && Boolean(receipt)) ||
    !["PENDING_APPROVAL", "APPROVED", "REJECTED", "EXPIRED"].includes(
      requiredString(record, "approvalStatus", "approval_status") ?? "",
    ) ||
    !["NOT_MATERIALIZED", "APPROVED", "CONSUMING", "CONSUMED", "REJECTED", "EXPIRED"]
      .includes(requiredString(record, "consumptionStatus", "consumption_status") ?? "") ||
    !/^[A-Z][A-Z0-9_]{0,63}$/.test(
      requiredString(record, "executionStatus", "execution_status") ?? "",
    )
  ) return false;

  let anatomy: JsonObject;
  try {
    anatomy = object(JSON.parse(publicWarrantBytes) as unknown);
  } catch {
    return false;
  }
  if (
    Object.keys(anatomy).sort().join("\0") !== [...PUBLIC_WARRANT_ANATOMY_KEYS].sort().join("\0") ||
    requiredString(anatomy, "format") !== "crosspatch-public-warrant-anatomy-v1" ||
    requiredString(anatomy, "warrant_id") !== warrantId ||
    requiredString(anatomy, "incident_id") !== incidentId ||
    requiredString(anatomy, "canonical_warrant_sha256") !== canonicalSha256 ||
    requiredString(anatomy, "nonce_sha256") !== nonceSha256 ||
    requiredString(anatomy, "authority_snapshot_sha256") !== bindingHashes[0] ||
    requiredString(anatomy, "base_sha") !== baseSha ||
    requiredString(anatomy, "environment_digest") !== bindingHashes[1] ||
    requiredString(anatomy, "patch_sha256") !== bindingHashes[2] ||
    requiredString(anatomy, "repository_manifest_sha256") !== bindingHashes[3] ||
    requiredString(anatomy, "reviewed_evidence_manifest_sha256") !== bindingHashes[4] ||
    requiredString(anatomy, "reviewed_timeline_head") !== bindingHashes[5] ||
    requiredString(anatomy, "runner_digest") !== bindingHashes[6] ||
    requiredString(anatomy, "test_plan_sha256") !== bindingHashes[7] ||
    requiredString(anatomy, "verdict_sha256") !== bindingHashes[8] ||
    requiredString(anatomy, "expires_at") !== expiresAt ||
    !requiredString(anatomy, "approver_identity") ||
    strings(anatomy.allowed_paths).length !== (anatomy.allowed_paths as unknown[] | undefined)?.length ||
    strings(anatomy.allowed_paths).length === 0 ||
    strings(anatomy.plan_ids).length !== (anatomy.plan_ids as unknown[] | undefined)?.length ||
    strings(anatomy.plan_ids).length === 0
  ) return false;
  return true;
}

export async function decodePublishedCase(input: unknown): Promise<PublishedCaseDetail> {
  const root = object(input);
  const incidentId = requiredString(root, "incidentId", "incident_id");
  const displayTitle = requiredString(root, "displayTitle", "display_title");
  const revision = value(root, "revision");
  const manifestSha256 = requiredString(root, "manifestSha256", "manifest_sha256");
  const canonicalProjectionJson = requiredString(
    root,
    "canonicalProjectionJson",
    "canonical_projection_json",
  );
  const readableProjection = object(root.projection);
  if (
    !incidentId ||
    !displayTitle ||
    typeof revision !== "number" ||
    !Number.isInteger(revision) ||
    revision < 1 ||
    !manifestSha256 ||
    !SHA256_HEX.test(manifestSha256) ||
    !canonicalProjectionJson ||
    await canonicalPublicSha256(canonicalProjectionJson) !== manifestSha256
  ) {
    publishedValidationError("detail");
  }
  let canonicalProjection: unknown;
  try {
    canonicalProjection = JSON.parse(canonicalProjectionJson) as unknown;
  } catch {
    publishedValidationError("detail");
  }
  if (!sameJsonValue(canonicalProjection, readableProjection)) {
    publishedValidationError("detail");
  }
  const projection = object(canonicalProjection);
  const incident = object(projection.incident);
  const projectionIncidentId = requiredString(incident, "id", "incident_id");
  const createdAt = requiredString(incident, "createdAt", "created_at");
  const updatedAt = requiredString(incident, "updatedAt", "updated_at");
  const baseSha = requiredString(incident, "baseSha", "base_sha");
  const seats = projection.seats;
  const events = projection.events;
  const verdicts = projection.verdicts;
  const specialists = value(projection, "specialistSummaries", "specialist_summaries");
  const warrants = projection.warrants;
  const hasPendingWarrant = Object.hasOwn(projection, "pending_warrant") ||
    Object.hasOwn(projection, "pendingWarrant");
  const pendingWarrant = value(projection, "pendingWarrant", "pending_warrant");
  const warrantsValid = Array.isArray(warrants) && (
    await Promise.all(warrants.map((warrant) => validPublicWarrantHistory(warrant, incidentId)))
  ).every(Boolean);

  if (
    !incidentId ||
    projectionIncidentId !== incidentId ||
    requiredString(incident, "state") !== "VERIFIED" ||
    !requiredString(incident, "title") ||
    !requiredString(incident, "scenario") ||
    !baseSha ||
    !GIT_SHA.test(baseSha) ||
    !createdAt ||
    !updatedAt ||
    !validAwareIsoDate(createdAt) ||
    !validAwareIsoDate(updatedAt) ||
    Date.parse(updatedAt) < Date.parse(createdAt) ||
    !Array.isArray(seats) ||
    seats.length !== SEAT_ORDER.length ||
    !seats.every(validPublicSeat) ||
    new Set(seats.map((item) => requiredString(object(item), "name"))).size !== SEAT_ORDER.length ||
    !Array.isArray(events) ||
    events.length === 0 ||
    !events.every((event) => validPublicEvent(event, incidentId)) ||
    new Set(events.map((event) => requiredString(object(event), "id", "event_id"))).size !== events.length ||
    new Set(events.map((event) => value(object(event), "sequence"))).size !== events.length ||
    !Array.isArray(verdicts) ||
    !Array.isArray(specialists) ||
    !specialists.every(validPublicSpecialist) ||
    !warrantsValid ||
    !validPublishedArtifacts(projection.artifacts) ||
    !hasPendingWarrant ||
    pendingWarrant !== null
  ) {
    publishedValidationError("detail");
  }

  const eventRecords = events.map((item) => object(item));
  const eventTimes = eventRecords.map((event) => (
    Date.parse(requiredString(event, "occurredAt", "created_at") ?? "")
  ));
  if (
    eventRecords.some((event, index) => value(event, "sequence") !== index + 1) ||
    eventRecords[0] === undefined ||
    (requiredString(eventRecords[0], "type") ?? requiredString(eventRecords[0], "kind")) !==
      "INCIDENT_OPENED" ||
    eventTimes.some((eventTime, index) => index > 0 && eventTime < eventTimes[index - 1])
  ) {
    publishedValidationError("detail");
  }

  const verdictRecords = verdicts.map((item) => object(item));
  const verdictPath: PublishedCaseVerdictStep[] = [];
  const verdictTimes: number[] = [];
  for (const verdictRecord of verdictRecords) {
    const verdict = requiredString(verdictRecord, "verdict");
    const verdictIncidentId = requiredString(verdictRecord, "incidentId", "incident_id");
    const verdictSha256 = requiredString(verdictRecord, "verdictSha256", "verdict_sha256");
    const verdictCreatedAt = requiredString(verdictRecord, "createdAt", "created_at");
    if (
      !requiredString(verdictRecord, "id") ||
      verdictIncidentId !== incidentId ||
      !verdict ||
      !PUBLIC_VERDICT_STEPS.has(verdict as PublishedCaseVerdictStep) ||
      !verdictSha256 ||
      !SHA256_HEX.test(verdictSha256) ||
      requiredString(verdictRecord, "source") !== "Magistrate" ||
      !verdictCreatedAt ||
      !validAwareIsoDate(verdictCreatedAt)
    ) {
      publishedValidationError("detail");
    }
    verdictPath.push(verdict as PublishedCaseVerdictStep);
    verdictTimes.push(Date.parse(verdictCreatedAt));
  }
  if (
    verdictPath.length === 0 ||
    verdictTimes.some((verdictTime, index) => index > 0 && verdictTime < verdictTimes[index - 1])
  ) {
    publishedValidationError("detail");
  }

  const eventVerdicts: PublishedCaseVerdictStep[] = [];
  const eventVerdictTimes: number[] = [];
  const verdictEventIndices: number[] = [];
  eventRecords.forEach((event, index) => {
    const kind = requiredString(event, "type") ?? requiredString(event, "kind");
    if (kind !== "VERDICT") return;
    const details = object(event.details);
    const verdict = requiredString(details, "verdict");
    const remandTarget = requiredString(details, "remandTarget", "remand_target");
    if (
      requiredString(event, "actor") !== "Magistrate" ||
      !verdict ||
      !PUBLIC_VERDICT_STEPS.has(verdict as PublishedCaseVerdictStep) ||
      (verdict === "REMAND"
        ? !remandTarget || !PUBLIC_REMAND_TARGETS.has(remandTarget)
        : remandTarget !== null)
    ) {
      publishedValidationError("detail");
    }
    eventVerdicts.push(verdict as PublishedCaseVerdictStep);
    eventVerdictTimes.push(eventTimes[index]);
    verdictEventIndices.push(index);
  });
  if (
    eventVerdicts.length !== verdictPath.length ||
    eventVerdicts.some((verdict, index) => (
      verdict !== verdictPath[index] || eventVerdictTimes[index] !== verdictTimes[index]
    )) ||
    verdictPath.at(-1) !== "CLEAR" ||
    verdictPath.some((verdict) => verdict === "BLOCK" || verdict === "ABSTAIN")
  ) {
    publishedValidationError("detail");
  }

  const terminalClearIndex = verdictEventIndices.at(-1) ?? -1;
  const verifiedIndices = eventRecords.flatMap((event, index) => {
    const kind = requiredString(event, "type") ?? requiredString(event, "kind");
    return kind === "VERIFIED" ? [index] : [];
  });
  const invalidAfterClear = eventRecords.slice(terminalClearIndex + 1).some((event) => {
    const kind = requiredString(event, "type") ?? requiredString(event, "kind");
    return kind === "VERDICT" || kind === "TEST_FAILED" || kind === "EXECUTION_FAILED";
  });
  const metricEvents = eventRecords.filter((event) => (
    (requiredString(event, "type") ?? requiredString(event, "kind")) ===
      "MODEL_METRICS_RECORDED"
  ));
  if (
    verifiedIndices.length !== 1 ||
    verifiedIndices[0] <= terminalClearIndex ||
    invalidAfterClear ||
    metricEvents.length === 0 ||
    metricEvents.some((event) => {
      const cost = value(object(event.details), "costUsd", "cost_usd");
      return typeof cost !== "number" || !Number.isFinite(cost) || cost < 0;
    })
  ) {
    publishedValidationError("detail");
  }

  const verifiedEvent = events[verifiedIndices[0]];
  const receiptId = requiredString(object(object(verifiedEvent).details), "receiptId", "receipt_id");
  const tests = object(projection.artifacts).tests as unknown[];
  const trustedReceipt = tests.find((item) => {
    const record = object(item);
    return requiredString(record, "id", "test_id") === receiptId &&
      Boolean(requiredString(record, "label")) &&
      requiredString(record, "state") === "passed" &&
      requiredString(record, "detail") === "TRUSTED_HTTP_POSTGRES_INVARIANT_MATCHED" &&
      SHA256_HEX.test(requiredString(record, "receiptSha256", "receipt_sha256") ?? "");
  });
  if (!verifiedEvent || !receiptId || !trustedReceipt) publishedValidationError("detail");

  const canonicalSnapshot = decodeIncidentRoom({
    ...projection,
    viewer_role: "read_only",
    pending_warrant: null,
  });
  const snapshot: IncidentRoomSnapshot = {
    ...canonicalSnapshot,
    incident: { ...canonicalSnapshot.incident, title: displayTitle },
  };
  if (
    snapshot.incident.id !== incidentId ||
    snapshot.viewerRole !== "read_only" ||
    snapshot.pendingWarrant !== null ||
    snapshot.events.length !== events.length ||
    snapshot.seats.length !== seats.length ||
    snapshot.specialistSummaries.length !== specialists.length
  ) {
    publishedValidationError("detail");
  }

  return { incidentId, displayTitle, revision, manifestSha256, snapshot };
}

async function request(path: string, init?: RequestInit): Promise<Response> {
  const response = await fetch(path, {
    cache: "no-store",
    ...init,
    headers: authenticatedHeaders({ Accept: "application/json", ...init?.headers }),
  });
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try {
      const body = object(await response.json());
      message = text(body, "detail", "detail", message);
    } catch {
      // Do not expose an untrusted HTML error body in the incident room.
    }
    throw new ApiError(message, response.status);
  }
  return response;
}

async function publicRequest(path: string, signal?: AbortSignal): Promise<Response> {
  const response = await fetch(path, {
    cache: "no-store",
    signal,
    headers: { Accept: "application/json" },
  });
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try {
      const body = object(await response.json() as unknown);
      message = text(body, "detail", "detail", message);
    } catch {
      // Public error bodies are untrusted; never render an HTML response.
    }
    throw new ApiError(message, response.status);
  }
  return response;
}

export async function fetchPublishedCases(signal?: AbortSignal): Promise<PublishedCaseSummary[]> {
  const response = await publicRequest("/api/public/cases", signal);
  try {
    return decodePublishedCaseIndex(await response.json() as unknown);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    publishedValidationError("index");
  }
}

export async function fetchPublishedCase(
  id: string,
  signal?: AbortSignal,
): Promise<PublishedCaseDetail> {
  const response = await publicRequest(`/api/public/cases/${encodeURIComponent(id)}`, signal);
  let published: PublishedCaseDetail;
  try {
    published = await decodePublishedCase(await response.json() as unknown);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    publishedValidationError("detail");
  }
  if (published.incidentId !== id) publishedValidationError("detail");
  return published;
}

export async function fetchRoomProjection(
  id: string,
  signal?: AbortSignal,
): Promise<IncidentRoomSnapshot> {
  const encoded = encodeURIComponent(id);
  const response = await request(`/api/incidents/${encoded}/room`, { signal });
  return decodeIncidentRoom(await response.json() as unknown);
}

export async function getIncidentRoom(
  id: string,
  signal?: AbortSignal,
): Promise<IncidentRoomSnapshot> {
  return fetchRoomProjection(id, signal);
}

export async function openIncident(
  scenario: OperatorScenario,
  title: string,
  evidenceProfile: EvidenceProfile = "standard",
): Promise<OpenedIncident> {
  const safeTitle = title.trim();
  const response = await request("/api/incidents", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scenario, title: safeTitle, evidence_profile: evidenceProfile }),
  });
  const record = object(await response.json() as unknown);
  const id = text(record, "id", "incident_id");
  if (!id) throw new ApiError("Incident response did not include an ID", 502);
  return {
    id,
    title: text(record, "title", "title", safeTitle),
    scenario,
    state: text(record, "state", "state", "OPEN") as IncidentState,
  };
}

export function authenticatedHeaders(input: HeadersInit = {}): Headers {
  const headers = new Headers(input);
  const token = readAccessToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  return headers;
}

function approvalHeaders(): Record<string, string> {
  const { csrfToken, stepUpToken } = readApprovalCredentials();
  if (!csrfToken || !stepUpToken) {
    throw new ApiError("CSRF and step-up tokens are required for approval controls", 403);
  }
  return {
    "X-CSRF-Token": csrfToken,
    "X-CrossPatch-Step-Up": stepUpToken,
  };
}

export async function approveWarrant(
  id: string,
  warrantSha256: string,
  liveTrial = false,
): Promise<PendingWarrant> {
  const response = await request(`/api/warrants/${encodeURIComponent(id)}/approve`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(liveTrial ? {} : approvalHeaders()),
    },
    body: JSON.stringify({ confirmation: "APPROVE", warrant_sha256: warrantSha256 }),
  });
  const warrant = decodeWarrant(await response.json() as unknown);
  if (!warrant) throw new ApiError("Approval response did not include a warrant", 502);
  return warrant;
}

export async function rejectWarrant(
  id: string,
  warrantSha256: string,
  reason?: string,
  liveTrial = false,
): Promise<PendingWarrant> {
  const response = await request(`/api/warrants/${encodeURIComponent(id)}/reject`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(liveTrial ? {} : approvalHeaders()),
    },
    body: JSON.stringify({
      confirmation: "REJECT",
      warrant_sha256: warrantSha256,
      ...(reason ? { reason } : {}),
    }),
  });
  const warrant = decodeWarrant(await response.json() as unknown);
  if (!warrant) throw new ApiError("Rejection response did not include a warrant", 502);
  return warrant;
}

export async function requestWarrantRevision(
  id: string,
  warrantSha256: string,
  comment: string,
): Promise<void> {
  await request(`/api/warrants/${encodeURIComponent(id)}/request-revision`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      confirmation: "REQUEST_REVISION",
      warrant_sha256: warrantSha256,
      comment,
    }),
  });
}

export function incidentEventsUrl(id: string): string {
  return `/api/incidents/${encodeURIComponent(id)}/events/stream?limit=500`;
}

export async function downloadCaseFile(id: string): Promise<void> {
  const response = await request(`/api/incidents/${encodeURIComponent(id)}/export`, {
    headers: { Accept: "application/zip" },
  });
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `crosspatch-${id}-case.zip`;
  link.click();
  URL.revokeObjectURL(url);
}
