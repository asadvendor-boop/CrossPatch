export type SeatName = "Prosecutor" | "Inspector" | "Counsel" | "Magistrate" | "Bailiff";
export type Effort = "none" | "low" | "medium" | "high" | "xhigh";
export type SeatRunState =
  | "idle"
  | "working"
  | "complete"
  | "failed"
  | "abstained"
  | "unavailable";
export type IncidentState =
  | "OPEN"
  | "REPRODUCING"
  | "EVIDENCE_READY"
  | "ANALYZING"
  | "PATCHING"
  | "REVIEWING"
  | "REMANDED"
  | "APPROVAL_PENDING"
  | "APPROVED"
  | "EXECUTING"
  | "TEST_FAILED"
  | "VERIFIED"
  | "BLOCKED"
  | "ABSTAINED"
  | "HUMAN_ESCALATION";

export interface SeatView {
  name: SeatName;
  role: string;
  model: string;
  tierRationale: string;
  effort: Effort;
  escalationCount: number;
  state: SeatRunState;
}

export type EventVisualState = "neutral" | "active" | "warning" | "failed" | "verified";

export interface TimelineEvent {
  id: string;
  eventHash: string;
  rawPublicJson: string;
  sequence: number;
  kind: string;
  actor: string;
  occurredAt: string;
  summary: string;
  detail?: string | null;
  details?: Record<string, unknown>;
  state: EventVisualState;
  explanation?: string | null;
  evidenceIds?: string[];
}

export interface EvidenceItem {
  classification: "UNTRUSTED_EVIDENCE";
  id: string;
  label: string;
  kind: string;
  sha256: string;
  capturedAt: string;
  content?: string | null;
  tags?: string[];
}

export interface TrustedObservation {
  counts: {
    receipts: number;
    jobs: number;
    deliveries: number;
  };
  responseStatuses: number[];
}

export interface TestResult {
  id: string;
  label: string;
  state: "pending" | "running" | "passed" | "failed";
  durationMs?: number | null;
  detail?: string | null;
  receiptSha256?: string | null;
  trustedObservation?: TrustedObservation | null;
}

interface SpecialistSummaryBase {
  runId: string;
  rawPublicJson: string;
  model: string;
  effort: Effort;
  escalationCount: number;
  phase: string;
  outputSha256: string;
  semanticSha256: string;
  createdAt: string;
  sanitizationTags?: string[];
}

export interface InspectorSpecialistSummary extends SpecialistSummaryBase {
  kind: "INSPECTOR";
  seat: "Inspector";
  mechanism: string;
  evidenceIds: string[];
  falsifiers: string[];
}

export interface ProsecutorSpecialistSummary extends SpecialistSummaryBase {
  kind: "PROSECUTOR";
  seat: "Prosecutor";
  outcome: "SUPPORTED_RIVAL" | "NO_SUPPORTED_RIVAL";
  rivalMechanism: string | null;
  counterexampleIds: string[];
  testIds: string[];
  evidenceIds: string[];
}

export interface CounselSpecialistSummary extends SpecialistSummaryBase {
  kind: "COUNSEL";
  seat: "Counsel";
  candidateId: string | null;
  patchSha256: string;
  patchDefense: string;
  evidenceIds: string[];
  testIntentions: Array<{ catalogId: string; purpose: string }>;
}

export type SpecialistSummary =
  | InspectorSpecialistSummary
  | ProsecutorSpecialistSummary
  | CounselSpecialistSummary;

export interface WarrantBindingHashes {
  authoritySnapshotSha256: string;
  baseSha: string;
  environmentDigest: string;
  patchSha256: string;
  repositoryManifestSha256: string;
  reviewedEvidenceManifestSha256: string;
  reviewedTimelineHead: string;
  runnerDigest: string;
  testPlanSha256: string;
  verdictSha256: string;
}

export interface PublicWarrantAnatomy {
  format: "crosspatch-public-warrant-anatomy-v1";
  warrantId: string;
  incidentId: string;
  canonicalWarrantSha256: string;
  authoritySnapshotSha256: string;
  verdictSha256: string;
  repositoryManifestSha256: string;
  reviewedEvidenceManifestSha256: string;
  reviewedTimelineHead: string;
  baseSha: string;
  patchSha256: string;
  allowedPaths: string[];
  planIds: string[];
  runnerDigest: string;
  environmentDigest: string;
  testPlanSha256: string;
  expiresAt: string;
  approverIdentity: string;
  nonceSha256: string;
}

export interface WarrantHistoryItem {
  warrantId: string;
  canonicalSha256: string;
  publicWarrantBytes?: string;
  publicWarrantSha256?: string;
  nonceSha256?: string;
  publicWarrant?: PublicWarrantAnatomy;
  bindingHashes: WarrantBindingHashes;
  approvalStatus: "PENDING_APPROVAL" | "APPROVED" | "REJECTED" | "EXPIRED";
  approvalId: string | null;
  consumptionStatus:
    | "NOT_MATERIALIZED"
    | "APPROVED"
    | "CONSUMING"
    | "CONSUMED"
    | "REJECTED"
    | "EXPIRED";
  executionStatus: string;
  receiptIds: string[];
  createdAt: string;
  expiresAt: string;
  consumedAt: string | null;
}

export interface PendingWarrant {
  id: string;
  incidentId: string;
  warrantHash: string;
  canonicalDocument: string;
  patchHash: string;
  baseSha: string;
  paths: string[];
  commands: string[];
  expiresAt: string;
  approvalState: "pending" | "approved" | "rejected" | "expired" | "unavailable";
}

export interface IncidentArtifacts {
  evidence: EvidenceItem[];
  diff: string | null;
  tests: TestResult[];
  warrant: PendingWarrant | null;
}

export interface IncidentSummary {
  id: string;
  title: string;
  state: IncidentState;
  severity: string;
  service: string;
  baseSha: string;
  createdAt: string;
  updatedAt: string;
}

export interface IncidentRoomSnapshot {
  viewerRole: "read_only" | "operator" | "approver" | "live_trial";
  incident: IncidentSummary;
  seats: SeatView[];
  events: TimelineEvent[];
  specialistSummaries: SpecialistSummary[];
  warrants: WarrantHistoryItem[];
  artifacts: IncidentArtifacts;
  pendingWarrant: PendingWarrant | null;
}

export type PublishedCaseVerdictStep =
  | "CLEAR"
  | "REMAND"
  | "BLOCK"
  | "ABSTAIN";

export interface PublishedSeatSpend {
  seat: SeatName;
  effort: Effort;
  escalationCount: number;
  costUsd: number;
}

export interface PublishedCaseSummary {
  incidentId: string;
  title: string;
  state: "VERIFIED";
  scenario: string;
  createdAt: string;
  updatedAt: string;
  revision: number;
  manifestSha256: string;
  verdictPath: PublishedCaseVerdictStep[];
  recordedCostUsd: number | null;
  durationSeconds: number | null;
  evidenceToVerifiedSeconds: number | null;
  humanGateDwellSeconds: number | null;
  executionVerificationSeconds: number | null;
  seatSpend: PublishedSeatSpend[];
}

export interface PublishedCaseDetail {
  incidentId: string;
  displayTitle: string;
  revision: number;
  manifestSha256: string;
  snapshot: IncidentRoomSnapshot;
}

export type StreamConnectionState = "connecting" | "live" | "reconnecting" | "offline";
