import {
  ArrowRight,
  Boxes,
  GitBranch,
  RadioTower,
  ReceiptText,
  Send,
  ShieldCheck,
} from "lucide-react";
import type { ReactNode } from "react";

import { RecordDerivedHeadline } from "./RecordDerivedHeadline";
import {
  ApprovalBarrier,
  RecordedEventLedger,
  RecordedMomentFeed,
  RoomFrame,
  RoomSeats,
  RoomStatusLegend,
  VerifiedProof,
  type RoomViewProps,
} from "./RoomPrimitives";
import { formatPublicEnum } from "@/lib/presentation";
import { canonicalRoomSnapshot, type RoomMotionRegions } from "@/lib/room-motion";
import { buildRoomStory } from "@/lib/room-story";
import type { StreamConnectionState } from "@/lib/types";

import styles from "./SignalRoom.module.css";

const STAGES = [
  "evidence",
  "analysis",
  "repair",
  "review",
  "approval",
  "execution",
  "verified",
] as const;

type SignalState = "pending" | "current" | "complete";

function signalState(stage: RoomViewProps["story"]["stage"], threshold: number): SignalState {
  const current = STAGES.indexOf(stage);
  if (current < threshold) return "pending";
  if (current === threshold) return "current";
  return "complete";
}

function countLabel(count: number, singular: string, plural: string): string {
  return `${count} ${count === 1 ? singular : plural}`;
}

interface SignalRoomProps extends RoomViewProps {
  approvalControls?: ReactNode;
  artifactInspector?: ReactNode;
  connectionState?: StreamConnectionState;
}

const REGION_NAMES: Record<keyof RoomMotionRegions, string> = {
  header: "header",
  seats: "seats",
  topology: "topology",
  feed: "feed",
  humanGate: "human-gate",
  proof: "proof",
  actions: "actions",
  artifacts: "artifacts",
  ledger: "ledger",
};

function motionRegion(motion: RoomViewProps["motion"], key: keyof RoomMotionRegions) {
  const region = motion.regions[key];
  return {
    "data-motion-region": REGION_NAMES[key],
    "data-motion-ordinal": region.ordinal,
    "data-motion-state": region.state,
  };
}

function storyMatchesCanonicalEvents(
  story: RoomViewProps["story"],
  snapshot: RoomViewProps["snapshot"],
): boolean {
  return story.events.length === snapshot.events.length
    && story.events.every((event, index) => event.id === snapshot.events[index]?.id);
}

export function SignalRoom({
  snapshot,
  story: suppliedStory,
  motion,
  approvalControls,
  artifactInspector,
  connectionState = "offline",
}: SignalRoomProps) {
  const canonicalSnapshot = canonicalRoomSnapshot(snapshot);
  const story = storyMatchesCanonicalEvents(suppliedStory, canonicalSnapshot)
    ? suppliedStory
    : buildRoomStory(canonicalSnapshot);
  const baseline = story.baselineCounts;
  const sanitizerEvidence = !baseline
    ? snapshot.artifacts.evidence.find((evidence) => evidence.tags?.some((tag) => (
        tag === "POTENTIAL_INSTRUCTION_REDACTED"
          || tag === "PRIVATE_AUTHORITY_MATERIAL_REDACTED"
      ))) ?? null
    : null;
  const instructionMaterialRedacted = sanitizerEvidence?.tags?.includes(
    "POTENTIAL_INSTRUCTION_REDACTED",
  ) ?? false;
  const shortHead = motion.eventHead ? motion.eventHead.slice(0, 12) : "unavailable";
  const recordComplete = motion.recordState === "complete";
  const recordTerminal = recordComplete
    ? snapshot.incident.state === "BLOCKED" ? "blocked" : "verified"
    : "active";
  const streamLabel = recordComplete ? "Record complete" : connectionState;
  const streamState = recordComplete ? "complete" : connectionState;
  const projectionScope = snapshot.viewerRole === "read_only"
    ? "published"
    : snapshot.viewerRole === "live_trial"
      ? "live-trial"
      : "authorized";
  const projectionLabel = projectionScope === "published"
    ? "Published projection"
    : projectionScope === "live-trial"
      ? "Private trial projection"
      : "Authorized projection";
  const artifactRegionLabel = projectionScope === "published"
    ? "Published incident artifacts"
    : projectionScope === "live-trial"
      ? "Private trial artifacts"
      : "Authorized incident artifacts";

  return (
    <RoomFrame story={story} className={styles.signalRoom} recordTerminal={recordTerminal}>
      <div className={styles.signalShell} data-motion={motion.choreography} data-stage={story.stage}>
        <header className={styles.recordHeader} {...motionRegion(motion, "header")}>
          <RecordDerivedHeadline
            projectionScope={projectionScope}
            story={story}
            title={snapshot.incident.title}
          />
          <dl className={styles.recordFacts} aria-label="Recorded room status">
            <div>
              <dt>State</dt>
              <dd
                data-recorded-state={snapshot.incident.state}
                data-testid="recorded-room-state"
              >
                {formatPublicEnum(snapshot.incident.state)}
              </dd>
            </div>
            <div><dt>Records</dt><dd>{motion.eventCount}</dd></div>
            <div><dt>Chain head</dt><dd title={motion.eventHead}>{shortHead}</dd></div>
            <div>
              <dt>Stream</dt>
              <dd data-stream={streamState} role="status" aria-live="polite" aria-atomic="true">
                {streamLabel}
              </dd>
            </div>
          </dl>
        </header>

        <section
          className={styles.castPanel}
          aria-labelledby="signal-cast-title"
          data-motion-active-seat={motion.activeSeat ?? "none"}
          {...motionRegion(motion, "seats")}
        >
          <div className={styles.sectionHeading}>
            <div>
              <span>Fixed execution order</span>
              <h3 id="signal-cast-title">Five agents. One human authority boundary.</h3>
            </div>
            <RoomStatusLegend />
          </div>
          <RoomSeats activeSeat={motion.activeSeat} seats={snapshot.seats} />
        </section>

        <div className={styles.workspace}>
          <section
            className={styles.causalPanel}
            aria-labelledby="signal-causal-title"
            data-testid="delivery-split"
            {...motionRegion(motion, "topology")}
          >
            <header className={styles.panelHeader}>
              <div>
                <span>{sanitizerEvidence ? "Recorded sanitizer boundary / dark anchor" : "Recorded baseline / dark anchor"}</span>
                <h3 id="signal-causal-title">
                  {sanitizerEvidence
                    ? instructionMaterialRedacted
                      ? "Instruction-like evidence stopped at the evidence boundary"
                      : "Authority-bearing material withheld at the evidence boundary"
                    : "Webhook race topology"}
                </h3>
              </div>
              <strong>{motion.storyStep}</strong>
            </header>

            {baseline ? (
              <div
                className={styles.causalMap}
                role="img"
                aria-label={
                  `Recorded webhook race: ${countLabel(baseline.receipts, "receipt", "receipts")}, `
                  + `${countLabel(baseline.jobs, "job", "jobs")}, and `
                  + `${countLabel(baseline.deliveries, "delivery", "deliveries")}`
                }
              >
                <div className={styles.signalNode} data-signal-state={signalState(motion.storyStep, 0)}>
                  <RadioTower aria-hidden="true" />
                  <span>Trigger</span>
                  <strong>Webhook event</strong>
                </div>
                <ArrowRight className={styles.arrow} aria-hidden="true" />
                <div className={styles.signalNode} data-signal-state={signalState(motion.storyStep, 1)}>
                  <ReceiptText aria-hidden="true" />
                  <span>Recorded</span>
                  <strong>{countLabel(baseline.receipts, "receipt", "receipts")}</strong>
                </div>
                <ArrowRight className={styles.arrow} aria-hidden="true" />
                <div className={styles.branchStack}>
                  <span className={styles.branchCaption}><GitBranch aria-hidden="true" />Same webhook, parallel outcomes</span>
                  <div className={styles.branchNodes}>
                    <div className={styles.signalNode} data-signal-state={signalState(motion.storyStep, 2)}>
                      <Boxes aria-hidden="true" />
                      <span>Queued work</span>
                      <strong>{countLabel(baseline.jobs, "job", "jobs")}</strong>
                    </div>
                    <div className={styles.signalNode} data-signal-state={signalState(motion.storyStep, 3)}>
                      <Send aria-hidden="true" />
                      <span>Observed effect</span>
                      <strong>{countLabel(baseline.deliveries, "delivery", "deliveries")}</strong>
                    </div>
                  </div>
                </div>
              </div>
            ) : sanitizerEvidence ? (
              <div
                className={styles.sanitizerBoundary}
                data-testid="sanitizer-boundary"
                data-classification={sanitizerEvidence.classification}
              >
                <ShieldCheck aria-hidden="true" />
                <div>
                  <span>Untrusted evidence</span>
                  <strong>
                    {instructionMaterialRedacted
                      ? "Instruction-like material was removed before model context."
                      : "Sensitive authority material was withheld from model context."}
                  </strong>
                  <p>
                    The public record retains the sanitized evidence identity and the exact
                    redaction decisions without exposing the removed bytes.
                  </p>
                  <code>{sanitizerEvidence.id}</code>
                </div>
                <ul aria-label="Recorded sanitizer decisions">
                  {sanitizerEvidence.tags?.map((tag) => (
                    <li key={tag} data-sanitizer-tag={tag}>{formatPublicEnum(tag)}</li>
                  ))}
                </ul>
              </div>
            ) : (
              <p
                className={styles.unavailable}
                data-baseline-state="not-reached"
                role="status"
              >
                Baseline counts have not been reached in this recorded view. The completed
                record remains available in the ledger.
              </p>
            )}

            <ol className={styles.stageRail} aria-label="Recorded incident stage">
              {STAGES.map((stage, index) => (
                <li
                  key={stage}
                  data-stage-state={signalState(motion.storyStep, index)}
                  aria-current={stage === motion.storyStep ? "step" : undefined}
                >
                  <span>{String(index + 1).padStart(2, "0")}</span>{stage}
                </li>
              ))}
            </ol>
          </section>

          <section
            className={styles.feedPanel}
            aria-labelledby="signal-feed-title"
            {...motionRegion(motion, "feed")}
          >
            <header className={styles.panelHeader}>
              <div>
                <span>Recorded-moment feed / latest first</span>
                <h3 id="signal-feed-title">Agents speak from the record</h3>
              </div>
              <strong>{story.moments.length} moments</strong>
            </header>
            <RecordedMomentFeed story={story} />
          </section>
        </div>

        <section className={styles.controlRibbon} aria-label="Authority and verification outcome">
          <div className={styles.motionCell} {...motionRegion(motion, "humanGate")}>
            <ApprovalBarrier story={story} />
          </div>
          <div className={styles.motionCell} {...motionRegion(motion, "proof")}>
            <VerifiedProof story={story} />
          </div>
        </section>

        {approvalControls ? (
          <section
            className={styles.actionRegion}
            aria-label="Interactive warrant approval controls"
            {...motionRegion(motion, "actions")}
          >
            <header><span>Exact authority control</span><h3>Review the live warrant</h3></header>
            {approvalControls}
          </section>
        ) : null}

        {artifactInspector ? (
          <section
            className={styles.artifactRegion}
            aria-label={artifactRegionLabel}
            {...motionRegion(motion, "artifacts")}
          >
            <header><span>{projectionLabel}</span><h3>Evidence, findings, patch, tests, and warrant</h3></header>
            {artifactInspector}
          </section>
        ) : null}

        <div className={styles.ledgerRegion} {...motionRegion(motion, "ledger")}>
          <RecordedEventLedger story={story} />
        </div>
      </div>
    </RoomFrame>
  );
}
