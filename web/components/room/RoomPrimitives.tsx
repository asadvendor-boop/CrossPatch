"use client";

import { useState } from "react";
import { AtSign, ChevronRight, Clock3 } from "lucide-react";

import { PersonaPortrait } from "../PersonaPortrait";
import { StatusBadge } from "../StatusBadge";
import { formatPublicEnum } from "@/lib/presentation";
import { DEFAULT_SEATS, SEAT_ORDER } from "@/lib/tokens";
import { hasSupportedProvenance, type RoomMoment, type RoomStory } from "@/lib/room-story";
import type { RoomMotionState } from "@/lib/room-motion";
import type { IncidentRoomSnapshot, TimelineEvent } from "@/lib/types";

import styles from "./RoomPrimitives.module.css";

export interface RoomViewProps {
  snapshot: IncidentRoomSnapshot;
  story: RoomStory;
  motion: RoomMotionState;
}

export function RoomFrame({
  story,
  children,
  className = "",
  recordTerminal = "active",
}: {
  story: RoomStory;
  children: React.ReactNode;
  className?: string;
  recordTerminal?: "active" | "verified" | "blocked";
}) {
  return (
    <section
      className={`${styles.frame} ${className}`}
      data-testid="room-experience"
      data-room-layout="signal"
      data-event-head={story.eventHead}
      data-record-count={story.eventCount}
      data-story-step={story.stage}
      data-barrier-state={story.barrierState}
      data-proof-state={story.proof.state}
      data-record-terminal={recordTerminal}
    >
      {children}
    </section>
  );
}

export function RoomSeats({
  activeSeat,
  seats,
}: {
  activeSeat: RoomStory["activeSeat"];
  seats: IncidentRoomSnapshot["seats"];
}) {
  const byName = new Map(seats.map((seat) => [seat.name, seat]));
  const orderedSeats = SEAT_ORDER.map((name) =>
    byName.get(name) ?? DEFAULT_SEATS.find((seat) => seat.name === name)!);

  return (
    <ol className={styles.cast} aria-label="Five model-driven seats">
      {orderedSeats.map((seat) => (
        <li
          className={`${styles.seat} ${seat.name === activeSeat || seat.state === "working" ? styles.seatActive : ""}`}
          data-testid={`seat-${seat.name.toLowerCase()}`}
          data-room-seat="true"
          data-seat={seat.name}
          data-seat-state={seat.state}
          key={seat.name}
        >
          {seat.name === "Bailiff" ? (
            <div
              className={styles.seatApprovalBoundary}
              role="separator"
              aria-label="Human approval boundary"
            >
              <strong>Human gate</strong>
              <span>Magistrate → Bailiff</span>
            </div>
          ) : null}
          <PersonaPortrait seat={seat.name} />
          <div className={styles.seatCopy}>
            <div className={styles.seatHeading}>
              <strong>{seat.name}</strong>
              <StatusBadge state={seat.state} />
            </div>
            <span className={styles.seatRole}>{seat.role}</span>
            <small className={styles.seatModel}>{seat.model}</small>
            <p className={styles.seatRationale}>{seat.tierRationale}</p>
            <div className={styles.seatMeta}>
              <span>Effort: {seat.effort}</span>
              <span>Escalations: {seat.escalationCount}/2</span>
            </div>
          </div>
        </li>
      ))}
    </ol>
  );
}

export function RoomStatusLegend() {
  return (
    <ul className={styles.legend} data-testid="room-status-legend" aria-label="Room status legend">
      <li data-tone="active">Active</li>
      <li data-tone="warning">Needs human</li>
      <li data-tone="failure">Failed / abstain</li>
      <li data-tone="success">Verified</li>
    </ul>
  );
}

export function RecordedSourceDisclosure({ moment }: { moment: RoomMoment }) {
  return (
    <details className={styles.source}>
      <summary>Recorded source</summary>
      <dl>
        <dt>Record ID</dt><dd>{moment.source.id}</dd>
        <dt>SHA-256</dt><dd>{moment.source.sha256}</dd>
      </dl>
      <strong>Raw recorded JSON</strong>
      <pre>{moment.source.rawPublicJson}</pre>
    </details>
  );
}

export function RecordedMoment({ moment }: { moment: RoomMoment }) {
  return (
    <article
      className={styles.moment}
      data-testid={`moment-${moment.id}`}
      data-record-source-id={moment.source.id}
      data-record-source-sha256={moment.source.sha256}
      data-state={moment.state}
    >
      <div className={styles.momentHeader}>
        <div>
          <span data-recorded-kind={moment.kind}>{formatPublicEnum(moment.kind)}</span>
          <h3>{moment.actor}</h3>
        </div>
        <StatusBadge state={moment.state} />
      </div>
      {moment.mention ? <span className={styles.mention}>@{moment.mention}</span> : null}
      <p>{formatPublicEnum(moment.prose)}</p>
      <RecordedSourceDisclosure moment={moment} />
    </article>
  );
}

function recordedTime(value: string): string {
  const match = value.match(/T(\d{2}:\d{2}:\d{2})/);
  return match?.[1] ?? value;
}

function actorMonogram(actor: string): string {
  const words = actor.trim().split(/[^A-Za-z0-9]+/).filter(Boolean);
  if (words.length > 1) {
    return words.slice(0, 2).map((word) => word[0]).join("").toUpperCase();
  }
  return (words[0] || "record").slice(0, 2).toUpperCase();
}

export function RecordedMomentFeed({ story }: { story: RoomStory }) {
  const handoff = [...story.moments].reverse().find((moment) => moment.mention) ?? null;
  const moments = [...story.moments].reverse();

  return (
    <div className={styles.feedShell}>
      {handoff ? (
        <article className={styles.handoff} data-testid="record-handoff-spotlight" aria-hidden="true">
          <AtSign aria-hidden="true" />
          <div>
            <span>Recorded handoff · #{handoff.sequence}</span>
            <strong>{handoff.actor} → @{handoff.mention}</strong>
            <p>{formatPublicEnum(handoff.prose)}</p>
          </div>
        </article>
      ) : null}
      <ol
        className={styles.feed}
        data-testid="recorded-moment-feed"
        aria-label="Recorded room moments, latest first"
        role="log"
        aria-live="polite"
        aria-relevant="additions text"
      >
        {moments.map((moment) => (
          <li
            key={`${moment.source.kind}:${moment.id}`}
            data-testid="recorded-dialogue"
            data-sequence={moment.sequence}
          >
            <div className={styles.feedIdentity}>
              {moment.seat ? (
                <PersonaPortrait seat={moment.seat} />
              ) : (
                <span
                  className={styles.systemAvatar}
                  role="img"
                  aria-label={`${moment.actor} system record`}
                  data-testid="non-persona-avatar"
                >
                  {actorMonogram(moment.actor)}
                </span>
              )}
              <div>
                <strong>{moment.actor}</strong>
                <span><Clock3 aria-hidden="true" />{recordedTime(moment.occurredAt)}</span>
              </div>
            </div>
            <RecordedMoment moment={moment} />
          </li>
        ))}
      </ol>
    </div>
  );
}

function RecordedEventCard({ recordedEvent }: { recordedEvent: TimelineEvent }) {
  const [expanded, setExpanded] = useState(false);
  const provenanceValid = hasSupportedProvenance(recordedEvent.eventHash, recordedEvent.rawPublicJson);
  const defaultSummary = recordedEvent.kind.replaceAll("_", " ");
  const visibleDetail = recordedEvent.detail
    || (recordedEvent.summary === defaultSummary
      ? formatPublicEnum(recordedEvent.kind)
      : recordedEvent.summary);

  return (
    <details
      className={`${styles.eventCard} ${provenanceValid ? "" : styles.eventInvalid}`}
      data-testid="recorded-event"
      data-event-id={recordedEvent.id}
      data-event-hash={recordedEvent.eventHash}
      onToggle={(toggle) => setExpanded(toggle.currentTarget.open)}
    >
      <summary data-sequence={String(recordedEvent.sequence).padStart(3, "0")}>
        <strong data-recorded-kind={recordedEvent.kind}>
          {formatPublicEnum(recordedEvent.kind)}
        </strong>
        <span className={styles.eventActor}>{recordedEvent.actor}</span>
        <span className={styles.eventDetail}>{visibleDetail}</span>
        <span className={styles.eventStatus}>
          <StatusBadge
            state={provenanceValid ? recordedEvent.state : "neutral"}
            label={provenanceValid ? recordedEvent.state : "Raw event"}
          />
        </span>
        <span className={styles.eventAction}><ChevronRight aria-hidden="true" />View record</span>
      </summary>
      {expanded ? (
        <div className={styles.eventBody}>
          {!provenanceValid ? (
            <p className={styles.provenanceFailure}>Provenance unavailable — excluded from dialogue only</p>
          ) : null}
          <dl>
            <dt>Event ID</dt><dd>{recordedEvent.id}</dd>
            <dt>SHA-256</dt><dd>{recordedEvent.eventHash || "Missing from incident projection"}</dd>
            <dt>Occurred</dt><dd>{recordedEvent.occurredAt || "Unavailable"}</dd>
          </dl>
          <strong>Raw recorded JSON</strong>
          {recordedEvent.rawPublicJson
            ? <pre>{recordedEvent.rawPublicJson}</pre>
            : <p>Recorded JSON unavailable.</p>}
        </div>
      ) : null}
    </details>
  );
}

export function RecordedEventLedger({ story }: { story: RoomStory }) {
  return (
    <section className={styles.eventLedger} aria-labelledby="recorded-event-ledger-title">
      <header className={styles.eventLedgerHeader}>
        <div>
          <span>Append-only record / {story.events.length}</span>
          <h3 id="recorded-event-ledger-title">Every recorded event remains visible</h3>
        </div>
        <p>Dialogue is provenance-gated. Neutral raw cards preserve every recorded event.</p>
      </header>
      {story.events.length ? (
        <ol className={styles.eventList}>
          {story.events.map((event) => <li key={event.id}><RecordedEventCard recordedEvent={event} /></li>)}
        </ol>
      ) : (
        <p className={styles.eventEmpty} role="status">No incident events yet</p>
      )}
    </section>
  );
}

export function ApprovalBarrier({ story }: { story: RoomStory }) {
  return (
    <section className={styles.barrier} data-testid="approval-barrier" data-state={story.barrierState}>
      <span>Magistrate → human → Bailiff</span>
      <strong>Human approval</strong>
      <span>{story.barrierState === "unlocked" ? "Recorded approval unlocked execution" : "Execution remains sealed"}</span>
    </section>
  );
}

export function VerifiedProof({ story }: { story: RoomStory }) {
  const counts = story.proof.counts;
  const label = story.proof.state === "verified" && counts
    ? `${counts.receipts} / ${counts.jobs} / ${counts.deliveries}`
    : "Proof unavailable";

  return (
    <section className={styles.proof} data-testid="verified-proof" data-state={story.proof.state}>
      <span>Trusted HTTP + PostgreSQL verifier</span>
      <strong>{label}</strong>
      <span>{story.proof.receiptId ?? "No verified receipt"}</span>
    </section>
  );
}
