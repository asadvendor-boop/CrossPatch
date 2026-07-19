"use client";

import { useEffect, useMemo } from "react";

import { EmptyState } from "./EmptyState";
import { StatusBadge } from "./StatusBadge";
import { normalizeTimelineEvent, persistEvent } from "@/lib/events";
import { formatPublicEnum } from "@/lib/presentation";
import type { StreamConnectionState, TimelineEvent } from "@/lib/types";

interface TimelineProps {
  events: readonly TimelineEvent[];
  connectionState: StreamConnectionState;
}

function testId(kind: string): string {
  return `event-${kind.toLowerCase().replaceAll("_", "-")}`;
}

export function Timeline({ events, connectionState }: TimelineProps) {
  const ordered = useMemo(
    () => [...events].map(normalizeTimelineEvent).sort((a, b) => a.sequence - b.sequence),
    [events],
  );
  const newest = ordered.length > 0 ? ordered[ordered.length - 1] : null;

  useEffect(() => {
    for (const event of ordered) persistEvent(event);
  }, [ordered]);

  return (
    <section className="timeline-panel panel-corners" aria-labelledby="timeline-title">
      <header className="panel-heading">
        <div>
          <span className="coordinate-label">LIVE TIMELINE / APPEND ONLY</span>
          <h2 id="timeline-title">Incident timeline</h2>
        </div>
        <StatusBadge state={connectionState} label={connectionState} />
      </header>
      <div className="timeline-panel__status" aria-live="polite" aria-atomic="true">
        {connectionState === "live" ? "Live event stream connected" : `Event stream ${connectionState}`}
      </div>
      <div
        className="timeline-panel__announcement"
        data-testid="timeline-live-announcement"
        role="status"
        aria-live="polite"
        aria-atomic="true"
      >
        {newest
          ? `Latest incident event: ${formatPublicEnum(newest.kind)}. ${newest.summary}`
          : ""}
      </div>
      {ordered.length === 0 ? (
        <EmptyState
          title="No incident events yet"
          detail="Waiting for the first published event from this real incident."
        />
      ) : (
        <ol className="timeline" aria-label="Incident events">
          {ordered.map((event) => (
            <li
              className={`timeline-event timeline-event--${event.state}`}
              key={event.id}
              data-testid={testId(event.kind)}
              data-state={event.state}
            >
              <div className="timeline-event__sequence" aria-label={`Sequence ${event.sequence}`}>
                {String(event.sequence).padStart(3, "0")}
              </div>
              <span className="timeline-event__node" aria-hidden="true" />
              <article>
                <header>
                  <div>
                    <span className="timeline-event__kind" data-recorded-kind={event.kind}>
                      {formatPublicEnum(event.kind)}
                    </span>
                    <strong>{event.summary}</strong>
                  </div>
                  <StatusBadge state={event.state} />
                </header>
                <div className="timeline-event__meta">
                  <span>{event.actor}</span>
                  <time dateTime={event.occurredAt}>
                    {event.occurredAt ? new Date(event.occurredAt).toLocaleString() : "Time unavailable"}
                  </time>
                  <span>ID {event.id}</span>
                </div>
                {event.detail ? <p className="timeline-event__detail">{event.detail}</p> : null}
                {event.details && Object.keys(event.details).length > 0 ? (
                  <pre
                    className="timeline-event__detail"
                    data-testid={`${testId(event.kind)}-details`}
                    aria-label="Published event details"
                  >
                    {JSON.stringify(event.details, null, 2)}
                  </pre>
                ) : null}
                {event.explanation ? (
                  <p className="timeline-event__escalation">{event.explanation}</p>
                ) : null}
              </article>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}
