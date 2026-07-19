"use client";

import { useEffect, useState } from "react";
import { ChevronLeft, ChevronRight, Pause, Play, Rewind } from "lucide-react";

import { usePrefersReducedMotion } from "@/lib/motion";

import styles from "./RecordScrubber.module.css";

interface RecordScrubberProps {
  eventCount: number;
  selectedEventCount: number;
  selectedTimestamp: string | null;
  onChange: (eventCount: number) => void;
}

export function RecordScrubber({
  eventCount,
  selectedEventCount,
  selectedTimestamp,
  onChange,
}: RecordScrubberProps) {
  const reducedMotion = usePrefersReducedMotion();
  const [playing, setPlaying] = useState(false);
  const activelyPlaying = playing && !reducedMotion && selectedEventCount < eventCount;

  useEffect(() => {
    if (!activelyPlaying) return;
    const timer = window.setInterval(() => {
      onChange(Math.min(eventCount, selectedEventCount + 1));
    }, 850);
    return () => window.clearInterval(timer);
  }, [activelyPlaying, eventCount, onChange, selectedEventCount]);

  function play(): void {
    if (selectedEventCount >= eventCount) onChange(0);
    setPlaying(true);
  }

  function select(next: number): void {
    setPlaying(false);
    onChange(Math.max(0, Math.min(eventCount, next)));
  }

  const timestamp = selectedTimestamp
    ? new Intl.DateTimeFormat(undefined, {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      }).format(new Date(selectedTimestamp))
    : "Before the first recorded event";

  return (
    <section className={styles.scrubber} aria-labelledby="record-scrubber-title">
      <header>
        <div>
          <span>Canonical ledger playback</span>
          <h2 id="record-scrubber-title">Walk the recorded decision</h2>
        </div>
        <div className={styles.position} aria-live="polite" aria-atomic="true">
          <strong>Event {selectedEventCount} of {eventCount}</strong>
          <span>{timestamp}</span>
        </div>
      </header>

      <div className={styles.controls}>
        {!reducedMotion ? (
          activelyPlaying ? (
            <button type="button" className={styles.primary} onClick={() => setPlaying(false)}>
              <Pause aria-hidden="true" />Pause recorded events
            </button>
          ) : (
            <button type="button" className={styles.primary} onClick={play} disabled={!eventCount}>
              <Play aria-hidden="true" />Play recorded events
            </button>
          )
        ) : null}
        <button
          type="button"
          onClick={() => select(selectedEventCount - 1)}
          disabled={selectedEventCount === 0}
          aria-label="Step backward"
        >
          <ChevronLeft aria-hidden="true" />Previous
        </button>
        <button
          type="button"
          onClick={() => select(selectedEventCount + 1)}
          disabled={selectedEventCount === eventCount}
          aria-label="Step forward"
        >
          Next<ChevronRight aria-hidden="true" />
        </button>
        <button
          type="button"
          onClick={() => select(0)}
          disabled={selectedEventCount === 0}
          aria-label="Return to start"
        >
          <Rewind aria-hidden="true" />Start
        </button>
      </div>

      {reducedMotion ? (
        <p className={styles.reduced}>Reduced motion: step through the record with Previous and Next.</p>
      ) : (
        <label className={styles.range}>
          <span>Recorded event position</span>
          <input
            type="range"
            min={0}
            max={eventCount}
            step={1}
            value={selectedEventCount}
            aria-label="Recorded event position"
            onChange={(event) => select(Number(event.currentTarget.value))}
          />
          <span className={styles.rangeEnds} aria-hidden="true"><span>Opened</span><span>Record complete</span></span>
        </label>
      )}
    </section>
  );
}
