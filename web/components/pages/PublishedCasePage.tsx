"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { ArrowLeft, BookOpenCheck, FileWarning, RefreshCw, ShieldCheck } from "lucide-react";

import { WarrantAnatomy } from "@/components/exhibits/WarrantAnatomy";
import { AuthorityLifecycle } from "@/components/exhibits/AuthorityLifecycle";
import { ImpactMetrics } from "@/components/exhibits/ImpactMetrics";
import { HypothesisExhibit } from "@/components/exhibits/HypothesisExhibit";
import { RecordScrubber } from "@/components/exhibits/RecordScrubber";
import { WhatHappened } from "@/components/exhibits/WhatHappened";
import { SignalRoom } from "@/components/room/SignalRoom";
import { fetchPublishedCase } from "@/lib/api";
import {
  deriveCaseMetrics,
  deriveCompetingHypotheses,
  deriveAuthorityLifecycle,
  deriveWhatHappened,
  projectRecordedPrefix,
} from "@/lib/case-exhibits";
import { usePrefersReducedMotion } from "@/lib/motion";
import { projectRoomMotion } from "@/lib/room-motion";
import { buildRoomStory, hasSupportedProvenance } from "@/lib/room-story";
import { formatRecordedDurationMs } from "@/lib/presentation";
import type { PublishedCaseDetail, TimelineEvent } from "@/lib/types";

import styles from "./Cases.module.css";

interface DetailLoadState {
  publishedCase: PublishedCaseDetail | null;
  loading: boolean;
  error: string | null;
}

function eventNumber(event: TimelineEvent, field: string): number | null {
  const value = event.details?.[field];
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : null;
}

function recordedCost(events: readonly TimelineEvent[]): string {
  const metrics = events.filter((event) =>
    event.kind === "MODEL_METRICS_RECORDED" &&
    hasSupportedProvenance(event.eventHash, event.rawPublicJson));
  if (!metrics.length) return "Not recorded";
  const costs = metrics.map((event) => eventNumber(event, "cost_usd"));
  if (costs.some((cost) => cost === null)) return "Unavailable";
  return `$${costs.reduce<number>((total, cost) => total + (cost ?? 0), 0).toFixed(4)}`;
}

function recordedDuration(events: readonly TimelineEvent[]): string {
  const occurred = events
    .filter((event) => hasSupportedProvenance(event.eventHash, event.rawPublicJson))
    .map((event) => Date.parse(event.occurredAt))
    .filter(Number.isFinite);
  if (occurred.length < 2) return "Not recorded";
  return formatRecordedDurationMs(Math.max(0, Math.max(...occurred) - Math.min(...occurred)));
}

export function PublishedCasePage({ incidentId }: { incidentId: string }) {
  const [attempt, setAttempt] = useState(0);
  const [selectedEventCount, setSelectedEventCount] = useState<number | null>(null);
  const reducedMotion = usePrefersReducedMotion();
  const [state, setState] = useState<DetailLoadState>({
    publishedCase: null,
    loading: true,
    error: null,
  });

  useEffect(() => {
    const controller = new AbortController();
    fetchPublishedCase(incidentId, controller.signal)
      .then((publishedCase) => {
        setSelectedEventCount(publishedCase.snapshot.events.length);
        setState({ publishedCase, loading: false, error: null });
      })
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") return;
        setState({
          publishedCase: null,
          loading: false,
          error: error instanceof Error ? error.message : "Published case unavailable",
        });
      });
    return () => controller.abort();
  }, [attempt, incidentId]);

  const snapshot = state.publishedCase?.snapshot ?? null;
  const projectedSnapshot = useMemo(() => {
    if (!snapshot) return null;
    const count = selectedEventCount ?? snapshot.events.length;
    return projectRecordedPrefix(snapshot, count) ?? snapshot;
  }, [selectedEventCount, snapshot]);
  const story = useMemo(
    () => projectedSnapshot ? buildRoomStory(projectedSnapshot) : null,
    [projectedSnapshot],
  );
  const motion = useMemo(
    () => projectedSnapshot
      ? projectRoomMotion(projectedSnapshot, { reducedMotion })
      : null,
    [projectedSnapshot, reducedMotion],
  );

  if (state.loading) {
    return (
      <main id="main-content" className={styles.detailPage} data-page="case-detail" tabIndex={-1} aria-busy="true">
        <section className={styles.detailState} role="status">
          <RefreshCw className={styles.loadingIcon} aria-hidden="true" />
          <div><strong>Loading published case</strong><span>Validating the public manifest and projection…</span></div>
        </section>
      </main>
    );
  }

  if (state.error || !state.publishedCase || !snapshot || !projectedSnapshot || !story || !motion) {
    return (
      <main id="main-content" className={styles.detailPage} data-page="case-detail" tabIndex={-1}>
        <section className={`${styles.detailState} ${styles.errorPanel}`} role="alert">
          <FileWarning aria-hidden="true" />
          <div><strong>Published case unavailable</strong><span>{state.error ?? "The public projection failed closed."}</span></div>
          <button
            type="button"
            onClick={() => {
              setSelectedEventCount(null);
              setState({ publishedCase: null, loading: true, error: null });
              setAttempt((value) => value + 1);
            }}
          >
            Retry published case
          </button>
          <Link href="/cases">Return to published cases</Link>
        </section>
      </main>
    );
  }

  return (
    <main id="main-content" className={styles.detailPage} data-page="case-detail" tabIndex={-1}>
      <header className={styles.detailHeader}>
        <Link href="/cases" className={styles.backLink}><ArrowLeft aria-hidden="true" />Published cases</Link>
        <div className={styles.detailTitle}>
          <span className={styles.detailIcon} aria-hidden="true"><BookOpenCheck /></span>
          <div>
            <span className={styles.eyebrow}>Published read-only case</span>
            <h1>{state.publishedCase.displayTitle}</h1>
            <code>{state.publishedCase.incidentId}</code>
          </div>
        </div>
        <dl className={styles.publicationFacts} aria-label="Publication manifest">
          <div><dt>Scope</dt><dd><ShieldCheck aria-hidden="true" />Sanitized projection</dd></div>
          <div><dt>Publication</dt><dd>Revision {state.publishedCase.revision}</dd></div>
          <div className={styles.detailCryptoRow}>
            <dt>Record integrity</dt>
            <dd>
              <details className={styles.cryptoDetails}>
                <summary>Inspect cryptographic details</summary>
                <code>{state.publishedCase.manifestSha256}</code>
              </details>
            </dd>
          </div>
        </dl>
      </header>

      <dl className={styles.recordedFacts} aria-label="Recorded case facts">
        <div><dt>Recorded model spend</dt><dd>{recordedCost(story.events)}</dd></div>
        <div><dt>Incident duration</dt><dd>{recordedDuration(story.events)}</dd></div>
        <div><dt>Published record</dt><dd>{story.eventCount} events</dd></div>
        <div>
          <dt>Trusted proof</dt>
          <dd>
            {story.proof.state === "verified" && story.proof.counts
              ? `${story.proof.counts.receipts} / ${story.proof.counts.jobs} / ${story.proof.counts.deliveries}`
              : "Unavailable"}
          </dd>
        </div>
      </dl>

      <WhatHappened sentences={deriveWhatHappened(snapshot)} />
      <ImpactMetrics metrics={deriveCaseMetrics(snapshot)} scope="this published case" />
      <HypothesisExhibit exhibit={deriveCompetingHypotheses(snapshot)} />

      <section className={styles.readOnlyNotice} aria-label="Read-only case boundary">
        <ShieldCheck aria-hidden="true" />
        <p>
          <strong>Publication is the authorization boundary.</strong>
          This replay contains no approval, mutation, shell, test-run, secret, or raw-evidence capability.
        </p>
      </section>

      <div id="recorded-replay" className={styles.caseExhibits}>
        <RecordScrubber
          eventCount={snapshot.events.length}
          selectedEventCount={projectedSnapshot.events.length}
          selectedTimestamp={projectedSnapshot.events.at(-1)?.occurredAt ?? null}
          onChange={setSelectedEventCount}
        />
        <WarrantAnatomy warrant={snapshot.warrants.at(-1) ?? null} />
        <AuthorityLifecycle items={deriveAuthorityLifecycle(snapshot)} />
      </div>

      <div id="recorded-artifacts">
        <SignalRoom
          snapshot={projectedSnapshot}
          story={story}
          motion={motion}
          connectionState="offline"
        />
      </div>
    </main>
  );
}
