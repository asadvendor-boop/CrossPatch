"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Archive,
  ArrowRight,
  FileCheck2,
  RefreshCw,
  ShieldCheck,
} from "lucide-react";

import { PublishedStatsRibbon } from "@/components/exhibits/PublishedStatsRibbon";
import { fetchPublishedCases } from "@/lib/api";
import {
  isFeaturedCase,
  isHostileEvidenceCase,
  pinFeaturedCases,
} from "@/lib/featured-cases";
import { formatPublicEnum, formatRecordedDurationSeconds } from "@/lib/presentation";
import { isRecordedReplay } from "@/lib/replay";
import { scenarioMetadata } from "@/lib/scenarios";
import type { PublishedCaseSummary } from "@/lib/types";

import styles from "./Cases.module.css";

interface CasesLoadState {
  cases: PublishedCaseSummary[];
  loading: boolean;
  error: string | null;
}

function readableDate(value: string): string {
  return new Intl.DateTimeFormat("en", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "UTC",
  }).format(new Date(value));
}

function recordedCost(value: number | null): string {
  return value === null ? "Not recorded" : `$${value.toFixed(4)}`;
}

function costPerVerifiedRepair(cases: PublishedCaseSummary[]): number | null {
  if (!cases.length || cases.some((publishedCase) => publishedCase.recordedCostUsd === null)) {
    return null;
  }
  const total = cases.reduce(
    (sum, publishedCase) => sum + (publishedCase.recordedCostUsd ?? 0),
    0,
  );
  return total / cases.length;
}

export function CasesPage() {
  const replayMode = isRecordedReplay();
  const [attempt, setAttempt] = useState(0);
  const [state, setState] = useState<CasesLoadState>({
    cases: [],
    loading: true,
    error: null,
  });

  useEffect(() => {
    const controller = new AbortController();
    fetchPublishedCases(controller.signal)
      .then((cases) => setState({ cases, loading: false, error: null }))
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") return;
        setState({
          cases: [],
          loading: false,
          error: error instanceof Error ? error.message : "Published case index unavailable",
        });
      });
    return () => controller.abort();
  }, [attempt]);

  const recordedCostPerRepair = costPerVerifiedRepair(state.cases);
  const displayedCases = pinFeaturedCases(state.cases);

  return (
    <main
      id="main-content"
      className={styles.page}
      data-page="cases"
      tabIndex={-1}
      aria-busy={state.loading}
    >
      <header className={styles.hero}>
        <span className={styles.heroIcon} aria-hidden="true"><Archive /></span>
        <div>
          <span className={styles.eyebrow}>Publication-scoped evidence</span>
          <h1>Published cases</h1>
          <p>
            Browse sanitized, immutable incident projections. Nothing unpublished, in-flight,
            secret-bearing, or mutation-capable enters this surface.
          </p>
        </div>
        <div className={styles.boundary}>
          <ShieldCheck aria-hidden="true" />
          <span>Read-only boundary</span>
          <strong>Explicitly published cases only</strong>
        </div>
      </header>

      {!state.loading ? (
        <div className={styles.publicationRibbon}>
          <PublishedStatsRibbon
            hasHostileEvidence={state.cases.some((item) => isHostileEvidenceCase(item.incidentId))}
            publishedCount={state.error ? null : state.cases.length}
            status={state.error ? "unavailable" : "ready"}
          />
        </div>
      ) : null}

      {state.loading ? (
        <section className={styles.statePanel} role="status">
          <RefreshCw className={styles.loadingIcon} aria-hidden="true" />
          <div><strong>Loading published cases</strong><span>Reading the public case index…</span></div>
        </section>
      ) : null}

      {state.error ? (
        <section className={`${styles.statePanel} ${styles.errorPanel}`} role="alert">
          <FileCheck2 aria-hidden="true" />
          <div><strong>Published cases unavailable</strong><span>{state.error}</span></div>
          <button
            type="button"
            onClick={() => {
              setState({ cases: [], loading: true, error: null });
              setAttempt((value) => value + 1);
            }}
          >
            Retry published cases
          </button>
        </section>
      ) : null}

      {!state.loading && !state.error && state.cases.length === 0 ? (
        <section className={styles.emptyPanel} role="status">
          <FileCheck2 aria-hidden="true" />
          <span>Public index / zero records</span>
          <h2>No cases have been published.</h2>
          <p>
            {replayMode
              ? "The signed replay contains no published case."
              : "The boundary is working: unpublished and in-flight incidents remain private."}
          </p>
          {!replayMode ? (
            <Link href="/open-incident">Open an operator incident <ArrowRight aria-hidden="true" /></Link>
          ) : null}
        </section>
      ) : null}

      {!state.loading && !state.error && state.cases.length ? (
        <section className={styles.gallery} aria-labelledby="published-case-gallery-title">
          <header className={styles.galleryHeader}>
            <div>
              <span>Published proof / signed records</span>
              <h2 id="published-case-gallery-title">Verified incident records</h2>
            </div>
            <p>Each card is backed by a revisioned, SHA-256-bound public manifest.</p>
            <aside
              className={styles.costPerRepair}
              aria-label="Recorded cost per verified repair"
            >
              <span>Recorded cost / verified repair</span>
              <strong>
                {recordedCostPerRepair === null
                  ? "Unavailable"
                  : recordedCost(recordedCostPerRepair)}
              </strong>
              <small>
                {recordedCostPerRepair === null
                  ? "Incomplete recorded metrics"
                  : `${state.cases.length} verified ${state.cases.length === 1 ? "repair" : "repairs"}`}
              </small>
            </aside>
          </header>
          <ol className={styles.caseGrid}>
            {displayedCases.map((publishedCase, index) => (
              <li key={publishedCase.incidentId}>
                <article className={styles.caseCard} data-testid="published-case-card">
                  <header>
                    <span className={styles.caseIndex} aria-hidden="true">
                      {String(index + 1).padStart(2, "0")}
                    </span>
                    <span
                      className={styles.verifiedState}
                      data-recorded-state={publishedCase.state}
                      data-testid="published-case-status"
                    >
                      {formatPublicEnum(publishedCase.state)}
                    </span>
                  </header>
                  <div className={styles.caseIdentity}>
                    {isFeaturedCase(publishedCase.incidentId) ? (
                      <strong className={styles.featuredLabel}>Featured case</strong>
                    ) : null}
                    <div className={styles.scenarioContext} aria-label="Scenario context">
                      <span><code>{publishedCase.scenario}</code></span>
                      <small>
                        {scenarioMetadata(publishedCase.scenario)?.description
                          ?? `Recorded scenario: ${publishedCase.scenario}`}
                      </small>
                    </div>
                    <h3>{publishedCase.title}</h3>
                  </div>
                  <ol className={styles.verdictPath} aria-label="Recorded verdict path">
                    {publishedCase.verdictPath.map((step, stepIndex) => (
                      <li key={`${step}-${stepIndex}`}>
                        <span data-testid="verdict-step" data-verdict={step}>{step}</span>
                        {stepIndex < publishedCase.verdictPath.length - 1
                          ? <ArrowRight aria-hidden="true" />
                          : null}
                      </li>
                    ))}
                  </ol>
                  <dl>
                    <div><dt>Recorded model spend</dt><dd>{recordedCost(publishedCase.recordedCostUsd)}</dd></div>
                    <div><dt>Duration</dt><dd>{formatRecordedDurationSeconds(publishedCase.durationSeconds)}</dd></div>
                    <div><dt>Publication</dt><dd>Revision {publishedCase.revision}</dd></div>
                    <div><dt>Updated</dt><dd><time dateTime={publishedCase.updatedAt}>{readableDate(publishedCase.updatedAt)}</time></dd></div>
                    <div className={styles.manifestRow}>
                      <dt className={styles.srOnly}>Record details</dt>
                      <dd>
                        <details className={styles.cryptoDetails}>
                          <summary>Inspect cryptographic details</summary>
                          <dl>
                            <div><dt>Incident ID</dt><dd><code>{publishedCase.incidentId}</code></dd></div>
                            <div><dt>Manifest SHA-256</dt><dd><code>{publishedCase.manifestSha256}</code></dd></div>
                          </dl>
                        </details>
                      </dd>
                    </div>
                  </dl>
                  <Link href={`/cases/${encodeURIComponent(publishedCase.incidentId)}`}>
                    Open published case <ArrowRight aria-hidden="true" />
                  </Link>
                </article>
              </li>
            ))}
          </ol>
        </section>
      ) : null}
    </main>
  );
}
