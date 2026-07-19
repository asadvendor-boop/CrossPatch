"use client";

import { useEffect, useState } from "react";

import { fetchPublishedCases } from "@/lib/api";
import { derivePublishedSummaryMetrics } from "@/lib/case-exhibits";
import { isHostileEvidenceCase } from "@/lib/featured-cases";
import type { PublishedCaseSummary } from "@/lib/types";

import { ImpactMetrics } from "./ImpactMetrics";
import { PublishedStatsRibbon } from "./PublishedStatsRibbon";
import styles from "./PublishedSetOverview.module.css";

interface LoadState {
  cases: PublishedCaseSummary[] | null;
  error: boolean;
}

export function PublishedSetOverview() {
  const [state, setState] = useState<LoadState>({ cases: null, error: false });

  useEffect(() => {
    const controller = new AbortController();
    fetchPublishedCases(controller.signal)
      .then((cases) => setState({ cases, error: false }))
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") return;
        setState({ cases: null, error: true });
      });
    return () => controller.abort();
  }, []);

  const metrics = state.cases ? derivePublishedSummaryMetrics(state.cases) : null;
  return (
    <div className={styles.proof} data-testid="published-set-overview">
      <PublishedStatsRibbon
        hasHostileEvidence={
          state.cases?.some((item) => isHostileEvidenceCase(item.incidentId)) ?? false
        }
        publishedCount={state.cases?.length ?? null}
        status={state.cases ? "ready" : state.error ? "unavailable" : "loading"}
      />
      {metrics ? <ImpactMetrics metrics={metrics} scope="across this published set" /> : null}
    </div>
  );
}
