import { Activity, Clock3, Coins, TimerReset } from "lucide-react";

import type { CaseMetrics, PublishedSetMetrics, SeatSpendMetric } from "@/lib/case-exhibits";
import { formatRecordedDurationMs } from "@/lib/presentation";
import { SEAT_ORDER } from "@/lib/tokens";

import styles from "./ImpactMetrics.module.css";

function scopeLabel(scope: string): string {
  return scope ? `${scope[0]?.toUpperCase()}${scope.slice(1)}` : scope;
}

function groupedSpend(items: readonly SeatSpendMetric[]): SeatSpendMetric[] {
  const groups = new Map<string, SeatSpendMetric>();
  for (const item of items) {
    const key = `${item.seat}:${item.effort}:${item.escalationCount}`;
    const prior = groups.get(key);
    groups.set(key, {
      ...item,
      costUsd: Number(((prior?.costUsd ?? 0) + item.costUsd).toFixed(12)),
    });
  }
  return [...groups.values()].sort((left, right) => (
    SEAT_ORDER.indexOf(left.seat) - SEAT_ORDER.indexOf(right.seat)
    || left.escalationCount - right.escalationCount
    || left.effort.localeCompare(right.effort)
  ));
}

export function ImpactMetrics({
  metrics,
  scope,
}: {
  metrics: CaseMetrics | PublishedSetMetrics;
  scope: "this published case" | "across this published set" | "sealed cohort";
}) {
  const publishedSet = "caseCount" in metrics;
  const timing = [
    {
      label: publishedSet ? "Median evidence to verified" : "Evidence to verified",
      value: publishedSet ? metrics.medianEvidenceToVerifiedMs : metrics.evidenceToVerifiedMs,
      measured: publishedSet ? metrics.measuredEvidenceToVerifiedCount : null,
      icon: Activity,
    },
    {
      label: publishedSet ? "Median human-gate dwell" : "Human-gate dwell",
      value: publishedSet ? metrics.medianHumanGateDwellMs : metrics.humanGateDwellMs,
      measured: publishedSet ? metrics.measuredHumanGateDwellCount : null,
      icon: Clock3,
    },
    {
      label: publishedSet
        ? "Median execution + verification"
        : "Execution + verification",
      value: publishedSet
        ? metrics.medianExecutionVerificationMs
        : metrics.executionVerificationMs,
      measured: publishedSet ? metrics.measuredExecutionVerificationCount : null,
      icon: TimerReset,
    },
  ].filter((item) => item.value !== null);
  const spend = groupedSpend(metrics.seatSpend);

  if (!timing.length && metrics.totalSpendUsd === null && !spend.length) return null;

  return (
    <section
      className={styles.panel}
      aria-label="Recorded impact metrics"
      data-testid="impact-metrics"
    >
      <header>
        <div>
          <span>Recorded impact</span>
          <h2>Measured from the event ledger</h2>
        </div>
        <strong>{scopeLabel(scope)}</strong>
      </header>
      <div className={styles.metrics}>
        {timing.map(({ label, value, measured, icon: Icon }) => (
          <article key={label}>
            <Icon aria-hidden="true" />
            <span>{label}</span>
            <strong>{formatRecordedDurationMs(value ?? 0)}</strong>
            {measured !== null ? <small>{measured} measured record{measured === 1 ? "" : "s"}</small> : null}
          </article>
        ))}
        {metrics.totalSpendUsd !== null ? (
          <article>
            <Coins aria-hidden="true" />
            <span>Recorded model spend</span>
            <strong>${metrics.totalSpendUsd.toFixed(4)}</strong>
            <small>No adoption or savings estimate</small>
          </article>
        ) : null}
      </div>
      {spend.length ? (
        <ol className={styles.spend} aria-label="Spend by seat and escalation">
          {spend.map((item) => (
            <li key={`${item.seat}-${item.effort}-${item.escalationCount}`}>
              <span>
                {item.seat} · {item.effort} · {item.escalationCount
                  ? `escalation ${item.escalationCount}`
                  : "base effort"}
              </span>
              <strong>${item.costUsd.toFixed(4)}</strong>
            </li>
          ))}
        </ol>
      ) : null}
    </section>
  );
}
