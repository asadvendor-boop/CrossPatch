import { ArrowRight, Database, FileCheck2, ShieldCheck } from "lucide-react";

import type { PayloadEquivalenceComparison as Comparison } from "@/lib/case-exhibits";

import styles from "./PayloadEquivalenceComparison.module.css";

function statusSequence(statuses: readonly number[]): string {
  return statuses.join(" / ");
}

function countSequence(counts: Comparison["repaired"]["counts"]): string {
  const label = (value: number, singular: string, plural = `${singular}s`) => (
    `${value} ${value === 1 ? singular : plural}`
  );
  return [
    label(counts.receipts, "receipt"),
    label(counts.jobs, "job"),
    label(counts.deliveries, "delivery", "deliveries"),
  ].join(" / ");
}

export function PayloadEquivalenceComparison({
  comparison,
}: {
  comparison: Comparison | null;
}) {
  if (!comparison) return null;

  return (
    <section
      className={styles.comparison}
      aria-labelledby="payload-equivalence-comparison-title"
      data-testid="payload-equivalence-comparison"
    >
      <header className={styles.header}>
        <span className={styles.kicker}>Recorded causal proof</span>
        <h2 id="payload-equivalence-comparison-title">Retry semantics, before and after</h2>
        <p>The equivalent retry changes. The genuinely different payload does not.</p>
      </header>

      <div className={styles.sequence}>
        <article
          className={styles.affected}
          data-record-source-id={comparison.affected.source.id}
          data-record-source-sha256={comparison.affected.source.sha256}
        >
          <div className={styles.label}>
            <FileCheck2 aria-hidden="true" />
            <div>
              <strong>Affected reproduction</strong>
              <span>Sanitized incident evidence</span>
            </div>
          </div>
          <output>{statusSequence(comparison.affected.responseStatuses)}</output>
          <p>First delivery / equivalent retry / different payload</p>
        </article>

        <ArrowRight className={styles.arrow} aria-hidden="true" />

        <article
          className={styles.repaired}
          data-record-source-id={comparison.repaired.source.id}
          data-record-source-sha256={comparison.repaired.source.sha256}
        >
          <div className={styles.label}>
            <ShieldCheck aria-hidden="true" />
            <div>
              <strong>Trusted verification</strong>
              <span>Post-patch sidecar oracle</span>
            </div>
          </div>
          <output>{statusSequence(comparison.repaired.responseStatuses)}</output>
          <p>First delivery / equivalent retry / different payload</p>
        </article>

        <article
          className={styles.oracle}
          data-record-source-id={comparison.repaired.source.id}
          data-record-source-sha256={comparison.repaired.source.sha256}
        >
          <div className={styles.label}>
            <Database aria-hidden="true" />
            <div>
              <strong>Database oracle</strong>
              <span>Trusted PostgreSQL observation</span>
            </div>
          </div>
          <output>{countSequence(comparison.repaired.counts)}</output>
          <p>One durable business outcome after all three requests</p>
        </article>
      </div>
    </section>
  );
}
