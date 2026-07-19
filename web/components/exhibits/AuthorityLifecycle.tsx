import {
  ArrowRight,
  CheckCircle2,
  CircleDot,
  KeyRound,
  ShieldAlert,
} from "lucide-react";

import type { AuthorityLifecycleItem } from "@/lib/case-exhibits";
import { formatPublicEnum } from "@/lib/presentation";

import styles from "./AuthorityLifecycle.module.css";

function readableUtc(value: string): string {
  return new Intl.DateTimeFormat("en", {
    dateStyle: "medium",
    timeStyle: "medium",
    timeZone: "UTC",
  }).format(new Date(value));
}

function RecordedStep({
  at,
  label,
  detail,
  state,
}: {
  at: string;
  label: string;
  detail?: string;
  state: "issued" | "approved" | "consumed" | "failed";
}) {
  return (
    <li data-state={state}>
      <span aria-hidden="true"><CircleDot /></span>
      <div>
        <strong>{label}</strong>
        {detail ? <small>{detail}</small> : null}
        <time dateTime={at}>{readableUtc(at)}</time>
      </div>
    </li>
  );
}

export function AuthorityLifecycle({ items }: { items: readonly AuthorityLifecycleItem[] }) {
  if (!items.length) return null;

  return (
    <section className={styles.lifecycle} aria-label="Consumed authority lifecycle">
      <header>
        <div>
          <span>Persisted warrant history</span>
          <h2>Consumed authority lifecycle</h2>
        </div>
        <strong><KeyRound aria-hidden="true" />Single-use authority</strong>
      </header>
      <ol className={styles.records}>
        {items.map((item, index) => (
          <li key={item.warrantId}>
            <article data-testid="authority-record">
              <header>
                <span>Authority {String(index + 1).padStart(2, "0")}</span>
                <strong>{item.warrantId}</strong>
                <code>{item.canonicalSha256}</code>
              </header>
              <ol className={styles.steps}>
                <RecordedStep at={item.issuedAt} label="Issued" state="issued" />
                {item.approvedAt ? (
                  <RecordedStep
                    at={item.approvedAt}
                    label={item.approver ? `Approved by ${item.approver}` : "Approved"}
                    state="approved"
                  />
                ) : null}
                {item.consumedAt ? (
                  <RecordedStep
                    at={item.consumedAt}
                    label="Consumed"
                    detail={`${item.receiptIds.length} recorded receipt${item.receiptIds.length === 1 ? "" : "s"}`}
                    state="consumed"
                  />
                ) : null}
                {item.failureAt ? (
                  <RecordedStep
                    at={item.failureAt}
                    label="Candidate failed"
                    detail={formatPublicEnum(item.executionStatus)}
                    state="failed"
                  />
                ) : null}
              </ol>
              {!item.approvedAt ? (
                <p className={styles.pending}><ShieldAlert aria-hidden="true" />Awaiting its own approval</p>
              ) : null}
              {item.successorWarrantId && item.successorCanonicalSha256 ? (
                <aside className={styles.successor}>
                  <CheckCircle2 aria-hidden="true" />
                  <div>
                    <strong>Fresh approval required</strong>
                    <span>{item.successorWarrantId}</span>
                    <code>{item.successorCanonicalSha256}</code>
                  </div>
                  <ArrowRight aria-hidden="true" />
                </aside>
              ) : null}
            </article>
          </li>
        ))}
      </ol>
    </section>
  );
}
