import {
  Boxes,
  CheckCircle2,
  FileCheck2,
  FileSearch,
  GitPullRequest,
  LockKeyhole,
  ShieldCheck,
  TestTube2,
  UserCheck,
} from "lucide-react";

import { PublishedSetOverview } from "@/components/exhibits/PublishedSetOverview";
import { PrimaryLink, SeatStrip } from "./PagePrimitives";
import styles from "./AppPages.module.css";

const FLOW = [
  { label: "Sanitize evidence", detail: "Raw bytes stay outside model context.", icon: FileSearch },
  { label: "Test hypotheses", detail: "The leading mechanism meets a real rival.", icon: GitPullRequest },
  { label: "Propose repair", detail: "Counsel emits a bounded patch, never commands.", icon: FileCheck2 },
  { label: "Review verdict", detail: "The decision fails closed when proof is incomplete.", icon: ShieldCheck },
  { label: "Approve warrant", detail: "A human reviews the exact hash-bound document.", icon: UserCheck },
  { label: "Verify execution", detail: "Trusted tests derive success outside candidate code.", icon: TestTube2 },
] as const;

// Historical evidence statement: this is not live telemetry. These immutable values are bound
// to the sealed paced-batch cohort at the recorded source revision below.
export const IMMUTABLE_SEALED_COHORT_STATEMENT = Object.freeze({
  cohortGitSha: "8a19ef1115bc1d665665a972f94d7c708a9dcbf5",
  genuineCases: 10,
  humanApproved: 10,
  verifiedRepairs: 10,
});

export function OverviewPage() {
  return (
    <main
      id="main-content"
      className={`${styles.page} ${styles.overviewPage}`}
      data-page="overview"
      tabIndex={-1}
    >
      <header className={styles.overviewHero}>
        <div>
          <span className={styles.overviewKicker}>Control plane / recorded proof</span>
          <h1>Operational proof, at a glance.</h1>
          <p>Evidence becomes a reviewed repair while the human authority boundary stays visible and inspectable.</p>
          <p className={styles.problemLine}>
            Agent remediation is unauditable, so humans can&apos;t safely delegate without recorded proof.
          </p>
        </div>
        <aside className={styles.cohortStamp} aria-label="Sealed cohort status">
          <span>Sealed cohort</span>
          <strong>
            {IMMUTABLE_SEALED_COHORT_STATEMENT.verifiedRepairs}
            {" / "}
            {IMMUTABLE_SEALED_COHORT_STATEMENT.genuineCases}
          </strong>
          <p>Verified</p>
        </aside>
      </header>

      <PublishedSetOverview />

      <section className={`${styles.overviewPanel} ${styles.overviewSeatPanel}`} aria-labelledby="overview-seats-title">
        <header className={styles.sectionHeader}>
          <div><span>Fixed execution order</span><h2 id="overview-seats-title">Five model-driven seats, one explicit gate</h2></div>
          <p>Exact model identity, role, effort, and escalation policy remain visible.</p>
        </header>
        <SeatStrip />
      </section>

      <section className={styles.metricGrid} aria-label="Verified cohort summary">
        <article>
          <span>01 / Genuine model runs</span>
          <strong>{IMMUTABLE_SEALED_COHORT_STATEMENT.genuineCases} genuine cases</strong>
          <FileCheck2 aria-hidden="true" />
        </article>
        <article>
          <span>02 / Recorded decisions</span>
          <strong>{IMMUTABLE_SEALED_COHORT_STATEMENT.humanApproved} human-approved</strong>
          <UserCheck aria-hidden="true" />
        </article>
        <article>
          <span>03 / Trusted outcomes</span>
          <strong>{IMMUTABLE_SEALED_COHORT_STATEMENT.verifiedRepairs} verified repairs</strong>
          <CheckCircle2 aria-hidden="true" />
        </article>
      </section>

      <section className={styles.flowPanel} aria-labelledby="overview-flow-title">
        <header className={styles.sectionHeader}>
          <div><span>Bounded control flow</span><h2 id="overview-flow-title">Six steps from evidence to proof</h2></div>
          <PrimaryLink href="/open-incident">Open an incident</PrimaryLink>
        </header>
        <ol className={styles.flowGrid} aria-label="Repair control flow">
          {FLOW.map(({ label, detail, icon: Icon }, index) => (
            <li key={label}>
              <span className={styles.flowIndex}>{String(index + 1).padStart(2, "0")}</span>
              <Icon aria-hidden="true" />
              <strong>{label}</strong>
              <p>{detail}</p>
            </li>
          ))}
        </ol>
      </section>

      <section className={`${styles.boundaryGrid} ${styles.overviewBoundaryGrid}`} aria-label="Authority boundaries">
        <article><LockKeyhole aria-hidden="true" /><div><strong>Human gate</strong><p>Magistrate CLEAR can present a warrant; only a human can approve it.</p></div></article>
        <article><Boxes aria-hidden="true" /><div><strong>Isolated runner</strong><p>Candidate code cannot see control-plane secrets or declare its own success.</p></div></article>
        <article><ShieldCheck aria-hidden="true" /><div><strong>Published projection</strong><p>Judges browse sanitized, explicitly published case snapshots only.</p></div></article>
      </section>
    </main>
  );
}
