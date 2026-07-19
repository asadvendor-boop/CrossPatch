import Link from "next/link";
import {
  ArrowRight,
  CheckCircle2,
  FileSearch,
  GitPullRequest,
  ShieldCheck,
  UserCheck,
} from "lucide-react";

import { SeatStrip } from "./PagePrimitives";
import { FeaturedCaseLink } from "./FeaturedCaseLink";
import styles from "./AppPages.module.css";

const PROOF_STEPS = [
  { label: "Evidence", detail: "Sanitized and attributable", icon: FileSearch },
  { label: "Challenge", detail: "Rival hypotheses tested", icon: GitPullRequest },
  { label: "Approval", detail: "Exact warrant reviewed", icon: UserCheck },
  { label: "Verified", detail: "Trusted receipt retained", icon: CheckCircle2 },
] as const;

export function PublicLandingPage() {
  return (
    <main id="main-content" className={`${styles.page} ${styles.landingPage}`} data-page="landing" tabIndex={-1}>
      <section className={styles.landingHero} aria-labelledby="landing-title">
        <div className={styles.landingCopy}>
          <span className={styles.heroKicker}><ShieldCheck aria-hidden="true" /> Live tampered-evidence case</span>
          <h1 id="landing-title">The evidence was tampered with. The release gate held.</h1>
          <p className={styles.heroSummary}>
            An instruction hidden inside a signed incident log was denied authority while the
            legitimate repair still moved through CLEAR → human approval → VERIFIED.
            <span>CrossPatch is a due-process layer for agent-proposed changes.</span>
          </p>
          <p className={styles.audienceLine}>
            For SRE and platform teams who won&apos;t trust autonomous agents in production.
          </p>
          <div className={styles.heroActions}>
            <FeaturedCaseLink />
            <Link className={styles.secondaryLink} href="/cases">Browse all verified cases</Link>
            <Link className={styles.secondaryLink} href="/overview">Enter the control plane</Link>
            <Link className={styles.secondaryLink} href="/open-incident">Open a real incident</Link>
            <Link className={styles.secondaryLink} href="/open-incident#live-trial-entry">
              Run a live incident yourself
            </Link>
          </div>
          <p className={styles.liveTrialBoundary}>
            Fresh model output runs under one global spend cap; you approve the warrant before a
            private, sandbox-confined trial executes. Trials never publish.
          </p>
          <ul className={styles.assuranceList} aria-label="CrossPatch assurances">
            <li><CheckCircle2 aria-hidden="true" />No seeded evidence</li>
            <li><CheckCircle2 aria-hidden="true" />Human-gated execution</li>
            <li><CheckCircle2 aria-hidden="true" />Append-only proof</li>
          </ul>
        </div>

        <aside className={styles.proofCanvas} aria-label="CrossPatch proof path">
          <header>
            <span>Live repair path</span>
            <strong>Evidence → challenge → approval → verified repair</strong>
          </header>
          <ol className={styles.proofPath}>
            {PROOF_STEPS.map(({ label, detail, icon: Icon }, index) => (
              <li key={label}>
                <span className={styles.proofStepIcon} aria-hidden="true"><Icon /></span>
                <div><strong>{label}</strong><span>{detail}</span></div>
                {index < PROOF_STEPS.length - 1 ? <ArrowRight className={styles.proofArrow} aria-hidden="true" /> : null}
              </li>
            ))}
          </ol>
          <div className={styles.landingCast}>
            <div><span>Five exact seats</span><strong>One bounded chain of review</strong></div>
            <SeatStrip landing />
          </div>
        </aside>
      </section>

      <section className={styles.landingFooter} aria-label="Product boundary">
        <div><strong>Failure first</strong><span>The baseline stays visible after repair.</span></div>
        <div><strong>Approval explicit</strong><span>No model crosses the human gate.</span></div>
        <div><strong>Proof durable</strong><span>Hashes, tests, and receipts remain inspectable.</span></div>
      </section>
    </main>
  );
}
