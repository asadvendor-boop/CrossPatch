import Link from "next/link";
import { ArrowRight, FileQuestion, ShieldCheck } from "lucide-react";

import styles from "./not-found.module.css";

export default function NotFound() {
  return (
    <main id="main-content" className={styles.page} data-page="not-found" tabIndex={-1}>
      <section className={styles.record} aria-labelledby="not-found-title">
        <div className={styles.index} aria-hidden="true">
          <span>HTTP</span>
          <strong>404</strong>
          <small>No record</small>
        </div>
        <div className={styles.content}>
          <span className={styles.icon} aria-hidden="true"><FileQuestion /></span>
          <p className={styles.eyebrow}>Route lookup / failed closed</p>
          <h1 id="not-found-title">This route has no record.</h1>
          <p className={styles.summary}>
            CrossPatch could not match this address to a published case or workspace surface.
            No incident, approval, or artifact was inferred from the missing route.
          </p>
          <div className={styles.actions}>
            <Link className={styles.primary} href="/cases">
              Browse verified cases <ArrowRight aria-hidden="true" />
            </Link>
            <Link className={styles.secondary} href="/overview">Return to overview</Link>
          </div>
          <aside className={styles.boundary}>
            <ShieldCheck aria-hidden="true" />
            <p><strong>Publication stays explicit.</strong> An unknown identifier never becomes a case.</p>
          </aside>
        </div>
      </section>
    </main>
  );
}
