"use client";

import Link from "next/link";

import { CrossPatchMark } from "@/components/brand/CrossPatchMark";

import styles from "./error-boundary.module.css";

type ErrorBoundaryProps = {
  error: Error & { digest?: string };
  reset: () => void;
};

export default function ErrorPage({ reset }: ErrorBoundaryProps) {
  return (
    <main id="main-content" className={styles.page} data-page="route-error" tabIndex={-1}>
      <section className={styles.record} aria-labelledby="route-error-title">
        <aside className={styles.index} aria-hidden="true">
          <CrossPatchMark className={styles.brand} size={52} />
          <p className={styles.indexCode}>Render boundary / 500</p>
          <p className={styles.indexState}>Recorded state preserved</p>
        </aside>
        <div className={styles.content}>
          <p className={styles.eyebrow}>Route boundary / failed closed</p>
          <h1 id="route-error-title">The incident view could not be rendered.</h1>
          <p className={styles.summary}>
            CrossPatch withheld the failed view instead of inventing incident state. Retry this
            recorded route, or recover through published evidence.
          </p>
          <nav className={styles.actions} aria-label="Error recovery">
            <button className={styles.primary} type="button" onClick={reset}>Retry this view</button>
            <Link className={styles.secondary} href="/cases">Browse verified cases</Link>
            <Link className={styles.tertiary} href="/">Return home</Link>
          </nav>
        </div>
      </section>
    </main>
  );
}
