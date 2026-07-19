"use client";

import Link from "next/link";

import { CrossPatchMark } from "@/components/brand/CrossPatchMark";

import styles from "./error-boundary.module.css";

type GlobalErrorProps = {
  error: Error & { digest?: string };
  reset: () => void;
};

function publicDigest(error: GlobalErrorProps["error"]): string | null {
  const digest = error.digest;
  if (typeof digest !== "string" || !/^[a-zA-Z0-9._:-]{1,128}$/.test(digest)) return null;
  return digest;
}

export function GlobalErrorPanel({ error, reset }: GlobalErrorProps) {
  const digest = publicDigest(error);

  return (
    <main className={styles.page} data-page="global-error">
      <section className={styles.record} aria-labelledby="global-error-title">
        <aside className={styles.index} aria-hidden="true">
          <CrossPatchMark className={styles.brand} size={52} />
          <p className={styles.indexCode}>Application boundary / 500</p>
          <p className={styles.indexState}>No authority inferred</p>
        </aside>
        <div className={styles.content}>
          <p className={styles.eyebrow}>Application boundary / failed closed</p>
          <h1 id="global-error-title">CrossPatch could not load.</h1>
          <p className={styles.summary}>
            The application shell stopped before it could safely render a record. No incident,
            approval, or execution state was inferred from this failure.
          </p>
          <nav className={styles.actions} aria-label="Application recovery">
            <button className={styles.primary} type="button" onClick={reset}>Retry CrossPatch</button>
            <Link className={styles.secondary} href="/cases">Browse verified cases</Link>
            <Link className={styles.tertiary} href="/">Return home</Link>
          </nav>
          {digest ? (
            <p className={styles.reference}>
              <span className={styles.referenceLabel}>Failure reference</span>
              <code>{digest}</code>
            </p>
          ) : null}
        </div>
      </section>
    </main>
  );
}

export default function GlobalError(props: GlobalErrorProps) {
  return (
    <html lang="en" className={styles.document} data-theme="tracepaper">
      <head>
        <title>CrossPatch could not load</title>
        <meta name="viewport" content="width=device-width, initial-scale=1" />
      </head>
      <body className={styles.body} data-theme="tracepaper">
        <GlobalErrorPanel {...props} />
      </body>
    </html>
  );
}
