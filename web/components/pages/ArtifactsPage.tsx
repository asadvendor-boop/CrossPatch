"use client";

import { FormEvent, useState } from "react";
import { Download, FileArchive, Fingerprint, RefreshCw } from "lucide-react";

import { InspectorPanel } from "@/components/InspectorPanel";
import { StatusBadge } from "@/components/StatusBadge";
import { ZeroCredentialGuide } from "@/components/exhibits/ZeroCredentialGuide";
import { downloadCaseFile } from "@/lib/api";

import { PageIntro } from "./PagePrimitives";
import { useIncidentSnapshot } from "./useIncidentSnapshot";
import pageStyles from "./AppPages.module.css";
import styles from "./ArtifactsPage.module.css";

export function ArtifactsPage() {
  const {
    error,
    incidentId,
    incidentInput,
    loadIncident,
    setIncidentInput,
    snapshot,
    state,
  } = useIncidentSnapshot();
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const [downloaded, setDownloaded] = useState(false);

  function selectIncident(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    if (!incidentInput.trim()) return;
    setDownloaded(false);
    setExportError(null);
    void loadIncident(incidentInput);
  }

  async function exportCase(): Promise<void> {
    if (!snapshot || snapshot.incident.state !== "VERIFIED") return;
    setExporting(true);
    setDownloaded(false);
    setExportError(null);
    try {
      await downloadCaseFile(snapshot.incident.id);
      setDownloaded(true);
    } catch (caught) {
      setExportError(caught instanceof Error ? caught.message : "Case export failed");
    } finally {
      setExporting(false);
    }
  }

  const exportReady = snapshot?.incident.state === "VERIFIED";
  const artifactCount = snapshot
    ? snapshot.artifacts.evidence.length
      + snapshot.artifacts.tests.length
      + snapshot.specialistSummaries.length
      + snapshot.warrants.length
      + (snapshot.artifacts.diff ? 1 : 0)
    : 0;

  return (
    <main
      id="main-content"
      className={`${pageStyles.page} ${styles.page}`}
      data-page="artifacts"
      tabIndex={-1}
    >
      <PageIntro
        eyebrow="Verifiable output"
        title="Artifacts & exports"
        summary="Inspect one incident's sanitized evidence, reviewed diff, deterministic tests, specialist summaries, and warrant history. Signed export remains gated by VERIFIED state."
        icon={FileArchive}
      />

      <section className={styles.scopeCard} aria-labelledby="artifact-scope-title">
        <div className={styles.scopeCopy}>
          <span className={styles.scopeIcon} aria-hidden="true"><Fingerprint /></span>
          <div>
            <h2 id="artifact-scope-title">Select one incident</h2>
            <p>Enter or replace the incident ID remembered only for this browser tab.</p>
          </div>
        </div>
        <form className={styles.scopeForm} aria-label="Select incident artifacts" onSubmit={selectIncident}>
          <label>
            <span>Incident ID</span>
            <input
              value={incidentInput}
              autoComplete="off"
              onChange={(event) => setIncidentInput(event.target.value)}
            />
          </label>
          <button type="submit" disabled={!incidentInput.trim() || state === "loading"}>
            <RefreshCw aria-hidden="true" />
            {state === "loading" ? "Loading artifacts…" : "Load incident artifacts"}
          </button>
        </form>
      </section>

      {state === "restoring" ? (
        <p className={styles.stateCard} role="status">Restoring incident selection from this tab…</p>
      ) : null}
      {state === "unselected" ? (
        <ZeroCredentialGuide surface="artifacts" />
      ) : null}
      {state === "loading" ? (
        <p className={styles.stateCard} role="status" aria-live="polite">
          Loading the published incident projection and artifact references…
        </p>
      ) : null}
      {state === "error" ? (
        <p className={`${styles.stateCard} ${styles.error}`} role="alert">
          {error ?? "Incident projection unavailable"}
        </p>
      ) : null}

      {state === "ready" && snapshot ? (
        <section className={styles.workspace} aria-labelledby="artifact-incident-title">
          <header className={styles.workspaceHeader}>
            <div>
              <span>{incidentId}</span>
              <h2 id="artifact-incident-title">{snapshot.incident.title}</h2>
              <p>{artifactCount} recorded proof item{artifactCount === 1 ? "" : "s"} in this projection.</p>
            </div>
            <div className={styles.exportControls}>
              <StatusBadge state={snapshot.incident.state} />
              <button
                type="button"
                disabled={!exportReady || exporting}
                onClick={exportCase}
              >
                <Download aria-hidden="true" />
                {exporting ? "Preparing case file…" : "Export signed case file"}
              </button>
            </div>
          </header>

          {!exportReady ? (
            <p className={styles.exportState} role="status">
              Export unlocks only after trusted execution reaches VERIFIED.
            </p>
          ) : null}
          {artifactCount === 0 ? (
            <p className={styles.exportState} role="status">
              No incident artifacts have been published for this incident yet.
            </p>
          ) : null}
          {downloaded ? (
            <p className={styles.downloadState} role="status">
              Download started. Verify the ZIP offline before relying on it.
            </p>
          ) : null}
          {exportError ? <p className={styles.error} role="alert">{exportError}</p> : null}

          <div className={styles.inspectorFrame}>
            <InspectorPanel
              artifacts={{
                ...snapshot.artifacts,
                warrant: snapshot.artifacts.warrant ?? snapshot.pendingWarrant,
              }}
              summaries={snapshot.specialistSummaries}
              warrants={snapshot.warrants}
            />
          </div>

          <aside className={styles.verifyNote} aria-labelledby="offline-verification-title">
            <Fingerprint aria-hidden="true" />
            <div>
              <h2 id="offline-verification-title">Verify the archive outside the browser</h2>
              <p>
                Use <code>crosspatch.export.verify_export</code> with the key for the archive&apos;s
                recorded lineage. Pin the listed fingerprint; download success is not
                cryptographic verification.
              </p>
              <nav className={styles.keyLinks} aria-label="Export verification keys">
                <a href="/verification/production-export-public-key.json">
                  Production export key
                </a>
                <a href="/verification/sealed-cohort-export-public-key.json">
                  Sealed cohort key
                </a>
                <a href="/verification/export-public-keys.json">
                  Key provenance manifest
                </a>
              </nav>
            </div>
          </aside>
        </section>
      ) : null}
    </main>
  );
}
