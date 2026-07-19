"use client";

import { FormEvent } from "react";
import { Fingerprint, RefreshCw, ShieldCheck } from "lucide-react";

import { ApprovalGate } from "@/components/ApprovalGate";
import { WarrantAnatomy } from "@/components/exhibits/WarrantAnatomy";
import { ZeroCredentialGuide } from "@/components/exhibits/ZeroCredentialGuide";
import { StatusBadge } from "@/components/StatusBadge";
import { approveWarrant, rejectWarrant, requestWarrantRevision } from "@/lib/api";
import { hasApprovalCredentials } from "@/lib/session";

import { PageIntro } from "./PagePrimitives";
import { useIncidentSnapshot } from "./useIncidentSnapshot";
import pageStyles from "./AppPages.module.css";
import styles from "./ApprovalsPage.module.css";

export function ApprovalsPage() {
  const {
    error,
    incidentId,
    incidentInput,
    loadIncident,
    setIncidentInput,
    snapshot,
    state,
  } = useIncidentSnapshot();

  function selectIncident(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    if (!incidentInput.trim()) return;
    void loadIncident(incidentInput);
  }

  function matchingWarrant(id: string) {
    if (!snapshot?.pendingWarrant || snapshot.pendingWarrant.id !== id) {
      throw new Error("No matching pending warrant is available");
    }
    return snapshot.pendingWarrant;
  }

  async function approve(id: string): Promise<void> {
    const warrant = matchingWarrant(id);
    await approveWarrant(id, warrant.warrantHash, snapshot?.viewerRole === "live_trial");
    await loadIncident(incidentId);
  }

  async function reject(id: string, reason: string): Promise<void> {
    const warrant = matchingWarrant(id);
    const liveTrial = snapshot?.viewerRole === "live_trial";
    await rejectWarrant(id, warrant.warrantHash, liveTrial ? reason : undefined, liveTrial);
    await loadIncident(incidentId);
  }

  async function requestRevision(id: string, comment: string): Promise<void> {
    const warrant = matchingWarrant(id);
    if (snapshot?.viewerRole !== "live_trial") {
      throw new Error("Only a live-trial credential can request revision");
    }
    await requestWarrantRevision(id, warrant.warrantHash, comment);
    await loadIncident(incidentId);
  }

  return (
    <main
      id="main-content"
      className={`${pageStyles.page} ${styles.page}`}
      data-page="approvals"
      tabIndex={-1}
    >
      <PageIntro
        eyebrow="Human authority"
        title="Approval review"
        summary="Review one incident's exact pending warrant beside its recorded state. Decisions remain bound to the warrant bytes, incident, and approval credentials in this tab."
        icon={ShieldCheck}
      />

      <section className={styles.scopeCard} aria-labelledby="approval-scope-title">
        <div className={styles.scopeCopy}>
          <span className={styles.scopeIcon} aria-hidden="true"><Fingerprint /></span>
          <div>
            <h2 id="approval-scope-title">Select one incident</h2>
            <p>Enter or replace the incident ID remembered only for this browser tab.</p>
          </div>
        </div>
        <form className={styles.scopeForm} aria-label="Select incident for approval" onSubmit={selectIncident}>
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
            {state === "loading" ? "Loading review…" : "Load approval review"}
          </button>
        </form>
      </section>

      {state === "restoring" ? (
        <p className={styles.stateCard} role="status">Restoring incident selection from this tab…</p>
      ) : null}
      {state === "unselected" ? (
        <ZeroCredentialGuide surface="approvals" />
      ) : null}
      {state === "loading" ? (
        <p className={styles.stateCard} role="status" aria-live="polite">
          Loading the incident state and pending warrant…
        </p>
      ) : null}
      {state === "error" ? (
        <p className={`${styles.stateCard} ${styles.error}`} role="alert">
          {error ?? "Incident projection unavailable"}
        </p>
      ) : null}

      {state === "ready" && snapshot ? (
        <section className={styles.review} data-testid="incident-approval-review" aria-labelledby="review-title">
          <header className={styles.reviewHeader}>
            <div>
              <span>{snapshot.incident.id}</span>
              <h2 id="review-title">{snapshot.incident.title}</h2>
              <p>One incident · one pending warrant · one explicit human decision.</p>
            </div>
            <StatusBadge state={snapshot.incident.state} />
          </header>
          {snapshot.pendingWarrant ? (
            <>
              <ApprovalGate
                warrant={snapshot.pendingWarrant}
                incidentState={snapshot.incident.state}
                approvalCredentialsAvailable={
                  snapshot.viewerRole === "live_trial" || hasApprovalCredentials()
                }
                liveTrial={snapshot.viewerRole === "live_trial"}
                onApprove={approve}
                onReject={reject}
                onRequestRevision={requestRevision}
              />
              <div className={styles.anatomy}>
                <WarrantAnatomy
                  warrant={snapshot.warrants.find(
                    (warrant) => warrant.warrantId === snapshot.pendingWarrant?.id,
                  ) ?? snapshot.warrants.at(-1) ?? null}
                />
              </div>
            </>
          ) : (
            <div className={styles.empty} role="status">
              <strong>No pending warrant for this incident.</strong>
              <p>The page does not infer authority from an earlier or different incident.</p>
            </div>
          )}
        </section>
      ) : null}
    </main>
  );
}
