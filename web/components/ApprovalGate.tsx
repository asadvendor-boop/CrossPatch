"use client";

import { useState } from "react";
import Link from "next/link";

import type { IncidentState, PendingWarrant } from "@/lib/types";

interface ApprovalGateProps {
  warrant: PendingWarrant | null;
  incidentState: IncidentState;
  approvalCredentialsAvailable?: boolean;
  liveTrial?: boolean;
  onApprove?: (id: string) => Promise<void>;
  onReject?: (id: string, reason: string) => Promise<void>;
  onRequestRevision?: (id: string, comment: string) => Promise<void>;
}

const APPROVAL_CREDENTIALS_UNAVAILABLE =
  "Approval credentials are unavailable in this browser tab. Approval stays disabled.";

function approvalUnavailableReason(
  warrant: PendingWarrant | null,
  incidentState: IncidentState,
  approvalCredentialsAvailable: boolean,
): string | null {
  if (!warrant) return "No pending warrant is available. Approval stays disabled.";

  const expiresAt = Date.parse(warrant.expiresAt);
  if (
    warrant.approvalState === "expired" ||
    (Number.isFinite(expiresAt) && expiresAt <= Date.now())
  ) {
    return "This warrant has expired. Approval stays disabled.";
  }
  if (warrant.approvalState !== "pending") {
    return `This warrant is ${warrant.approvalState}. Only a pending warrant can be reviewed.`;
  }
  if (!warrant.canonicalDocument) {
    return "The canonical warrant document is missing. Approval failed closed.";
  }
  if (!/^[0-9a-f]{64}$/.test(warrant.warrantHash)) {
    return "The canonical warrant SHA-256 is malformed. Approval failed closed.";
  }
  if (!Number.isFinite(expiresAt)) {
    return "The warrant expiry is missing or invalid. Approval failed closed.";
  }
  if (incidentState !== "APPROVAL_PENDING") {
    return `Incident state ${incidentState} does not permit approval. A Magistrate CLEAR is required.`;
  }
  if (!approvalCredentialsAvailable) return APPROVAL_CREDENTIALS_UNAVAILABLE;
  return null;
}

export function ApprovalGate(props: ApprovalGateProps) {
  const binding = props.warrant
    ? `${props.warrant.id}:${props.warrant.warrantHash}:${props.warrant.canonicalDocument}:${props.warrant.approvalState}:${props.warrant.expiresAt}`
    : "NO_WARRANT";
  const authorityBinding = `${props.incidentState}:${Boolean(props.approvalCredentialsAvailable)}:${Boolean(props.liveTrial)}`;
  return <ApprovalGateState key={`${binding}:${authorityBinding}`} {...props} />;
}

function ApprovalGateState({
  warrant,
  incidentState,
  approvalCredentialsAvailable = false,
  liveTrial = false,
  onApprove,
  onReject,
  onRequestRevision,
}: ApprovalGateProps) {
  const [confirmed, setConfirmed] = useState(false);
  const [reason, setReason] = useState("");
  const [rejectionReason, setRejectionReason] = useState("");
  const [revisionComment, setRevisionComment] = useState("");
  const [busy, setBusy] = useState<"approve" | "reject" | "revision" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const unavailableReason = approvalUnavailableReason(
    warrant,
    incidentState,
    approvalCredentialsAvailable,
  );
  const actionable = unavailableReason === null;

  async function approve() {
    if (!warrant || !onApprove || !actionable || !confirmed) return;
    setBusy("approve");
    setError(null);
    try {
      await onApprove(warrant.id);
      setConfirmed(false);
    } catch (value) {
      setError(value instanceof Error ? value.message : "Approval failed closed");
    } finally {
      setBusy(null);
    }
  }

  async function reject() {
    if (
      !warrant ||
      !onReject ||
      !actionable ||
      reason.trim() !== "REJECT" ||
      (liveTrial && !rejectionReason.trim())
    ) return;
    setBusy("reject");
    setError(null);
    try {
      await onReject(warrant.id, liveTrial ? rejectionReason.trim() : reason.trim());
      setReason("");
      setRejectionReason("");
    } catch (value) {
      setError(value instanceof Error ? value.message : "Rejection could not be recorded");
    } finally {
      setBusy(null);
    }
  }

  async function requestRevision() {
    if (
      !warrant ||
      !onRequestRevision ||
      !actionable ||
      !confirmed ||
      !revisionComment.trim()
    ) return;
    setBusy("revision");
    setError(null);
    try {
      await onRequestRevision(warrant.id, revisionComment.trim());
      setConfirmed(false);
      setRevisionComment("");
    } catch (value) {
      setError(value instanceof Error ? value.message : "Revision could not be requested");
    } finally {
      setBusy(null);
    }
  }

  return (
    <section className="approval-gate panel-corners" data-testid="approval-gate" aria-labelledby="approval-title">
      <div className="approval-gate__stripe" aria-hidden="true" />
      <div className="approval-gate__heading">
        <span className="coordinate-label">GATE / HUMAN</span>
        <h2 id="approval-title">Human approval</h2>
      </div>
      {!actionable ? (
        <div className="approval-gate__empty-control">
          <p
            className="approval-gate__unavailable"
            data-testid="approval-unavailable-reason"
            role="status"
          >
            {unavailableReason}
            {unavailableReason === APPROVAL_CREDENTIALS_UNAVAILABLE ? (
              <>
                {" "}
                <Link href="/open-incident#join-incident-title">Enter approver credentials</Link>.
              </>
            ) : null}
          </p>
          <button className="button button--approve" type="button" disabled>
            Approve warrant
          </button>
        </div>
      ) : (
        <>
          <dl className="warrant-bindings">
            <div><dt>Warrant</dt><dd>{warrant?.id}</dd></div>
            <div className="warrant-bindings__full"><dt>Canonical SHA-256</dt><dd>{warrant?.warrantHash}</dd></div>
            <div><dt>Patch</dt><dd title={warrant?.patchHash}>{warrant?.patchHash.slice(0, 12)}</dd></div>
            <div><dt>Base</dt><dd title={warrant?.baseSha}>{warrant?.baseSha.slice(0, 12)}</dd></div>
            <div><dt>Expires</dt><dd>{warrant ? new Date(warrant.expiresAt).toLocaleString() : "—"}</dd></div>
          </dl>
          <div className="canonical-warrant">
            <strong>Exact canonical warrant document</strong>
            <p>These are the exact UTF-8 bytes bound to the SHA-256 above.</p>
            <pre
              data-testid="canonical-warrant-document"
              data-warrant-sha256={warrant?.warrantHash}
              role="region"
              aria-label="Exact canonical warrant document"
              tabIndex={0}
            >
              {warrant?.canonicalDocument}
            </pre>
          </div>
          <details className="approval-gate__details">
            <summary>Review bound paths and test plan</summary>
            <div
              className="binding-list"
              role="region"
              aria-label="Bound paths and catalog test plan"
              tabIndex={0}
            >
              <strong>Paths</strong>
              <ul>{warrant?.paths.map((path) => <li key={path}>{path}</li>)}</ul>
              <strong>Catalog tests</strong>
              <ul>{warrant?.commands.map((command) => <li key={command}>{command}</li>)}</ul>
            </div>
          </details>
          <label className="confirmation-control">
            <input
              type="checkbox"
              checked={confirmed}
              onChange={(event) => setConfirmed(event.target.checked)}
            />
            <span>I reviewed the exact canonical warrant, bound patch, paths, and test plan</span>
          </label>
          <div className="approval-gate__actions">
            <button
              className="button button--approve"
              type="button"
              disabled={!confirmed || busy !== null || !onApprove}
              onClick={approve}
            >
              {busy === "approve" ? "Recording…" : "Approve warrant"}
            </button>
            <label className="reject-control">
              <span>Type REJECT to confirm</span>
              <input
                value={reason}
                autoComplete="off"
                spellCheck={false}
                onChange={(event) => setReason(event.target.value)}
              />
            </label>
            {liveTrial ? (
              <label className="reject-control">
                <span>Rejection reason</span>
                <textarea
                  value={rejectionReason}
                  maxLength={2000}
                  onChange={(event) => setRejectionReason(event.target.value)}
                />
              </label>
            ) : null}
            <button
              className="button button--reject"
              type="button"
              disabled={
                reason.trim() !== "REJECT" ||
                (liveTrial && !rejectionReason.trim()) ||
                busy !== null ||
                !onReject
              }
              onClick={reject}
            >
              Reject warrant
            </button>
            {liveTrial ? (
              <div className="revision-control">
                <label>
                  <span>Revision guidance for Counsel</span>
                  <textarea
                    value={revisionComment}
                    maxLength={2000}
                    onChange={(event) => setRevisionComment(event.target.value)}
                  />
                </label>
                <button
                  className="button button--revision"
                  type="button"
                  disabled={
                    !confirmed ||
                    !revisionComment.trim() ||
                    busy !== null ||
                    !onRequestRevision
                  }
                  onClick={requestRevision}
                >
                  {busy === "revision" ? "Requesting…" : "Request revision"}
                </button>
              </div>
            ) : null}
          </div>
        </>
      )}
      {error ? <p className="inline-failure" role="alert">{error}</p> : null}
    </section>
  );
}
