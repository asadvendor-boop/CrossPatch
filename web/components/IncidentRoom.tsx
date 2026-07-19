"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";

import { ApprovalGate } from "./ApprovalGate";
import { InspectorPanel } from "./InspectorPanel";
import { SignalRoom } from "./room/SignalRoom";
import { StatusBadge } from "./StatusBadge";
import {
  approveWarrant,
  decodeTimelineEvent,
  downloadCaseFile,
  getIncidentRoom,
  incidentEventsUrl,
  rejectWarrant,
  requestWarrantRevision,
} from "@/lib/api";
import { mergeTimelineEvents, useIncidentEventStream } from "@/lib/events";
import { usePrefersReducedMotion } from "@/lib/motion";
import { formatSeverity } from "@/lib/presentation";
import { isRecordComplete, projectRoomMotion } from "@/lib/room-motion";
import { buildRoomStory } from "@/lib/room-story";
import { hasApprovalCredentials } from "@/lib/session";
import type {
  IncidentRoomSnapshot,
  PendingWarrant,
  StreamConnectionState,
  TimelineEvent,
} from "@/lib/types";

interface IncidentRoomProps {
  incidentId: string;
}

interface LoadState {
  incidentId: string;
  loading: boolean;
  error: string | null;
}

export function IncidentRoom({ incidentId }: IncidentRoomProps) {
  const [snapshot, setSnapshot] = useState<IncidentRoomSnapshot | null>(null);
  const [loadState, setLoadState] = useState<LoadState>({
    incidentId,
    loading: true,
    error: null,
  });
  const [actionError, setActionError] = useState<string | null>(null);
  const [connection, setConnection] = useState<StreamConnectionState>("connecting");
  const reducedMotion = usePrefersReducedMotion();
  const refreshGeneration = useRef(0);
  const loading = loadState.incidentId !== incidentId || loadState.loading;
  const loadError = loadState.incidentId === incidentId ? loadState.error : null;

  const refreshRoom = useCallback(async (decision?: PendingWarrant) => {
    const generation = ++refreshGeneration.current;
    const fresh = await getIncidentRoom(incidentId);
    if (generation !== refreshGeneration.current) return;
    setSnapshot((current) => {
      const projectedWarrant = fresh.artifacts.warrant;
      const decisionIsNewer = Boolean(
        decision &&
          (!projectedWarrant ||
            (projectedWarrant.id === decision.id &&
              projectedWarrant.approvalState === "pending" &&
              decision.approvalState !== "pending")),
      );
      const pendingWarrant =
        decision &&
        decision.approvalState !== "pending" &&
        fresh.pendingWarrant?.id === decision.id
          ? null
          : fresh.pendingWarrant;
      const terminalProjection = isRecordComplete(fresh.incident.state);
      return {
        ...fresh,
        events: current && !terminalProjection
          ? mergeTimelineEvents(current.events, fresh.events)
          : fresh.events,
        artifacts: {
          ...fresh.artifacts,
          warrant: decisionIsNewer && decision ? decision : projectedWarrant,
        },
        pendingWarrant,
      };
    });
  }, [incidentId]);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    refreshGeneration.current += 1;
    getIncidentRoom(incidentId, controller.signal)
      .then((value) => {
        if (!active) return;
        setSnapshot(value);
        setActionError(null);
        setLoadState({ incidentId, loading: false, error: null });
      })
      .catch((value: unknown) => {
        if (!active || (value instanceof DOMException && value.name === "AbortError")) return;
        setLoadState({
          incidentId,
          loading: false,
          error: value instanceof Error ? value.message : "Incident room unavailable",
        });
      });
    return () => {
      active = false;
      controller.abort();
    };
  }, [incidentId]);

  const terminalRecord = snapshot ? isRecordComplete(snapshot.incident.state) : false;

  const receiveEvent = useCallback((event: TimelineEvent) => {
    if (terminalRecord) return;
    setSnapshot((current) =>
      current ? { ...current, events: mergeTimelineEvents(current.events, [event]) } : current,
    );
    void refreshRoom().catch((value: unknown) => {
      setActionError(
        value instanceof Error ? `Live room refresh failed: ${value.message}` : "Live room refresh failed",
      );
    });
  }, [refreshRoom, terminalRecord]);

  const lastEventId = snapshot?.events.reduce(
    (latest, event) => Math.max(latest, event.sequence),
    0,
  );

  useIncidentEventStream({
    incidentId,
    enabled:
      snapshot?.incident.id === incidentId
      && loadError === null
      && !terminalRecord,
    initialLastEventId: lastEventId ? String(lastEventId) : "",
    onEvent: receiveEvent,
    onState: setConnection,
    decode: decodeTimelineEvent,
    url: incidentEventsUrl(incidentId),
  });

  useEffect(() => {
    if (snapshot?.incident.id !== incidentId || loadError !== null) return;
    const revalidateVisibleRoom = () => {
      if (document.visibilityState !== "visible") return;
      void refreshRoom().catch((value: unknown) => {
        setActionError(
          value instanceof Error
            ? `Room revalidation failed: ${value.message}`
            : "Room revalidation failed",
        );
      });
    };
    const restorePage = () => revalidateVisibleRoom();
    document.addEventListener("visibilitychange", revalidateVisibleRoom);
    window.addEventListener("pageshow", restorePage);
    return () => {
      document.removeEventListener("visibilitychange", revalidateVisibleRoom);
      window.removeEventListener("pageshow", restorePage);
    };
  }, [incidentId, loadError, refreshRoom, snapshot?.incident.id]);

  async function approve(id: string) {
    if (!snapshot?.pendingWarrant || snapshot.pendingWarrant.id !== id) {
      throw new Error("No matching pending warrant is available");
    }
    setActionError(null);
    const decision = await approveWarrant(
      id,
      snapshot.pendingWarrant.warrantHash,
      snapshot.viewerRole === "live_trial",
    );
    setSnapshot((current) =>
      current
        ? {
            ...current,
            artifacts: { ...current.artifacts, warrant: decision },
            pendingWarrant: decision.approvalState === "pending" ? decision : null,
          }
        : current,
    );
    try {
      await refreshRoom(decision);
    } catch (value) {
      setActionError(
        value instanceof Error
          ? `Warrant approved; room refresh failed: ${value.message}`
          : "Warrant approved; room refresh failed",
      );
    }
  }

  async function reject(id: string, reason: string) {
    if (!snapshot?.pendingWarrant || snapshot.pendingWarrant.id !== id) {
      throw new Error("No matching pending warrant is available");
    }
    setActionError(null);
    const decision = await rejectWarrant(
      id,
      snapshot.pendingWarrant.warrantHash,
      snapshot.viewerRole === "live_trial" ? reason : undefined,
      snapshot.viewerRole === "live_trial",
    );
    setSnapshot((current) =>
      current
        ? {
            ...current,
            artifacts: { ...current.artifacts, warrant: decision },
            pendingWarrant: decision.approvalState === "pending" ? decision : null,
          }
        : current,
    );
    try {
      await refreshRoom(decision);
    } catch (value) {
      setActionError(
        value instanceof Error
          ? `Warrant rejected; room refresh failed: ${value.message}`
          : "Warrant rejected; room refresh failed",
      );
    }
  }

  async function requestRevision(id: string, comment: string) {
    if (!snapshot?.pendingWarrant || snapshot.pendingWarrant.id !== id) {
      throw new Error("No matching pending warrant is available");
    }
    if (snapshot.viewerRole !== "live_trial") {
      throw new Error("Only a live-trial credential can request revision");
    }
    setActionError(null);
    await requestWarrantRevision(id, snapshot.pendingWarrant.warrantHash, comment);
    try {
      await refreshRoom();
    } catch (value) {
      setActionError(
        value instanceof Error
          ? `Revision requested; room refresh failed: ${value.message}`
          : "Revision requested; room refresh failed",
      );
    }
  }

  async function exportCaseFile() {
    if (!snapshot) return;
    setActionError(null);
    try {
      await downloadCaseFile(snapshot.incident.id);
    } catch (value) {
      setActionError(value instanceof Error ? value.message : "Case export failed");
    }
  }

  if (loading) {
    return (
      <main id="main-content" className="room-state" tabIndex={-1} aria-busy="true">
        <div className="loading-grid" aria-hidden="true" />
        <p role="status">Loading incident room…</p>
      </main>
    );
  }

  if (loadError || !snapshot) {
    return (
      <main id="main-content" className="room-state room-state--failure" tabIndex={-1}>
        <span className="coordinate-label">INCIDENT ROOM / FAIL CLOSED</span>
        <h1>Incident room unavailable</h1>
        <p role="alert">{loadError ?? "No authorized incident projection was returned."}</p>
        <Link className="button button--secondary" href="/">Return to CrossPatch</Link>
      </main>
    );
  }

  const {
    incident,
    artifacts,
    pendingWarrant,
    specialistSummaries,
    warrants,
  } = snapshot;
  const shortBase = incident.baseSha ? incident.baseSha.slice(0, 12) : "unavailable";
  const exportReady = incident.state === "VERIFIED";
  const story = buildRoomStory(snapshot);
  const motion = projectRoomMotion(snapshot, { reducedMotion });

  return (
    <main id="main-content" className="incident-room" tabIndex={-1}>
      <header
        className="incident-header panel-corners"
      >
        <div className="incident-header__identity">
          <div className="incident-header__title">
            <span className="coordinate-label">INCIDENT / {incident.id}</span>
            <h1>{incident.title}</h1>
          </div>
        </div>
        <dl className="incident-header__metrics">
          <div><dt>State</dt><dd><StatusBadge state={incident.state} /></dd></div>
          <div>
            <dt>Severity</dt>
            <dd data-recorded-severity={incident.severity}>{formatSeverity(incident.severity)}</dd>
          </div>
          <div><dt>Service</dt><dd>{incident.service}</dd></div>
          <div><dt>Base SHA</dt><dd title={incident.baseSha}>{shortBase}</dd></div>
        </dl>
        <button
          className="button button--export"
          type="button"
          onClick={exportCaseFile}
          disabled={!exportReady}
          aria-describedby={exportReady ? undefined : "case-export-unavailable"}
        >
          Export case file
        </button>
      </header>

      {!exportReady ? (
        <p id="case-export-unavailable" className="incident-export-status" role="status">
          Export available after verified execution.
        </p>
      ) : null}

      {actionError ? <p className="room-alert" role="alert">{actionError}</p> : null}

      <SignalRoom
        snapshot={snapshot}
        story={story}
        motion={motion}
        connectionState={connection}
        approvalControls={(
          <ApprovalGate
            warrant={pendingWarrant}
            incidentState={incident.state}
            approvalCredentialsAvailable={
              snapshot.viewerRole === "live_trial" || hasApprovalCredentials()
            }
            liveTrial={snapshot.viewerRole === "live_trial"}
            onApprove={approve}
            onReject={reject}
            onRequestRevision={requestRevision}
          />
        )}
        artifactInspector={(
          <InspectorPanel
            artifacts={{ ...artifacts, warrant: artifacts.warrant ?? pendingWarrant }}
            summaries={specialistSummaries}
            warrants={warrants}
          />
        )}
      />

      <footer className="incident-footer">
        <span>
          {snapshot.viewerRole === "live_trial"
            ? "Private live trial — never enters Judge MCP"
            : snapshot.viewerRole === "read_only"
              ? "Published snapshot only"
              : "Authorized incident projection"}
        </span>
        <span>Timeline entries remain visible after retries</span>
        <time dateTime={incident.updatedAt}>
          Updated {incident.updatedAt ? new Date(incident.updatedAt).toLocaleString() : "—"}
        </time>
      </footer>
    </main>
  );
}
