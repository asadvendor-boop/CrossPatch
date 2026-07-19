"use client";

import { useState } from "react";

import { storeAccessToken, storeApprovalCredentials, storeIncidentId } from "@/lib/session";

interface IncidentAccessFormProps {
  onOpen?: (href: string) => void;
}

export function IncidentAccessForm({ onOpen }: IncidentAccessFormProps) {
  const [incidentId, setIncidentId] = useState("");
  const [token, setToken] = useState("");
  const [csrfToken, setCsrfToken] = useState("");
  const [stepUpToken, setStepUpToken] = useState("");
  const ready = Boolean(incidentId.trim() && token.trim());

  return (
    <form
      className="incident-access-form"
      onSubmit={(event) => {
        event.preventDefault();
        if (!ready) return;
        storeAccessToken(token);
        storeApprovalCredentials(csrfToken, stepUpToken);
        const normalizedIncidentId = incidentId.trim();
        storeIncidentId(normalizedIncidentId);
        const href = `/incidents/${encodeURIComponent(normalizedIncidentId)}`;
        if (onOpen) onOpen(href);
        else window.location.assign(href);
      }}
    >
      <label>
        <span>Incident ID</span>
        <input
          value={incidentId}
          autoComplete="off"
          onChange={(event) => setIncidentId(event.target.value)}
        />
      </label>
      <label>
        <span>Access token</span>
        <input
          type="password"
          value={token}
          autoComplete="off"
          onChange={(event) => setToken(event.target.value)}
        />
      </label>
      <label>
        <span>CSRF token</span>
        <input
          type="password"
          value={csrfToken}
          autoComplete="off"
          onChange={(event) => setCsrfToken(event.target.value)}
        />
      </label>
      <label>
        <span>Step-up token</span>
        <input
          type="password"
          value={stepUpToken}
          autoComplete="off"
          onChange={(event) => setStepUpToken(event.target.value)}
        />
      </label>
      <p>
        The access token opens the room. CSRF and step-up tokens are required only for approval
        controls. Credentials stay in this browser tab and are never bundled into the web build.
      </p>
      <button className="button button--approve" type="submit" disabled={!ready}>
        Open incident room
      </button>
    </form>
  );
}
