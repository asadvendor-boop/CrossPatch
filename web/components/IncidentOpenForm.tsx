"use client";

import { FormEvent, useState } from "react";

import { ApiError, openIncident } from "@/lib/api";
import {
  type EvidenceProfile,
  INSTRUCTION_LOG_TITLE,
  isOperatorScenario,
  OPERATOR_SCENARIOS,
  type OperatorScenario,
} from "@/lib/scenarios";
import { storeAccessToken, storeApprovalCredentials, storeIncidentId } from "@/lib/session";

const DEFAULT_SCENARIO: OperatorScenario = "webhook-race";
const OPERATOR_SCENARIO_IDS = Object.keys(OPERATOR_SCENARIOS) as OperatorScenario[];

interface IncidentOpenFormProps {
  onOpen?: (href: string) => void;
}

export function IncidentOpenForm({ onOpen }: IncidentOpenFormProps) {
  const [scenario, setScenario] = useState<OperatorScenario>(DEFAULT_SCENARIO);
  const [title, setTitle] = useState<string>(OPERATOR_SCENARIOS[DEFAULT_SCENARIO].title);
  const [evidenceProfile, setEvidenceProfile] = useState<EvidenceProfile>("standard");
  const [token, setToken] = useState("");
  const [opening, setOpening] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ready = Boolean(title.trim() && token.trim() && !opening);

  async function handleSubmit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!ready) return;
    setError(null);
    setOpening(true);
    storeAccessToken(token);
    // Approval credentials are incident- and identity-sensitive. Never carry
    // stale values into a newly opened room or infer approval from operator access.
    storeApprovalCredentials("", "");
    try {
      const incident = await openIncident(scenario, title, evidenceProfile);
      storeIncidentId(incident.id);
      const href = `/incidents/${encodeURIComponent(incident.id)}`;
      if (onOpen) onOpen(href);
      else window.location.assign(href);
    } catch (caught) {
      setError(
        caught instanceof ApiError || caught instanceof Error
          ? caught.message
          : "CrossPatch could not open the incident.",
      );
    } finally {
      setOpening(false);
    }
  }

  return (
    <form
      className="incident-open-form"
      aria-label={`Open ${scenario} incident`}
      aria-busy={opening}
      onSubmit={handleSubmit}
    >
      <label>
        <span>Incident scenario</span>
        <select
          className="button"
          value={scenario}
          onChange={(event) => {
            const nextScenario = event.currentTarget.value;
            if (!isOperatorScenario(nextScenario)) return;
            setScenario(nextScenario);
            setEvidenceProfile("standard");
            setTitle(OPERATOR_SCENARIOS[nextScenario].title);
          }}
        >
          {OPERATOR_SCENARIO_IDS.map((scenarioId) => (
            <option key={scenarioId} value={scenarioId}>
              {OPERATOR_SCENARIOS[scenarioId].title}
            </option>
          ))}
        </select>
      </label>
      {scenario === "webhook-race" ? (
        <label>
          <span>Evidence fixture</span>
          <select
            className="button"
            value={evidenceProfile}
            onChange={(event) => {
              const nextProfile = event.currentTarget.value as EvidenceProfile;
              setEvidenceProfile(nextProfile);
              setTitle(
                nextProfile === "instruction-like-log"
                  ? INSTRUCTION_LOG_TITLE
                  : OPERATOR_SCENARIOS[scenario].title,
              );
            }}
          >
            <option value="standard">Standard webhook evidence</option>
            <option value="instruction-like-log">Instruction-like webhook log</option>
          </select>
        </label>
      ) : null}
      <label>
        <span>Incident title</span>
        <input
          value={title}
          maxLength={240}
          autoComplete="off"
          onChange={(event) => setTitle(event.target.value)}
        />
      </label>
      <label>
        <span>
          {scenario === "webhook-race"
            ? "Operator or live-trial bearer token"
            : "Operator bearer token"}
        </span>
        <input
          type="password"
          value={token}
          autoComplete="off"
          onChange={(event) => setToken(event.target.value)}
        />
      </label>
      <p>
        {OPERATOR_SCENARIOS[scenario].description} Explicitly starts the shipped{" "}
        <code>{scenario}</code> reproduction and writes only isolated victim test data. It does not
        approve a patch or alter a candidate worktree. {scenario === "webhook-payload-equivalence"
          ? "Operator access only; private live trials remain fixed to webhook-race."
          : evidenceProfile === "instruction-like-log"
            ? "Operator-only sanitizer demonstration; authentication and candidate capabilities are unchanged."
            : null}
      </p>
      {error ? <p className="incident-form-error" role="alert">{error}</p> : null}
      <button className="button button--approve" type="submit" disabled={!ready}>
        {opening ? "Opening real incident…" : `Open ${scenario} incident`}
      </button>
    </form>
  );
}
