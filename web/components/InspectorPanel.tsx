"use client";

import { useId, useState } from "react";

import { EmptyState } from "./EmptyState";
import { StatusBadge } from "./StatusBadge";
import { formatPublicEnum } from "@/lib/presentation";
import type {
  IncidentArtifacts,
  SpecialistSummary,
  WarrantHistoryItem,
} from "@/lib/types";

type Tab = "Specialists" | "Evidence" | "Diff" | "Tests" | "Warrants";
const TABS: Tab[] = ["Specialists", "Evidence", "Diff", "Tests", "Warrants"];

interface InspectorPanelProps {
  artifacts: IncidentArtifacts;
  summaries: readonly SpecialistSummary[];
  warrants: readonly WarrantHistoryItem[];
}

function label(value: string): string {
  return formatPublicEnum(value);
}

function ReferenceList({ label: listLabel, values }: { label: string; values: readonly string[] }) {
  return (
    <div className="proof-references">
      <strong>{listLabel}</strong>
      {values.length ? (
        <ul>{values.map((value) => <li key={value}><code>{value}</code></li>)}</ul>
      ) : <span>None recorded</span>}
    </div>
  );
}

function SpecialistSummaryCard({ summary }: { summary: SpecialistSummary }) {
  return (
    <details
      className="proof-disclosure"
      data-testid={`specialist-summary-${summary.runId}`}
      aria-label={`${summary.seat} specialist summary`}
      open
    >
      <summary>
        <span>
          <strong>{summary.seat}</strong>
          <small>{label(summary.phase)}</small>
        </span>
        <span className="proof-disclosure__meta">{summary.model} · {summary.effort}</span>
      </summary>
      <div className="proof-disclosure__body">
        <dl className="proof-metadata">
          <div><dt>Run</dt><dd><code>{summary.runId}</code></dd></div>
          <div><dt>Output SHA</dt><dd><code>{summary.outputSha256}</code></dd></div>
          <div><dt>Semantic SHA</dt><dd><code>{summary.semanticSha256}</code></dd></div>
          <div><dt>Escalation</dt><dd>{summary.escalationCount}/2</dd></div>
        </dl>
        {summary.kind === "INSPECTOR" ? (
          <div className="specialist-facts">
            <p><strong>Mechanism</strong><span>{label(summary.mechanism)}</span></p>
            <ReferenceList label="Evidence IDs" values={summary.evidenceIds} />
            <ReferenceList label="Falsifiers" values={summary.falsifiers} />
          </div>
        ) : null}
        {summary.kind === "PROSECUTOR" ? (
          <div className="specialist-facts">
            <p><strong>Recorded outcome</strong><span>{label(summary.outcome)}</span></p>
            {summary.rivalMechanism ? (
              <p><strong>Rival mechanism</strong><span>{label(summary.rivalMechanism)}</span></p>
            ) : null}
            <ReferenceList label="Counterexample IDs" values={summary.counterexampleIds} />
            <ReferenceList label="Test IDs" values={summary.testIds} />
            <ReferenceList label="Evidence IDs" values={summary.evidenceIds} />
          </div>
        ) : null}
        {summary.kind === "COUNSEL" ? (
          <div className="specialist-facts">
            <p><strong>Patch defense</strong><span>{summary.patchDefense || "No defense recorded"}</span></p>
            <p><strong>Candidate</strong><code>{summary.candidateId ?? "Unavailable"}</code></p>
            <p><strong>Patch SHA-256</strong><code>{summary.patchSha256}</code></p>
            <ReferenceList label="Evidence IDs" values={summary.evidenceIds} />
            <div className="proof-references">
              <strong>Test intentions</strong>
              {summary.testIntentions.length ? (
                <ul>
                  {summary.testIntentions.map((intention) => (
                    <li key={`${intention.catalogId}:${intention.purpose}`}>
                      <code>{intention.catalogId}</code><span>{intention.purpose}</span>
                    </li>
                  ))}
                </ul>
              ) : <span>None recorded</span>}
            </div>
          </div>
        ) : null}
        {summary.sanitizationTags?.length ? (
          <ul className="tag-list" aria-label="Specialist summary sanitizer tags">
            {summary.sanitizationTags.map((tag) => <li key={tag}>{tag}</li>)}
          </ul>
        ) : null}
      </div>
    </details>
  );
}

const BINDING_LABELS: Array<[keyof WarrantHistoryItem["bindingHashes"], string]> = [
  ["patchSha256", "Patch SHA-256"],
  ["baseSha", "Base SHA"],
  ["repositoryManifestSha256", "Repository manifest"],
  ["reviewedEvidenceManifestSha256", "Evidence manifest"],
  ["reviewedTimelineHead", "Timeline head"],
  ["verdictSha256", "Verdict SHA-256"],
  ["authoritySnapshotSha256", "Authority snapshot"],
  ["testPlanSha256", "Test plan"],
  ["runnerDigest", "Runner digest"],
  ["environmentDigest", "Environment digest"],
];

function WarrantHistoryCard({ warrant }: { warrant: WarrantHistoryItem }) {
  const outcome = warrant.executionStatus === "EXECUTED"
    ? "verified"
    : warrant.executionStatus === "TEST_FAILED"
      ? "failed"
      : "warning";
  return (
    <details
      className="proof-disclosure warrant-history-card"
      data-testid={`warrant-history-${warrant.warrantId}`}
      open
    >
      <summary>
        <span><strong>{warrant.warrantId}</strong><small>{label(warrant.executionStatus)}</small></span>
        <StatusBadge state={outcome} label={label(warrant.executionStatus)} />
      </summary>
      <div className="proof-disclosure__body">
        <dl className="proof-metadata">
          <div><dt>Canonical SHA-256</dt><dd><code>{warrant.canonicalSha256}</code></dd></div>
          <div><dt>Approval</dt><dd>{label(warrant.approvalStatus)}</dd></div>
          <div><dt>Approval ID</dt><dd><code>{warrant.approvalId ?? "Not issued"}</code></dd></div>
          <div><dt>Consumption</dt><dd>{label(warrant.consumptionStatus)}</dd></div>
          <div><dt>Execution</dt><dd>{label(warrant.executionStatus)}</dd></div>
          <div><dt>Created</dt><dd>{new Date(warrant.createdAt).toLocaleString()}</dd></div>
          <div><dt>Expires</dt><dd>{new Date(warrant.expiresAt).toLocaleString()}</dd></div>
          <div><dt>Consumed</dt><dd>{warrant.consumedAt ? new Date(warrant.consumedAt).toLocaleString() : "Not consumed"}</dd></div>
        </dl>
        <ReferenceList label="Receipt IDs" values={warrant.receiptIds} />
        <details className="binding-disclosure">
          <summary>Safe binding hashes</summary>
          <dl className="proof-metadata proof-metadata--bindings">
            {BINDING_LABELS.map(([key, bindingLabel]) => (
              <div key={key}><dt>{bindingLabel}</dt><dd><code>{warrant.bindingHashes[key]}</code></dd></div>
            ))}
          </dl>
        </details>
      </div>
    </details>
  );
}

export function InspectorPanel({ artifacts, summaries, warrants }: InspectorPanelProps) {
  const [active, setActive] = useState<Tab>("Evidence");
  const id = useId();

  function panel() {
    if (active === "Specialists") {
      return summaries.length ? (
        <ol className="proof-list" aria-label="Sanitized specialist summaries">
          {summaries.map((summary) => (
            <li key={summary.runId}><SpecialistSummaryCard summary={summary} /></li>
          ))}
        </ol>
      ) : (
        <EmptyState
          compact
          title="No specialist summaries"
          detail="Only sanitized, schema-validated specialist fields will appear here."
        />
      );
    }
    if (active === "Evidence") {
      return artifacts.evidence.length ? (
        <ul className="artifact-list">
          {artifacts.evidence.map((item) => (
            <li key={item.id} className="artifact-card">
              <div className="artifact-card__heading">
                <strong>{item.label}</strong>
                <span>{label(item.classification)}</span>
              </div>
              <span className="coordinate-label" data-recorded-kind={item.kind}>
                {formatPublicEnum(item.kind)}
              </span>
              <code title={item.sha256}>SHA {item.sha256.slice(0, 16)}</code>
              {item.content ? (
                <pre
                  className="evidence-content"
                  role="region"
                  aria-label={`${item.label} sanitized evidence content`}
                  tabIndex={0}
                >
                  {item.content}
                </pre>
              ) : null}
              {item.tags?.length ? (
                <ul className="tag-list" aria-label="Sanitizer tags">
                  {item.tags.map((tag) => <li key={tag}>{tag}</li>)}
                </ul>
              ) : null}
            </li>
          ))}
        </ul>
      ) : <EmptyState compact title="No evidence recorded" detail="Only sanitized evidence will appear here." />;
    }
    if (active === "Diff") {
      return artifacts.diff ? (
        <pre
          className="diff-view"
          role="region"
          aria-label="Candidate patch diff"
          tabIndex={0}
        >
          {artifacts.diff}
        </pre>
      ) : <EmptyState compact title="No candidate diff" detail="A reviewed candidate has not been recorded." />;
    }
    if (active === "Tests") {
      return artifacts.tests.length ? (
        <ul className="test-list">
          {artifacts.tests.map((test) => (
            <li key={test.id} className={`test-result test-result--${test.state}`} data-state={test.state}>
              <div><strong>{test.label}</strong><code>{test.id}</code></div>
              <StatusBadge state={test.state === "passed" ? "verified" : test.state === "failed" ? "failed" : "active"} label={test.state} />
              {test.durationMs ? <span>{test.durationMs} ms</span> : null}
              {test.detail ? <p>{test.detail}</p> : null}
              {test.receiptSha256 ? (
                <p><strong>Receipt SHA-256</strong><code>{test.receiptSha256}</code></p>
              ) : null}
            </li>
          ))}
        </ul>
      ) : <EmptyState compact title="No test results" detail="Deterministic runner results will remain visible here." />;
    }
    return warrants.length ? (
      <ol className="proof-list" aria-label="Persistent warrant history">
        {warrants.map((warrant) => (
          <li key={warrant.warrantId}><WarrantHistoryCard warrant={warrant} /></li>
        ))}
      </ol>
    ) : (
      <EmptyState
        compact
        title="No warrant history"
        detail="Only a valid Magistrate CLEAR can produce a reviewable warrant."
      />
    );
  }

  return (
    <aside className="inspector-panel panel-corners" aria-labelledby={`${id}-title`}>
      <header className="panel-heading">
        <div>
          <span className="coordinate-label">PROOF SURFACE</span>
          <h2 id={`${id}-title`}>Incident artifacts</h2>
        </div>
      </header>
      <div className="inspector-tabs" role="tablist" aria-label="Incident artifacts">
        {TABS.map((tab) => (
          <button
            key={tab}
            id={`${id}-${tab}-tab`}
            type="button"
            role="tab"
            aria-selected={active === tab}
            aria-controls={`${id}-${tab}-panel`}
            tabIndex={active === tab ? 0 : -1}
            onClick={() => setActive(tab)}
            onKeyDown={(event) => {
              if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
              event.preventDefault();
              const offset = event.key === "ArrowRight" ? 1 : -1;
              const next = TABS[(TABS.indexOf(tab) + offset + TABS.length) % TABS.length];
              setActive(next);
              document.getElementById(`${id}-${next}-tab`)?.focus();
            }}
          >
            {tab}
          </button>
        ))}
      </div>
      <div
        className="inspector-panel__content"
        id={`${id}-${active}-panel`}
        role="tabpanel"
        aria-labelledby={`${id}-${active}-tab`}
        tabIndex={0}
      >
        {panel()}
      </div>
    </aside>
  );
}
