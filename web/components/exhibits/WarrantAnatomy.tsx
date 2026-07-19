"use client";

import { useEffect, useState } from "react";
import { Fingerprint, RotateCcw, ShieldCheck } from "lucide-react";

import type { WarrantHistoryItem } from "@/lib/types";

import styles from "./WarrantAnatomy.module.css";

async function sha256(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function WarrantAnatomyBody({ warrant }: { warrant: Required<Pick<
  WarrantHistoryItem,
  "publicWarrant" | "publicWarrantBytes" | "publicWarrantSha256" | "nonceSha256"
>> & WarrantHistoryItem }) {
  const anatomy = warrant.publicWarrant;
  const [integrityCopy, setIntegrityCopy] = useState(warrant.publicWarrantBytes);
  const [observedSha256, setObservedSha256] = useState(warrant.publicWarrantSha256);

  useEffect(() => {
    let current = true;
    void sha256(integrityCopy).then((digest) => {
      if (current) setObservedSha256(digest);
    });
    return () => { current = false; };
  }, [integrityCopy]);

  const matches = observedSha256 === warrant.publicWarrantSha256;
  const bindings = [
    ["Full broker-bound SHA-256", warrant.canonicalSha256],
    ["Public anatomy SHA-256", warrant.publicWarrantSha256],
    ["Verdict hash", anatomy.verdictSha256],
    ["Evidence manifest", anatomy.reviewedEvidenceManifestSha256],
    ["Timeline head", anatomy.reviewedTimelineHead],
    ["Base SHA", anatomy.baseSha],
    ["Patch bytes SHA-256", anatomy.patchSha256],
    ["Authority snapshot", anatomy.authoritySnapshotSha256],
    ["Repository manifest", anatomy.repositoryManifestSha256],
    ["Environment digest", anatomy.environmentDigest],
    ["Test plan SHA-256", anatomy.testPlanSha256],
    ["Allowed paths", anatomy.allowedPaths.join("\n")],
    ["Plan IDs", anatomy.planIds.join("\n")],
    ["Runner digest", anatomy.runnerDigest],
    ["Expiry", anatomy.expiresAt],
    ["Approver", anatomy.approverIdentity],
    ["Nonce SHA-256", anatomy.nonceSha256],
  ] as const;

  function perturbOneByte(): void {
    setIntegrityCopy((current) => {
      if (!current) return current;
      const firstByte = current.charCodeAt(0);
      return String.fromCharCode(firstByte ^ 1) + current.slice(1);
    });
  }

  return (
    <section id="warrant-anatomy" className={styles.exhibit} aria-labelledby={`warrant-anatomy-${warrant.warrantId}`}>
      <header className={styles.header}>
        <span className={styles.icon} aria-hidden="true"><Fingerprint /></span>
        <div>
          <span className={styles.eyebrow}>Recorded authority · {warrant.warrantId}</span>
          <h2 id={`warrant-anatomy-${warrant.warrantId}`}>Warrant anatomy</h2>
          <p>This is what the human approved. One changed byte and the broker refuses.</p>
        </div>
        <span className={styles.readOnly}><ShieldCheck aria-hidden="true" />Read-only exhibit</span>
      </header>

      <div className={styles.body}>
        <dl className={styles.bindings} data-testid="warrant-anatomy-bindings">
          {bindings.map(([label, value]) => (
            <div key={label}>
              <dt>{label}</dt>
              <dd><code>{value}</code></dd>
            </div>
          ))}
        </dl>

        <div className={styles.canonical}>
          <div className={styles.codeHeader}>
            <div>
              <span>Nonce-safe public canonical view</span>
              <strong>Exact recorded bytes</strong>
            </div>
            <code>{warrant.publicWarrantSha256}</code>
          </div>
          <pre data-testid="canonical-public-warrant-bytes" tabIndex={0}>
            {warrant.publicWarrantBytes}
          </pre>
          <p>
            The secret-bearing nonce and patch bytes are replaced by one-way hashes. The full
            broker-bound canonical SHA-256 remains annotated separately above.
          </p>
        </div>

        <div className={styles.integrityLab}>
          <div className={styles.labHeader}>
            <div>
              <span>Local integrity demonstration</span>
              <strong>Disposable byte copy</strong>
            </div>
            <span className={matches ? styles.match : styles.mismatch} role="status" aria-live="polite">
              {matches ? "Integrity match" : "Mismatch — broker would refuse"}
            </span>
          </div>
          <pre data-testid="warrant-integrity-copy" tabIndex={0}>{integrityCopy}</pre>
          <dl className={styles.digestComparison}>
            <div><dt>Recorded</dt><dd><code>{warrant.publicWarrantSha256}</code></dd></div>
            <div><dt>Recomputed</dt><dd><code>{observedSha256}</code></dd></div>
          </dl>
          <div className={styles.actions}>
            <button type="button" onClick={perturbOneByte} disabled={!matches}>
              Perturb one byte
            </button>
            <button
              type="button"
              className={styles.secondary}
              onClick={() => setIntegrityCopy(warrant.publicWarrantBytes)}
              disabled={matches}
            >
              <RotateCcw aria-hidden="true" />Reset bytes
            </button>
          </div>
        </div>
      </div>
    </section>
  );
}

export function WarrantAnatomy({ warrant }: { warrant: WarrantHistoryItem | null }) {
  if (
    !warrant?.publicWarrant ||
    !warrant.publicWarrantBytes ||
    !warrant.publicWarrantSha256 ||
    !warrant.nonceSha256
  ) return null;
  return <WarrantAnatomyBody key={warrant.warrantId} warrant={warrant as Required<Pick<
    WarrantHistoryItem,
    "publicWarrant" | "publicWarrantBytes" | "publicWarrantSha256" | "nonceSha256"
  >> & WarrantHistoryItem} />;
}
