import { formatPublicEnum } from "@/lib/presentation";
import type { CompetingHypotheses } from "@/lib/case-exhibits";

import styles from "./HypothesisExhibit.module.css";

function EvidenceList({
  items,
}: {
  items: CompetingHypotheses["inspector"]["evidence"];
}) {
  return (
    <ul className={styles.citations} aria-label="Cited evidence">
      {items.map((item) => (
        <li key={item.id}><code>{item.id}</code> · {item.label}</li>
      ))}
    </ul>
  );
}

export function HypothesisExhibit({ exhibit }: { exhibit: CompetingHypotheses | null }) {
  if (!exhibit) return null;
  return (
    <section className={styles.exhibit} aria-label="The hypothesis that died">
      <header className={styles.header}>
        <div>
          <span>Recorded adversarial review</span>
          <h2>The hypothesis that died</h2>
        </div>
        <span className={styles.readOnly}>Read-only derivation</span>
      </header>

      <div className={styles.duel}>
        <article className={styles.card}>
          <span className={styles.cardEyebrow}>Inspector · leading account</span>
          <h3>{formatPublicEnum(exhibit.inspector.mechanism)}</h3>
          <p>Evidence-linked mechanism carried into adversarial review.</p>
          <EvidenceList items={exhibit.inspector.evidence} />
          <ul className={styles.falsifiers} aria-label="Inspector falsifiers">
            {exhibit.inspector.falsifiers.map((falsifier) => <li key={falsifier}>{falsifier}</li>)}
          </ul>
          <div className={styles.source}>
            <span>Run <code>{exhibit.inspector.runId}</code></span>
            <span>Output <code>{exhibit.inspector.outputSha256}</code></span>
          </div>
        </article>

        <article className={`${styles.card} ${styles.eliminated}`}>
          <span className={styles.cardEyebrow}>Prosecutor · supported rival</span>
          <span className={styles.stamp}>Prosecutor rival eliminated</span>
          <h3>{formatPublicEnum(exhibit.prosecutor.rivalMechanism)}</h3>
          <p>The rival was material enough to require recorded counterexamples and a negative control.</p>
          <EvidenceList items={exhibit.prosecutor.evidence} />
          <div className={styles.source}>
            <span>Run <code>{exhibit.prosecutor.runId}</code></span>
            <span>Output <code>{exhibit.prosecutor.outputSha256}</code></span>
          </div>
        </article>
      </div>

      <section className={styles.controls} aria-labelledby="negative-controls-title">
        <div>
          <h3 id="negative-controls-title">Cited negative controls</h3>
          <p>Every reference resolves to a published evidence item or terminal test receipt.</p>
        </div>
        <ul className={styles.controlList}>
          {exhibit.negativeControls.map((control) => (
            <li className={styles.control} key={`${control.kind}:${control.reference}`}>
              <strong><code>{control.reference}</code></strong>
              <span>{control.kind === "test" ? `${control.label} · ${control.state}` : control.label}</span>
              <code>{control.sha256}</code>
            </li>
          ))}
        </ul>
      </section>

      <footer className={styles.verdict}>
        <p>
          The later recorded verdict eliminated the supported rival after these cited controls.
          Event <code>{exhibit.verdict.eventId}</code> · <code>{exhibit.verdict.eventSha256}</code>
        </p>
        <strong>{exhibit.verdict.value}</strong>
      </footer>
    </section>
  );
}
