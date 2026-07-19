import { Scale } from "lucide-react";

import { PUBLIC_DOCTRINE } from "@/lib/doctrine";

import { PageIntro } from "./PagePrimitives";
import pageStyles from "./AppPages.module.css";
import styles from "./DoctrinePage.module.css";

export function DoctrinePage() {
  return (
    <main
      id="main-content"
      className={`${pageStyles.page} ${styles.page}`}
      data-page="doctrine"
      tabIndex={-1}
    >
      <PageIntro
        eyebrow="Falsifiable guarantees"
        title="Due process for AI agents"
        summary="Six product claims, each tied to the module that enforces it and the machine-generated release artifact that tested it."
        icon={Scale}
      />

      <p className={styles.personaDisclosure}>
        The five personas are AI agents powered by GPT-5.6; portraits generated with ChatGPT
        Images; any resemblance to real persons is coincidental.
      </p>

      <section className={styles.statement} aria-label="Doctrine evidence boundary">
        <p>
          This is not a feature checklist. A guarantee appears here only when the checked-in
          registry resolves to one PASS claim in the generated claim map. Missing or malformed
          evidence fails the build-time join instead of leaving an unsupported row on the page.
        </p>
        <aside>
          <strong>Public evidence projection</strong>
          <span>Commands and internal provenance are deliberately omitted. Claim IDs, paths, hashes, status, and generators remain inspectable.</span>
        </aside>
      </section>

      <section className={styles.tableFrame} aria-label="Doctrine table frame">
        <table className={styles.table} aria-label="CrossPatch due-process guarantees">
          <thead>
            <tr>
              <th scope="col">Guarantee</th>
              <th scope="col">Enforcing module</th>
              <th scope="col">Generated claim evidence</th>
            </tr>
          </thead>
          <tbody>
            {PUBLIC_DOCTRINE.map((row) => (
              <tr key={row.id}>
                <th className={styles.guarantee} scope="row" aria-label={row.guarantee}>
                  <strong>{row.guarantee}</strong>
                  <span>{row.detail}</span>
                </th>
                <td className={styles.module}><code>{row.enforcingModule}</code></td>
                <td>
                  <div className={styles.evidence}>
                    <div className={styles.claimLine}>
                      <strong>{row.claimId}</strong>
                      <span className={styles.pass}>{row.artifactStatus}</span>
                    </div>
                    <dl>
                      <div><dt>Artifact</dt><dd><code>{row.artifactPath}</code></dd></div>
                      <div><dt>Artifact SHA-256</dt><dd><code>{row.artifactSha256}</code></dd></div>
                      <div><dt>Generator</dt><dd><code>{row.generator}</code></dd></div>
                    </dl>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </main>
  );
}
