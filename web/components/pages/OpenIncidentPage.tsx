import { DoorOpen, KeyRound, LockKeyhole, ShieldCheck, Siren } from "lucide-react";

import { IncidentAccessForm } from "@/components/IncidentAccessForm";
import { IncidentOpenForm } from "@/components/IncidentOpenForm";
import { ZeroCredentialGuide } from "@/components/exhibits/ZeroCredentialGuide";

import { PageIntro } from "./PagePrimitives";
import styles from "./AppPages.module.css";

export function OpenIncidentPage() {
  return (
    <main id="main-content" className={styles.page} data-page="open-incident" tabIndex={-1}>
      <PageIntro
        eyebrow="Incident entry / authorized"
        title="Start a real incident or rejoin one."
        summary="Operators can open either bundled scenario. Invited live-trial judges can open webhook-race only."
        icon={Siren}
      />

      <section className={styles.credentialNotice} aria-labelledby="credential-notice-title">
        <KeyRound aria-hidden="true" />
        <div>
          <h2 id="credential-notice-title">Credentials remain in this browser tab</h2>
          <p>Access tokens are kept in session storage, never local storage and never bundled into the web build.</p>
        </div>
        <span>Same-origin requests only</span>
      </section>

      <ZeroCredentialGuide surface="open" />

      <div className={styles.openGrid}>
        <section id="live-trial-entry" className={styles.formCard} aria-labelledby="new-incident-title">
          <header>
            <span className={styles.formIcon} aria-hidden="true"><DoorOpen /></span>
            <div><span>New controlled run</span><h2 id="new-incident-title">Open either bundled scenario</h2></div>
          </header>
          <p className={styles.formLead}>
            <span>Operators can open either bundled scenario.</span>{" "}
            <span>Invited live-trial judges can open webhook-race only.</span>{" "}
            Opening starts real isolated victim data and the five-seat analysis path. It does not approve a repair.
          </p>
          <IncidentOpenForm />
        </section>

        <section className={styles.formCard} aria-labelledby="join-incident-title">
          <header>
            <span className={styles.formIcon} aria-hidden="true"><LockKeyhole /></span>
            <div><span>Existing authorized room</span><h2 id="join-incident-title">Join without opening another run</h2></div>
          </header>
          <p className={styles.formLead}>
            The access token opens the room. CSRF and step-up credentials unlock approval controls only.
          </p>
          <IncidentAccessForm />
        </section>
      </div>

      <aside className={styles.openBoundary} aria-label="Incident entry safeguards">
        <ShieldCheck aria-hidden="true" />
        <div><strong>No synthetic room</strong><span>Evidence and events appear only after the backend publishes them.</span></div>
        <div><strong>No implied approval</strong><span>Operator access never substitutes for exact warrant review.</span></div>
        <div><strong>No production mutation</strong><span>Execution remains inside the disposable victim sandbox.</span></div>
      </aside>
    </main>
  );
}
