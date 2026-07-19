import type { Metadata } from "next";
import "@fontsource/ibm-plex-sans/latin-400.css";
import "@fontsource/ibm-plex-sans/latin-500.css";
import "@fontsource/ibm-plex-sans/latin-600.css";
import "@fontsource/ibm-plex-sans/latin-700.css";
import "@fontsource/ibm-plex-mono/latin-500.css";
import "@fontsource/ibm-plex-mono/latin-600.css";
import "@fontsource/sora/latin-600.css";
import "@fontsource/sora/latin-700.css";
import "@fontsource/sora/latin-800.css";

import { AppShell } from "@/components/shell/AppShell";

import "./globals.css";

export const metadata: Metadata = {
  metadataBase: new URL(process.env.CROSSPATCH_PUBLIC_URL?.trim() || "https://localhost"),
  title: {
    default: "CrossPatch — Failure-first incident repair",
    template: "%s · CrossPatch",
  },
  description: "A failure-first SRE incident room for evidence, adversarial review, minimal repair, and verifiable artifacts.",
  icons: {
    icon: [{ url: "/crosspatch-mark.png", type: "image/png" }],
    shortcut: "/crosspatch-mark.png",
  },
  openGraph: {
    type: "website",
    siteName: "CrossPatch",
    title: "CrossPatch — Failure-first incident repair",
    description: "Watch incident evidence become an adversarially reviewed repair, a human-approved warrant, and a verifiable case file.",
    images: [{
      url: "/crosspatch-share.png",
      width: 1200,
      height: 630,
      alt: "CrossPatch failure-first incident repair proof path",
    }],
  },
  twitter: {
    card: "summary_large_image",
    title: "CrossPatch — Failure-first incident repair",
    description: "Evidence, challenge, human approval, deterministic execution, and verifiable proof in one incident room.",
    images: ["/crosspatch-share.png"],
  },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>
        <a className="skip-link" href="#main-content">Skip to main content</a>
        <div className="ambient-grid" aria-hidden="true" />
        <AppShell>{children}</AppShell>
      </body>
    </html>
  );
}
