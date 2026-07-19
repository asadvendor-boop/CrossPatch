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

import NotFound from "./not-found";
import "./globals.css";

export const metadata: Metadata = {
  title: "Route not found",
  description: "The requested CrossPatch route does not match a published case or an available workspace surface.",
};

export default function GlobalNotFound() {
  return (
    <html lang="en">
      <body>
        <a className="skip-link" href="#main-content">Skip to main content</a>
        <div className="ambient-grid" aria-hidden="true" />
        <AppShell><NotFound /></AppShell>
      </body>
    </html>
  );
}
