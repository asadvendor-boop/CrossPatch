import type { Metadata } from "next";

import { CasesPage } from "@/components/pages/CasesPage";

export const metadata: Metadata = {
  title: "Verified published cases",
  description: "Browse credential-free, sanitized, immutable CrossPatch case projections backed by revisioned SHA-256 publication manifests.",
};

export default function Page() {
  return <CasesPage />;
}
