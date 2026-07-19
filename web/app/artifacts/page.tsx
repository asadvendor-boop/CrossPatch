import type { Metadata } from "next";

import { ArtifactsPage } from "@/components/pages/ArtifactsPage";

export const metadata: Metadata = {
  title: "Incident artifacts and exports",
  description: "Inspect sanitized evidence, specialist findings, reviewed diffs, deterministic test receipts, warrant history, and verified case exports.",
};

export default function Page() {
  return <ArtifactsPage />;
}
