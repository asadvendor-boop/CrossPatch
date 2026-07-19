import type { Metadata } from "next";

import { PublishedCasePage } from "@/components/pages/PublishedCasePage";

export const metadata: Metadata = {
  title: "Published case detail",
  description: "Inspect one explicitly published CrossPatch incident as a credential-free, read-only Signal Room replay with record-derived proof.",
};

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <PublishedCasePage incidentId={id} />;
}
