import type { Metadata } from "next";

import { IncidentRoom } from "@/components/IncidentRoom";

export const metadata: Metadata = {
  title: "Live incident room",
  description: "Follow the five CrossPatch seats, recorded incident moments, human approval gate, isolated execution, and trusted verification live.",
};

export default async function IncidentPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <IncidentRoom incidentId={id} />;
}
