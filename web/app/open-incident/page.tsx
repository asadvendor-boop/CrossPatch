import type { Metadata } from "next";

import { OpenIncidentPage } from "@/components/pages/OpenIncidentPage";

export const metadata: Metadata = {
  title: "Open or join an incident",
  description: "Open the bundled webhook-race incident or join an authorized CrossPatch room with credentials retained only in this browser tab.",
};

export default function Page() {
  return <OpenIncidentPage />;
}
