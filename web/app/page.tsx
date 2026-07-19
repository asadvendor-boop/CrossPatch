import type { Metadata } from "next";

import { PublicLandingPage } from "@/components/pages/PublicLandingPage";

export const metadata: Metadata = {
  title: "Failure-first incident repair",
  description: "See CrossPatch turn untrusted incident evidence into a reviewed repair, explicit human approval, deterministic tests, and durable proof.",
};

export default function HomePage() {
  return <PublicLandingPage />;
}
