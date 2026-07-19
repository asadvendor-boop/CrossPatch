import type { Metadata } from "next";

import { DoctrinePage } from "@/components/pages/DoctrinePage";

export const metadata: Metadata = {
  title: "Due process for AI agents",
  description: "Inspect six CrossPatch guarantees beside their enforcing modules and machine-generated claim evidence.",
};

export default function Page() {
  return <DoctrinePage />;
}
