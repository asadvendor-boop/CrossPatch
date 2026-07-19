import type { Metadata } from "next";

import { OverviewPage } from "@/components/pages/OverviewPage";

export const metadata: Metadata = {
  title: "Operational proof overview",
  description: "Understand CrossPatch's five-seat incident workflow, human authority boundary, isolated execution, and sealed verified-run evidence.",
};

export default function Page() {
  return <OverviewPage />;
}
