import type { Metadata } from "next";

import { ApprovalsPage } from "@/components/pages/ApprovalsPage";

export const metadata: Metadata = {
  title: "Incident warrant approval",
  description: "Review one incident's exact canonical warrant, bound patch, allowed paths, test plan, and expiry before a human decision.",
};

export default function Page() {
  return <ApprovalsPage />;
}
