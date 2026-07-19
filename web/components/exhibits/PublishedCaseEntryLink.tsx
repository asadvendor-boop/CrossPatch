"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

import { fetchPublishedCases } from "@/lib/api";

interface PublishedCaseEntryLinkProps {
  anchor: string;
  children: string;
  className?: string;
}

export function PublishedCaseEntryLink({
  anchor,
  children,
  className,
}: PublishedCaseEntryLinkProps) {
  const [href, setHref] = useState("/cases");

  useEffect(() => {
    const controller = new AbortController();
    fetchPublishedCases(controller.signal)
      .then((cases) => {
        const incidentId = cases.at(0)?.incidentId;
        if (incidentId) {
          setHref(`/cases/${encodeURIComponent(incidentId)}#${anchor}`);
        }
      })
      .catch(() => {
        // The public index is the only authority for published case IDs. Keep
        // the safe index fallback instead of guessing a detail route.
      });
    return () => controller.abort();
  }, [anchor]);

  return <Link className={className} href={href}>{children}</Link>;
}
