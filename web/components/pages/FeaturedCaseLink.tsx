"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowRight } from "lucide-react";

import { fetchPublishedCases } from "@/lib/api";
import { pinFeaturedCases } from "@/lib/featured-cases";

import styles from "./AppPages.module.css";

export function FeaturedCaseLink() {
  const [href, setHref] = useState("/cases");

  useEffect(() => {
    const controller = new AbortController();
    fetchPublishedCases(controller.signal)
      .then((cases) => {
        const featured = pinFeaturedCases(cases)[0];
        if (featured) setHref(`/cases/${encodeURIComponent(featured.incidentId)}`);
      })
      .catch(() => {
        // The public index remains the safe destination when no case can be resolved.
      });
    return () => controller.abort();
  }, []);

  return (
    <Link className={styles.primaryLink} href={href}>
      See the remanded repair<ArrowRight aria-hidden="true" />
    </Link>
  );
}
