import { readFileSync } from "node:fs";
import path from "node:path";

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import NotFound from "@/app/not-found";

describe("Tracepaper not-found surface", () => {
  it("returns judges to real proof without inventing a missing record", () => {
    render(<NotFound />);

    expect(screen.getByRole("main")).toHaveAttribute("data-page", "not-found");
    expect(screen.getByRole("heading", { level: 1, name: "This route has no record." }))
      .toBeVisible();
    expect(screen.getByRole("link", { name: "Browse verified cases" }))
      .toHaveAttribute("href", "/cases");
    expect(screen.getByRole("link", { name: "Return to overview" }))
      .toHaveAttribute("href", "/overview");
    expect(screen.getByText(/no incident, approval, or artifact was inferred/i)).toBeVisible();
  });

  it("uses the solid Tracepaper token system", () => {
    const css = readFileSync(path.resolve(process.cwd(), "app/not-found.module.css"), "utf8");

    expect(css).toContain("var(--trace)");
    expect(css).toContain("var(--ink-1)");
    expect(css).toContain("var(--line-strong)");
    expect(css).not.toMatch(/#[0-9a-f]{3,8}\b/i);
    expect(css).not.toMatch(/(?:linear|radial|conic|repeating-linear)-gradient\(/i);
    expect(css).not.toContain("var(--trace-ink)");
    expect(css).toMatch(/\.icon\s*\{[^}]*color:\s*var\(--text\)[^}]*background:\s*var\(--trace\)/s);
    expect(css).toMatch(/\.primary\s*\{[^}]*color:\s*var\(--text\)[^}]*background:\s*var\(--trace\)/s);
  });
});
