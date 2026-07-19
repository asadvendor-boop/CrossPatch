import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

describe("incident room accessibility styles", () => {
  it("wraps the complete tier rationale instead of clipping it", () => {
    const css = readFileSync(resolve(process.cwd(), "app/globals.css"), "utf8");
    const rule = css.match(/\.seat-card__rationale\s*\{([^}]*)\}/)?.[1] ?? "";

    expect(rule).toContain("white-space: normal");
    expect(rule).toContain("overflow-wrap: anywhere");
    expect(rule).not.toContain("overflow: hidden");
    expect(rule).not.toContain("text-overflow: ellipsis");
  });

  it("skins shared room, form, empty, and error states through semantic theme tokens", () => {
    const css = readFileSync(resolve(process.cwd(), "app/globals.css"), "utf8");

    for (const token of [
      "--accent:",
      "--warning:",
      "--warning-dark:",
      "--active-dark:",
      "--radius-card:",
      "--radius-control:",
      "--panel-shadow:",
      "--body-background:",
      "--ambient-background:",
    ]) {
      expect(css).toContain(token);
    }

    expect(css).toMatch(/body\s*\{[\s\S]*?background:\s*var\(--body-background\)/);
    expect(css).toMatch(/\.ambient-grid\s*\{[\s\S]*?display:\s*none/);
    expect(css).not.toMatch(/(?:linear|radial|conic|repeating-linear)-gradient\(/i);
    expect(css).toMatch(/\.incident-header\s*\{[\s\S]*?border-radius:\s*var\(--radius-card\)/);
    expect(css).toMatch(/\.room-state\s*\{[\s\S]*?border-radius:\s*var\(--radius-panel\)/);
    expect(css).not.toContain("var(--amber");
    expect(css).not.toContain("#ffc247");
  });

  it("does not override the locked 72 by 90 persona card dimensions on app pages", () => {
    const css = readFileSync(resolve(process.cwd(), "components/pages/AppPages.module.css"), "utf8");
    const landingPortrait = css.match(/\.landingSeats\s+:global\(\.persona-portrait\)\s*\{([^}]*)\}/)?.[1] ?? "";
    const overviewPortrait = css.match(/\.seatStrip\s+:global\(\.persona-portrait\)\s*\{([^}]*)\}/)?.[1] ?? "";

    for (const rule of [landingPortrait, overviewPortrait]) {
      expect(rule).not.toMatch(/width:\s*100%\s*!important/);
      expect(rule).not.toMatch(/height:\s*auto\s*!important/);
      expect(rule).not.toContain("aspect-ratio");
    }
  });

  it("inverts machine-exact evidence, diffs, tests, and warrant bindings onto dark anchors", () => {
    const css = readFileSync(resolve(process.cwd(), "app/globals.css"), "utf8");
    const exactOutput = css.match(/\.evidence-content,\s*\.diff-view\s*\{([^}]*)\}/)?.[1] ?? "";
    const testOutput = [...css.matchAll(/\.test-result\s*\{([^}]*)\}/g)]
      .map((match) => match[1])
      .find((rule) => rule.includes("background: var(--anchor-background)")) ?? "";
    const warrantBindings = css.match(/\.proof-metadata--bindings\s*\{([^}]*)\}/)?.[1] ?? "";

    for (const rule of [exactOutput, testOutput]) {
      expect(rule).toContain("color: var(--anchor-text)");
      expect(rule).toContain("background: var(--anchor-background)");
      expect(rule).toContain("border-color: var(--anchor-line)");
    }
    expect(warrantBindings).toContain("background: var(--anchor-line)");
    expect(css).toMatch(
      /\.proof-metadata--bindings\s*>\s*div\s*\{[^}]*background:\s*var\(--anchor-surface\)/,
    );
  });

  it("stacks the overview proof stamp below readable hero copy on narrow screens", () => {
    const css = readFileSync(resolve(process.cwd(), "components/pages/AppPages.module.css"), "utf8");
    const narrow = css.match(/@media\s*\(max-width:\s*780px\)\s*\{([\s\S]*?)\n\}/)?.[1] ?? "";

    expect(narrow).toMatch(/\.overviewHero\s*\{[^}]*grid-template-columns:\s*1fr/);
    expect(narrow).toMatch(/\.cohortStamp\s*\{[^}]*width:\s*100%/);
  });

  it("keeps the complete landing composition in a desktop frame without clipping overflow", () => {
    const css = readFileSync(resolve(process.cwd(), "components/pages/AppPages.module.css"), "utf8");
    const shellCss = readFileSync(resolve(process.cwd(), "components/shell/AppShell.module.css"), "utf8");
    const landingPage = css.match(/\.landingPage\s*\{([^}]*)\}/)?.[1] ?? "";
    const landingHero = css.match(/\.landingHero\s*\{([^}]*)\}/)?.[1] ?? "";
    const heroSummary = css.match(/\.heroSummary\s*\{([^}]*)\}/)?.[1] ?? "";
    const compactDesktop = css.match(
      /@media\s*\(min-width:\s*1181px\)\s*and\s*\(max-height:\s*900px\)\s*\{([\s\S]*?)\n\}/,
    )?.[1] ?? "";
    const shortDesktop = css.match(
      /@media\s*\(min-width:\s*1181px\)\s*and\s*\(max-height:\s*800px\)\s*\{([\s\S]*?)\n\}/,
    )?.[1] ?? "";
    const publicHeader = shellCss.match(/\.publicHeader\s*\{([^}]*)\}/)?.[1] ?? "";
    const publicBrandMark = shellCss.match(/\.publicHeader \.brandMark\s*\{([^}]*)\}/)?.[1] ?? "";

    expect(landingPage).toContain("align-content: start");
    expect(landingPage).toContain("min-height: calc(100svh - 67px)");
    expect(landingPage).toContain(
      "padding-inline: clamp(28px, 5vw, 76px) clamp(20px, 2vw, 36px)",
    );
    expect(landingPage).not.toMatch(/overflow:\s*hidden/);
    expect(landingHero).toContain("min-height: 0");
    expect(landingHero).toContain("align-items: start");
    expect(heroSummary).toContain("max-width: 510px");
    expect(compactDesktop).toMatch(
      /\.landingHero\s*\{[^}]*gap:\s*clamp\(24px,\s*2\.4vw,\s*36px\)/,
    );
    expect(compactDesktop).toMatch(/\.landingCopy h1\s*\{[^}]*margin-bottom:\s*18px/);
    expect(compactDesktop).toMatch(/\.proofCanvas\s*\{[^}]*padding:\s*22px/);
    expect(compactDesktop).not.toMatch(/overflow:\s*hidden/);
    expect(shortDesktop).toMatch(/\.proofPath li\s*\{[^}]*min-height:/);
    expect(shortDesktop).toMatch(/\.proofCanvas\s*\{[^}]*padding:\s*16px/);
    expect(publicHeader).toContain("min-height: 66px");
    expect(publicHeader).toMatch(/padding:\s*6px\s+clamp\(/);
    expect(publicBrandMark).toContain("width: 36px");
    expect(publicBrandMark).toContain("height: 36px");
  });
});
