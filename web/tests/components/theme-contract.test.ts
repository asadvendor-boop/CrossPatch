import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

const webRoot = path.resolve(import.meta.dirname, "../..");
const globalCssPath = path.join(webRoot, "app/globals.css");
const layoutPath = path.join(webRoot, "app/layout.tsx");
const shellCssPath = path.join(webRoot, "components/shell/AppShell.module.css");

function applicationCssFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    if (entry.isDirectory() && (entry.name.startsWith(".") || entry.name === "node_modules")) {
      return [];
    }
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory()) return applicationCssFiles(entryPath);
    return entry.isFile() && entry.name.endsWith(".css") ? [entryPath] : [];
  });
}

function rootBlock(css: string): string {
  const match = css.match(/:root\s*\{([\s\S]*?)\n\}/m);
  expect(match, "missing root theme block").not.toBeNull();
  return match?.[1] ?? "";
}

function hexColor(block: string, token: string): string {
  const match = block.match(new RegExp(`--${token}:\\s*(#[0-9a-f]{6})`, "i"));
  expect(match, `missing ${token}`).not.toBeNull();
  return match?.[1] ?? "#000000";
}

function contrastRatio(foreground: string, background: string): number {
  const luminance = (hex: string) => {
    const channels = [1, 3, 5].map((offset) => Number.parseInt(hex.slice(offset, offset + 2), 16) / 255);
    const [red, green, blue] = channels.map((channel) =>
      channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4);
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue;
  };
  const [lighter, darker] = [luminance(foreground), luminance(background)].sort((a, b) => b - a);
  return (lighter + 0.05) / (darker + 0.05);
}

describe("whole-app visual identity contract", () => {
  it("ships one unscoped Tracepaper identity with exact paper, carbon, and chartreuse anchors", () => {
    const root = rootBlock(readFileSync(globalCssPath, "utf8"));

    for (const declaration of [
      "--ink-0: #f3f1ea",
      "--ink-1: #fbfaf5",
      "--sidebar-background: #1b1915",
      "--text: #16130e",
      "--trace: #b8dc32",
      "--brand-mark-background: #b8dc32",
      "--anchor-background: #1b1915",
      "--radius-card: 2px",
      "--radius-panel: 2px",
      "--radius-control: 2px",
    ]) {
      expect(root).toContain(declaration);
    }
    expect(root).not.toContain("--accent-gradient");
  });

  it("keeps normal-size status text at AA contrast in Tracepaper", () => {
    const trace = rootBlock(readFileSync(globalCssPath, "utf8"));

    expect(contrastRatio(hexColor(trace, "active"), hexColor(trace, "active-dark")))
      .toBeGreaterThanOrEqual(4.5);
    expect(contrastRatio(hexColor(trace, "warning"), hexColor(trace, "warning-dark")))
      .toBeGreaterThanOrEqual(4.5);
    expect(contrastRatio(hexColor(trace, "failure"), hexColor(trace, "failure-dark")))
      .toBeGreaterThanOrEqual(4.5);
    expect(contrastRatio(hexColor(trace, "verified"), hexColor(trace, "verified-dark")))
      .toBeGreaterThanOrEqual(4.5);
  });

  it("reserves every chartreuse use for a filled emphasis behind dark text", () => {
    const declarations = applicationCssFiles(webRoot).flatMap((file) => {
      const css = readFileSync(file, "utf8");
      return [...css.matchAll(/([a-z-]+)\s*:[^;{}]*var\(--trace\)[^;{}]*;/gi)].map((match) => ({
        file: path.relative(webRoot, file),
        property: match[1].toLowerCase(),
      }));
    });

    expect(declarations.length).toBeGreaterThan(0);
    expect(declarations).toEqual(
      declarations.filter(({ property }) => property === "background" || property === "background-color"),
    );
  });

  it("has no runtime theme selector or losing identity token surface", () => {
    const layout = readFileSync(layoutPath, "utf8");
    const globals = readFileSync(globalCssPath, "utf8");
    const shell = readFileSync(shellCssPath, "utf8");
    const selectedCss = `${globals}\n${shell}`;

    expect(layout).not.toContain("data-ui-theme");
    expect(layout).not.toContain("themes.css");
    expect(selectedCss).not.toContain("--glass-surface");
    expect(globals).toMatch(/font-size:\s*var\(--body-size\)/);
    expect(globals).toMatch(/line-height:\s*var\(--body-leading\)/);
    expect(selectedCss).not.toMatch(/#060a14|#0a1120|#0e1526|#171512|#211e1a/i);
    expect(selectedCss).not.toMatch(/(?:linear|radial|conic|repeating-linear)-gradient\(/i);
  });

  it("keeps all four status meanings distinct in the selected identity", () => {
    const block = rootBlock(readFileSync(globalCssPath, "utf8"));
    const values = ["active", "warning", "failure", "verified"].map((token) => {
      const match = block.match(new RegExp(`--${token}:\\s*(#[0-9a-f]{6})`, "i"));
      expect(match, `missing ${token}`).not.toBeNull();
      return match?.[1].toLowerCase();
    });
    expect(new Set(values).size).toBe(4);
  });

  it("does not impose a viewport-wide body floor at the 320px accessibility boundary", () => {
    const globals = readFileSync(globalCssPath, "utf8");
    const body = globals.match(/body\s*\{([\s\S]*?)\}/)?.[1] ?? "";

    expect(body).not.toContain("min-width: 320px");
    expect(body).toContain("min-width: 0");
  });
});
