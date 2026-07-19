import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { metadata } from "@/app/layout";

const webRoot = path.resolve(import.meta.dirname, "../..");
const read = (relative: string) => readFileSync(path.join(webRoot, relative), "utf8");

describe("CrossPatch brand assets", () => {
  it("ships the exact operator-approved latest1 mark crop", () => {
    const asset = path.join(webRoot, "public/crosspatch-mark.png");
    expect(existsSync(asset)).toBe(true);
    if (!existsSync(asset)) return;

    const png = readFileSync(asset);
    expect([...png.subarray(0, 8)]).toEqual([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    expect(png.readUInt32BE(16)).toBe(261);
    expect(png.readUInt32BE(20)).toBe(261);
    expect(createHash("sha256").update(png).digest("hex")).toBe(
      "2d00e5bb22eb6eba2690f6f4e2226774593e940bf27a335766604d3ff2d0e505",
    );
    expect(existsSync(path.join(webRoot, "public/crosspatch-mark.jpg"))).toBe(false);
    expect(existsSync(path.join(webRoot, "public/crosspatch-mark.svg"))).toBe(false);
  });

  it("renders a decorative canonical mark with stable intrinsic dimensions", () => {
    const component = path.join(webRoot, "components/brand/CrossPatchMark.tsx");
    expect(existsSync(component)).toBe(true);
    if (!existsSync(component)) return;

    const source = readFileSync(component, "utf8");
    expect(source).toContain('src="/crosspatch-mark.png"');
    expect(source).toContain('alt=""');
    expect(source).toContain('aria-hidden="true"');
    expect(source).toContain("height={size}");
    expect(source).toContain("width={size}");
  });

  it("replaces every visible CP placeholder and keeps the real wordmark", () => {
    const surfaces = [
      "components/shell/AppShell.tsx",
      "app/error.tsx",
      "app/global-error.tsx",
    ];
    for (const surface of surfaces) expect(read(surface)).not.toMatch(/>\s*CP\s*</);

    const shell = read("components/shell/AppShell.tsx");
    expect(shell).toContain("<CrossPatchMark");
    expect(shell).toContain("<strong>CrossPatch</strong>");
    expect(shell).toContain("<small>Failure-first SRE</small>");
  });

  it("uses the canonical mark for browser icon metadata", () => {
    expect(metadata.icons).toMatchObject({
      icon: [{ url: "/crosspatch-mark.png", type: "image/png" }],
      shortcut: "/crosspatch-mark.png",
    });
  });

  it("uses the exact canonical asset in the social source", () => {
    const share = read("public/crosspatch-share.svg");
    expect(share).toContain('data-crosspatch-mark="operator-latest1-v1"');
    expect(share).toContain('href="crosspatch-mark.png"');
    expect(share).toContain('x="40" y="42" width="76" height="76"');
    expect(share).not.toMatch(/>\s*CP\s*</);
  });

  it("provides the pinned brand renderer without adding a dependency", () => {
    const pkg = JSON.parse(read("package.json")) as { scripts: Record<string, string> };
    expect(pkg.scripts["brand:render"]).toBe("node scripts/render-brand-assets.mjs");
    expect(read("scripts/render-brand-assets.mjs")).toContain('from "@playwright/test"');
  });
});
