import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

describe("Playwright production-server contract", () => {
  it("runs the already-built Next production server instead of next dev", () => {
    const config = readFileSync(resolve(process.cwd(), "playwright.config.ts"), "utf8");

    expect(config).toContain("cp -R .next/static .next/standalone/web/.next/static");
    expect(config).toContain("cp -R public .next/standalone/web/public");
    expect(config).toContain("node .next/standalone/web/server.js");
    expect(config).not.toContain("npm run dev");
  });
});
