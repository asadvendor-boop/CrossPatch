import { createHash } from "node:crypto";
import { readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";

import { expect, test, type Page } from "@playwright/test";

import { installOperatorRoom } from "../fixtures/operator-room";
import { publicCaseEnvelope, publicCaseSummary } from "../fixtures/public-cases";

const CAPTURE_ENABLED = process.env.CROSSPATCH_CAPTURE_GALLERY === "1";
const CAPTURE_METHOD = "playwright.page.screenshot";
const OUTPUT_DIRECTORY = path.resolve(process.cwd(), "..", "output", "phase2-tracepaper-final");
const CAPTURED_AT = new Date().toISOString();

interface CaptureEntry {
  path: string;
  sha256: string;
  width: number;
  height: number;
  viewport: { width: number; height: number };
  primary_landmark_count: number;
  source_url: string;
  capture_method: typeof CAPTURE_METHOD;
  captured_at: string;
}

interface RouteCapture {
  name: string;
  route: string;
}

const ROUTES: readonly RouteCapture[] = [
  { name: "landing", route: "/" },
  { name: "overview", route: "/overview" },
  { name: "open-incident", route: "/open-incident" },
  { name: "cases", route: "/cases" },
  { name: "case-detail", route: "/cases/inc-public-1" },
  { name: "signal-room", route: "/incidents/inc-e2e" },
  { name: "approvals", route: "/approvals" },
  { name: "artifacts", route: "/artifacts" },
  { name: "not-found", route: "/capture-missing" },
] as const;

const VIEWPORTS = [
  { width: 1440, height: 900 },
  { width: 1280, height: 720 },
  { width: 320, height: 900 },
] as const;

function resolveReferenceDirectory(): string {
  const configured = process.env.CROSSPATCH_REFERENCE_DIRECTORY;
  if (!configured) {
    throw new TypeError(
      "CROSSPATCH_REFERENCE_DIRECTORY is required when CROSSPATCH_CAPTURE_GALLERY=1",
    );
  }
  return path.resolve(configured);
}

function pngDimensions(payload: Buffer): { width: number; height: number } {
  const signature = payload.subarray(0, 8).toString("hex");
  if (signature !== "89504e470d0a1a0a" || payload.subarray(12, 16).toString("ascii") !== "IHDR") {
    throw new TypeError("Playwright screenshot did not produce a PNG");
  }
  return { width: payload.readUInt32BE(16), height: payload.readUInt32BE(20) };
}

async function settle(page: Page): Promise<void> {
  await page.locator("#main-content").waitFor({ state: "visible" });
  await page.evaluate(async () => {
    await document.fonts.ready;
    for (const animation of document.getAnimations()) animation.finish();
  });
}

async function capture(
  page: Page,
  filename: string,
  sourceUrl: string,
): Promise<CaptureEntry> {
  const viewport = page.viewportSize();
  if (!viewport) throw new TypeError("Playwright viewport is unavailable");
  const primaryLandmarkCount = await page.locator('[data-capture-landmark="primary"]').count();
  expect(primaryLandmarkCount, filename).toBe(1);
  const absolutePath = path.join(OUTPUT_DIRECTORY, filename);
  const payload = await page.screenshot({
    path: absolutePath,
    type: "png",
    fullPage: false,
    animations: "disabled",
    caret: "hide",
    scale: "css",
  });
  const dimensions = pngDimensions(payload);
  expect(dimensions, filename).toEqual(viewport);
  return {
    path: `output/phase2-tracepaper-final/${filename}`,
    sha256: createHash("sha256").update(payload).digest("hex"),
    ...dimensions,
    viewport,
    primary_landmark_count: primaryLandmarkCount,
    source_url: sourceUrl,
    capture_method: CAPTURE_METHOD,
    captured_at: CAPTURED_AT,
  };
}

async function installPublicCases(page: Page): Promise<void> {
  await page.route(/\/api\/public\/cases$/, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ cases: [publicCaseSummary()] }),
    });
  });
  await page.route(/\/api\/public\/cases\/inc-public-1$/, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(publicCaseEnvelope()),
    });
  });
}

function dataUrl(payload: Buffer, mime = "image/png"): string {
  return `data:${mime};base64,${payload.toString("base64")}`;
}

async function captureComparison(
  page: Page,
  filename: string,
  title: string,
  referencePath: string,
  implementationPath: string,
): Promise<CaptureEntry> {
  const [reference, implementation] = await Promise.all([
    readFile(referencePath),
    readFile(implementationPath),
  ]);
  await page.setViewportSize({ width: 2207, height: 712 });
  await page.setContent(`<!doctype html>
    <html lang="en"><head><meta charset="utf-8"><style>
      *{box-sizing:border-box}html,body{margin:0;width:100%;height:100%;overflow:hidden;background:#f3f1ea;color:#16130e;font-family:Arial,sans-serif}
      header{height:54px;display:flex;align-items:center;justify-content:space-between;padding:0 24px;background:#1b1915;color:#fbfaf5;border-bottom:4px solid #b8dc32}
      header strong{font-size:20px}header span{font-size:13px;letter-spacing:.08em;text-transform:uppercase}
      main{height:658px;display:grid;grid-template-columns:1fr 1fr;gap:16px;padding:16px}
      figure{margin:0;min-width:0;display:grid;grid-template-rows:26px 1fr;border:2px solid #1b1915;background:#fbfaf5;overflow:hidden}
      figcaption{padding:5px 10px;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;border-bottom:1px solid #1b1915}
      img{width:100%;height:100%;object-fit:contain;background:#ece8dc}
    </style></head><body>
      <header data-capture-landmark="primary"><strong>CrossPatch design comparison</strong><span>${title}</span></header>
      <main id="main-content">
        <figure><figcaption>Concept target</figcaption><img alt="Concept target" src="${dataUrl(reference)}"></figure>
        <figure><figcaption>Current implementation</figcaption><img alt="Current implementation" src="${dataUrl(implementation)}"></figure>
      </main>
    </body></html>`);
  await page.locator("img").last().waitFor({ state: "visible" });
  await page.evaluate(async () => {
    await Promise.all([...document.images].map((image) => image.decode()));
  });
  return capture(page, filename, `playwright:setContent:${filename}`);
}

test.describe("committed gallery capture generator", () => {
  test.skip(!CAPTURE_ENABLED, "set CROSSPATCH_CAPTURE_GALLERY=1 to regenerate committed captures");
  test.describe.configure({ mode: "serial" });

  test("regenerates the exact 30-file gallery with capture provenance", async ({ page }) => {
    const referenceDirectory = resolveReferenceDirectory();
    test.setTimeout(180_000);
    await page.emulateMedia({ reducedMotion: "reduce", colorScheme: "light" });
    await installOperatorRoom(page);
    await installPublicCases(page);

    const captures: CaptureEntry[] = [];
    for (const viewport of VIEWPORTS) {
      await page.setViewportSize(viewport);
      for (const target of ROUTES) {
        await page.goto(target.route, { waitUntil: "networkidle" });
        await settle(page);
        captures.push(await capture(
          page,
          `${target.name}-${viewport.width}x${viewport.height}.png`,
          page.url(),
        ));
      }
    }

    await page.setViewportSize({ width: 1280, height: 720 });
    await page.goto("/incidents/inc-e2e", { waitUntil: "networkidle" });
    await settle(page);
    await page.getByTestId("recorded-event").last().scrollIntoViewIfNeeded();
    captures.push(await capture(
      page,
      "signal-room-detail-1280x720.png",
      `${page.url()}#recorded-event-detail`,
    ));

    captures.push(await captureComparison(
      page,
      "overview-reference-comparison.png",
      "Overview",
      path.join(referenceDirectory, "ChatGPT Image Jul 15, 2026, 04_42_38 PM.png"),
      path.join(OUTPUT_DIRECTORY, "overview-1440x900.png"),
    ));
    captures.push(await captureComparison(
      page,
      "signal-reference-comparison.png",
      "Signal Room",
      path.join(referenceDirectory, "ChatGPT Image Jul 15, 2026, 04_06_55 PM.png"),
      path.join(OUTPUT_DIRECTORY, "signal-room-1440x900.png"),
    ));

    const ordered = captures.toSorted((left, right) => left.path.localeCompare(right.path));
    expect(ordered).toHaveLength(30);
    const manifest = {
      schema_version: 1,
      machine_generated: true,
      generator: "web/tests/e2e/gallery-capture.spec.ts",
      capture_method: CAPTURE_METHOD,
      captured_at: CAPTURED_AT,
      captures: ordered,
    };
    const manifestPath = path.join(OUTPUT_DIRECTORY, "capture-manifest.json");
    const temporaryPath = `${manifestPath}.tmp`;
    await writeFile(temporaryPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
    await rename(temporaryPath, manifestPath);
  });
});
