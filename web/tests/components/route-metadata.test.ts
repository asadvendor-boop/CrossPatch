import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { inflateSync } from "node:zlib";

import type { Metadata } from "next";
import { describe, expect, it } from "vitest";

import { metadata as rootMetadata } from "@/app/layout";

const webRoot = path.resolve(import.meta.dirname, "../..");

function paeth(left: number, above: number, upperLeft: number): number {
  const prediction = left + above - upperLeft;
  const leftDistance = Math.abs(prediction - left);
  const aboveDistance = Math.abs(prediction - above);
  const upperLeftDistance = Math.abs(prediction - upperLeft);
  if (leftDistance <= aboveDistance && leftDistance <= upperLeftDistance) return left;
  return aboveDistance <= upperLeftDistance ? above : upperLeft;
}

function rgbaPixels(png: Buffer): { width: number; pixel: (x: number, y: number) => string } {
  expect(png.subarray(1, 4).toString("ascii")).toBe("PNG");
  const width = png.readUInt32BE(16);
  const height = png.readUInt32BE(20);
  expect(png[24], "share image must remain 8-bit").toBe(8);
  expect(png[25], "share image must remain RGBA").toBe(6);
  expect(png[28], "share image must remain non-interlaced").toBe(0);

  const idat: Buffer[] = [];
  for (let offset = 8; offset < png.length;) {
    const length = png.readUInt32BE(offset);
    const type = png.subarray(offset + 4, offset + 8).toString("ascii");
    if (type === "IDAT") idat.push(png.subarray(offset + 8, offset + 8 + length));
    offset += length + 12;
  }

  const filtered = inflateSync(Buffer.concat(idat));
  const bytesPerPixel = 4;
  const stride = width * bytesPerPixel;
  const decoded = Buffer.alloc(stride * height);
  for (let y = 0; y < height; y += 1) {
    const sourceRow = y * (stride + 1);
    const filter = filtered[sourceRow];
    if (filter > 4) throw new Error(`unsupported PNG filter ${filter}`);
    for (let x = 0; x < stride; x += 1) {
      const raw = filtered[sourceRow + x + 1];
      const output = y * stride + x;
      const left = x >= bytesPerPixel ? decoded[output - bytesPerPixel] : 0;
      const above = y > 0 ? decoded[output - stride] : 0;
      const upperLeft = y > 0 && x >= bytesPerPixel
        ? decoded[output - stride - bytesPerPixel]
        : 0;
      const predictor = filter === 0
        ? 0
        : filter === 1
          ? left
          : filter === 2
            ? above
            : filter === 3
              ? Math.floor((left + above) / 2)
              : filter === 4
                ? paeth(left, above, upperLeft)
                : 0;
      decoded[output] = (raw + predictor) & 0xff;
    }
  }

  return {
    width,
    pixel: (x, y) => {
      const offset = (y * width + x) * bytesPerPixel;
      return `#${decoded.subarray(offset, offset + 3).toString("hex")}`;
    },
  };
}

const ROUTES = [
  { file: "app/page.tsx", load: () => import("@/app/page"), title: "Failure-first incident repair" },
  { file: "app/overview/page.tsx", load: () => import("@/app/overview/page"), title: "Operational proof overview" },
  { file: "app/open-incident/page.tsx", load: () => import("@/app/open-incident/page"), title: "Open or join an incident" },
  { file: "app/cases/page.tsx", load: () => import("@/app/cases/page"), title: "Verified published cases" },
  { file: "app/cases/[id]/page.tsx", load: () => import("@/app/cases/[id]/page"), title: "Published case detail" },
  { file: "app/doctrine/page.tsx", load: () => import("@/app/doctrine/page"), title: "Due process for AI agents" },
  { file: "app/approvals/page.tsx", load: () => import("@/app/approvals/page"), title: "Incident warrant approval" },
  { file: "app/artifacts/page.tsx", load: () => import("@/app/artifacts/page"), title: "Incident artifacts and exports" },
  { file: "app/incidents/[id]/page.tsx", load: () => import("@/app/incidents/[id]/page"), title: "Live incident room" },
] as const;

function pageFiles(directory: string, prefix = "app"): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const absolute = path.join(directory, entry.name);
    const relative = `${prefix}/${entry.name}`;
    if (entry.isDirectory()) return pageFiles(absolute, relative);
    return entry.name === "page.tsx" ? [relative] : [];
  });
}

describe("route discovery metadata", () => {
  it("gives every existing route a descriptive title and description", async () => {
    expect(pageFiles(path.join(webRoot, "app")).sort())
      .toEqual(ROUTES.map(({ file }) => file).sort());

    for (const route of ROUTES) {
      const routeModule = await route.load() as { metadata?: Metadata };
      expect(routeModule.metadata?.title, route.file).toBe(route.title);
      expect(routeModule.metadata?.description, route.file).toEqual(expect.any(String));
      expect(String(routeModule.metadata?.description).length, route.file).toBeGreaterThan(48);
    }
  });

  it("uses the pinned Next global-not-found convention for distinct 404 metadata", async () => {
    const configSource = readFileSync(path.join(webRoot, "next.config.ts"), "utf8");
    const globalNotFoundPath = path.join(webRoot, "app/global-not-found.tsx");

    expect(configSource).toContain("globalNotFound: true");
    expect(() => readFileSync(globalNotFoundPath, "utf8")).not.toThrow();

    const source = readFileSync(globalNotFoundPath, "utf8");
    const routeModule = await import("@/app/global-not-found") as { metadata?: Metadata };
    const title = routeModule.metadata?.title;
    const description = routeModule.metadata?.description;
    const rootTitle = rootMetadata.title as { default?: string };

    expect(title).toBe("Route not found");
    expect(title).not.toBe(rootTitle.default);
    expect(description).toEqual(expect.any(String));
    expect(String(description).length).toBeGreaterThan(48);
    expect(source).toContain("export const metadata");
    expect(source).toMatch(/<html\s+lang="en"/);
    expect(source).toContain("<body>");
  });

  it("wires Open Graph and Twitter cards to the same exact-size local image", () => {
    expect(rootMetadata.openGraph).toMatchObject({
      type: "website",
      siteName: "CrossPatch",
      images: [{
        url: "/crosspatch-share.png",
        width: 1200,
        height: 630,
        alt: expect.stringMatching(/CrossPatch/),
      }],
    });
    expect(rootMetadata.twitter).toMatchObject({
      card: "summary_large_image",
      images: ["/crosspatch-share.png"],
    });

    const png = readFileSync(path.join(webRoot, "public/crosspatch-share.png"));
    expect(png.subarray(1, 4).toString("ascii")).toBe("PNG");
    expect(png.readUInt32BE(16)).toBe(1200);
    expect(png.readUInt32BE(20)).toBe(630);

    const raster = rgbaPixels(png);
    expect({
      active: raster.pixel(600, 310),
      warning: raster.pixel(800, 310),
      failure: raster.pixel(400, 310),
      verified: raster.pixel(49, 306),
    }).toEqual({
      active: "#1f55a8",
      warning: "#7f4f00",
      failure: "#a82038",
      verified: "#006a52",
    });

    const source = readFileSync(path.join(webRoot, "public/crosspatch-share.svg"), "utf8");
    expect(source).toContain('width="1200"');
    expect(source).toContain('height="630"');
    expect(source.match(/<image\b/gi)?.length).toBe(1);
    expect(source).toContain(
      '<image data-crosspatch-mark="operator-latest1-v1" x="40" y="42" width="76" height="76" href="crosspatch-mark.png"/>',
    );
    expect(source).not.toMatch(/@font-face|(?:linear|radial|conic)-gradient|url\(/i);
    expect(source).not.toMatch(/(?:href|src)\s*=\s*["'](?:https?:|data:|\/)/i);

    for (const statusHue of ["#1f55a8", "#7f4f00", "#a82038", "#006a52"]) {
      expect(source).toContain(statusHue);
    }
    expect(source).not.toMatch(/#74b4f2|#e6b45c|#ee7272|#5fbb72/i);

    const chartreuseElements = [...source.matchAll(/<([^>]*#b8dc32[^>]*)>/gi)]
      .map(([, element]) => element.trim());
    expect(chartreuseElements.length).toBeGreaterThan(0);
    expect(chartreuseElements.every((element) =>
      element.startsWith("rect ") && element.includes('fill="#b8dc32"'))).toBe(true);
  });

  it("passes the canonical public origin into the hosted web image build", () => {
    const compose = readFileSync(path.resolve(webRoot, "../compose.yaml"), "utf8");
    const webService = compose.split("\n  web:\n", 2)[1]?.split("\n  caddy:\n", 1)[0] ?? "";
    const webServiceBuild = webService.split("\n    init:\n", 1)[0] ?? "";
    const dockerfile = readFileSync(path.resolve(webRoot, "../Dockerfile"), "utf8");
    const webBuild = dockerfile.split("FROM ${NODE_IMAGE} AS web-build", 2)[1]
      ?.split("FROM ${NODE_IMAGE} AS web-runtime", 1)[0] ?? "";

    expect(webServiceBuild).toContain("args:");
    expect(webServiceBuild).toContain(
      "CROSSPATCH_PUBLIC_URL: ${CROSSPATCH_PUBLIC_URL:-https://localhost}",
    );
    expect(webBuild).toContain("ARG CROSSPATCH_PUBLIC_URL=https://localhost");
    expect(webBuild).toContain("ENV CROSSPATCH_PUBLIC_URL=${CROSSPATCH_PUBLIC_URL}");
    expect(webBuild.indexOf("ENV CROSSPATCH_PUBLIC_URL=${CROSSPATCH_PUBLIC_URL}"))
      .toBeLessThan(webBuild.indexOf("npm --workspace @crosspatch/web run build"));
  });

  it("keeps the canonical public origin available to the hosted web runtime", () => {
    const compose = readFileSync(path.resolve(webRoot, "../compose.yaml"), "utf8");
    const webService = compose.split("\n  web:\n", 2)[1]?.split("\n  caddy:\n", 1)[0] ?? "";
    const runtimeEnvironment = webService.split("\n    environment:\n", 2)[1]
      ?.split("\n    expose:\n", 1)[0] ?? "";

    expect(runtimeEnvironment).toContain(
      "CROSSPATCH_PUBLIC_URL: ${CROSSPATCH_PUBLIC_URL:-https://localhost}",
    );
  });
});
