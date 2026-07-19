import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

import { chromium } from "@playwright/test";

const webRoot = path.resolve(import.meta.dirname, "..");
const shareSvg = path.join(webRoot, "public/crosspatch-share.svg");
const sharePng = path.join(webRoot, "public/crosspatch-share.png");
const reviewDirectory = path.resolve(webRoot, "../output");
const reviewPng = path.join(reviewDirectory, "crosspatch-logo-review.png");
const markSource = await readFile(path.join(webRoot, "public/crosspatch-mark.png"));
const markUrl = `data:image/png;base64,${markSource.toString("base64")}`;
const shareSource = (await readFile(shareSvg, "utf8"))
  .replace('href="crosspatch-mark.png"', `href="${markUrl}"`);
const shareUrl = `data:image/svg+xml;base64,${Buffer.from(shareSource).toString("base64")}`;

await mkdir(reviewDirectory, { recursive: true });
const browser = await chromium.launch({ headless: true });

try {
  const sharePage = await browser.newPage({
    deviceScaleFactor: 1,
    viewport: { width: 1200, height: 630 },
  });
  const shareRaster = await sharePage.evaluate(async (source) => {
    const canvas = document.createElement("canvas");
    canvas.width = 1200;
    canvas.height = 630;
    const context = canvas.getContext("2d");
    if (!context) throw new Error("Canvas 2D context is unavailable");
    const image = new Image();
    image.src = source;
    await image.decode();
    context.drawImage(image, 0, 0, 1200, 630);
    return canvas.toDataURL("image/png");
  }, shareUrl);
  const encodedShare = shareRaster.split(",")[1];
  if (!encodedShare) throw new Error("Brand renderer produced no PNG payload");
  await writeFile(sharePng, Buffer.from(encodedShare, "base64"));

  const reviewPage = await browser.newPage({
    deviceScaleFactor: 2,
    viewport: { width: 640, height: 220 },
  });
  await reviewPage.setContent(`<!doctype html><style>
    * { box-sizing: border-box; }
    body { margin: 0; display: grid; grid-template-columns: 1fr 1fr; height: 220px; }
    section { display: flex; align-items: center; justify-content: center; gap: 32px; }
    section:first-child { background: #f3f1ea; }
    section:last-child { background: #1b1915; }
    img { display: block; }
  </style><section>${[16, 36, 42].map((size) =>
    `<img src="${markUrl}" width="${size}" height="${size}" alt="">`).join("")}
  </section><section>${[16, 36, 42].map((size) =>
    `<img src="${markUrl}" width="${size}" height="${size}" alt="">`).join("")}
  </section>`);
  await reviewPage.screenshot({ animations: "disabled", path: reviewPng });
} finally {
  await browser.close();
}
