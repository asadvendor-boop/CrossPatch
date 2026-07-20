import { expect, test } from "@playwright/test";

import {
  publicCaseEnvelope,
  publicCaseSummary,
  publicPayloadEquivalenceEnvelope,
} from "../fixtures/public-cases";
import {
  installOperatorRoom,
  operatorCanonicalDocument,
  operatorEvents,
  operatorWarrant,
} from "../fixtures/operator-room";

test.describe("Signal incident room", () => {
  test.beforeEach(async ({ page }) => {
    await installOperatorRoom(page);
  });

  test("renders the fixed seat order and preserves every recorded event", async ({ page }) => {
    await page.goto("/incidents/inc-e2e");

    await expect(page.getByRole("heading", { level: 1, name: "Webhook receipt race" })).toBeVisible();
    await expect(page.getByTestId("room-experience")).toHaveAttribute("data-room-layout", "signal");

    const roomSeats = page.locator("[data-room-seat='true']");
    await expect(roomSeats).toHaveCount(5);
    expect(await roomSeats.evaluateAll((nodes) => nodes.map((node) => node.getAttribute("data-seat"))))
      .toEqual(["Prosecutor", "Inspector", "Counsel", "Magistrate", "Bailiff"]);
    await expect(page.getByRole("separator", { name: "Human approval boundary" })).toBeVisible();

    const recordedEvents = page.getByTestId("recorded-event");
    await expect(recordedEvents).toHaveCount(operatorEvents.length);
    await expect(recordedEvents.nth(0)).toContainText("Test failed");
    await expect(recordedEvents.nth(1)).toContainText("Retry started");
  });

  test("keeps every progressive room region readable at animation time zero", async ({ page }) => {
    await page.goto("/incidents/inc-e2e");
    const regions = page.locator("[data-motion-region]");
    await expect(regions).toHaveCount(9);

    const startStyles = await page.evaluate(() => {
      for (const animation of document.getAnimations()) {
        animation.pause();
        animation.currentTime = 0;
      }
      return [...document.querySelectorAll<HTMLElement>("[data-motion-region]")].map((region) => {
        const style = getComputedStyle(region);
        return {
          name: region.dataset.motionRegion,
          opacity: style.opacity,
          visibility: style.visibility,
          display: style.display,
          hasReadableText: Boolean(region.textContent?.trim()),
        };
      });
    });

    expect(startStyles).toHaveLength(9);
    for (const region of startStyles) {
      expect(region, region.name).toMatchObject({
        opacity: "1",
        visibility: "visible",
        hasReadableText: true,
      });
      expect(region.display, region.name).not.toBe("none");
    }
  });

  test("supports skip navigation and exact approval review at 320px", async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 900 });
    await page.goto("/incidents/inc-e2e");
    await expect(page.getByTestId("room-experience")).toHaveAttribute("data-room-layout", "signal");

    await page.keyboard.press("Tab");
    const skipLink = page.getByRole("link", { name: "Skip to main content" });
    await expect(skipLink).toBeFocused();
    await skipLink.press("Enter");
    await expect(page.locator("#main-content")).toBeFocused();

    const approve = page.getByRole("button", { name: "Approve warrant" });
    await expect(approve).toBeDisabled();
    await expect(page.getByTestId("canonical-warrant-document")).toHaveText(operatorCanonicalDocument);
    await expect(page.getByTestId("canonical-warrant-document")).toHaveAttribute(
      "data-warrant-sha256",
      operatorWarrant.warrant_sha256,
    );
    await page.getByRole("checkbox", { name: /reviewed the exact canonical warrant/i }).check();
    await expect(approve).toBeEnabled();
    await expect.poll(() => page.evaluate(() =>
      document.documentElement.scrollWidth <= document.documentElement.clientWidth))
      .toBe(true);
  });
});

test("reaches the featured published case in one credential-free click", async ({ page }) => {
  const authorizationHeaders: Array<string | undefined> = [];
  await page.addInitScript(() => window.sessionStorage.clear());
  await page.route(/\/api\/public\/cases$/, async (route) => {
    authorizationHeaders.push(route.request().headers().authorization);
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ cases: [publicCaseSummary()] }),
    });
  });
  await page.route(/\/api\/public\/cases\/inc-public-1$/, async (route) => {
    authorizationHeaders.push(route.request().headers().authorization);
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(publicCaseEnvelope()),
    });
  });

  await page.goto("/");
  expect(await page.evaluate(() => window.sessionStorage.length)).toBe(0);

  let visibleClicks = 0;
  await page.getByRole("link", { name: "See the remanded repair" }).click();
  visibleClicks += 1;
  await expect(page).toHaveURL(/\/cases\/inc-public-1$/);

  await expect(page.getByRole("heading", { level: 1, name: "Webhook receipt race" })).toBeVisible();
  await expect(page.getByTestId("room-experience")).toHaveAttribute("data-room-layout", "signal");
  await expect(page.getByText(/publication is the authorization boundary/i)).toBeVisible();
  expect(visibleClicks).toBe(1);
  expect(await page.evaluate(() => window.sessionStorage.length)).toBe(0);
  expect(authorizationHeaders).toEqual([undefined, undefined]);
});

test("shows the record-derived retry comparison without viewport overflow", async ({ page }) => {
  await page.route(/\/api\/public\/cases\/inc-public-1$/, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(publicPayloadEquivalenceEnvelope()),
    });
  });

  await page.goto("/cases/inc-public-1");

  const comparison = page.getByRole("region", { name: "Retry semantics, before and after" });
  await expect(comparison).toBeVisible();
  await expect(comparison).toContainText("202 / 409 / 409");
  await expect(comparison).toContainText("202 / 200 / 409");
  await expect(comparison).toContainText("1 receipt / 1 job / 1 delivery");

  await page.setViewportSize({ width: 320, height: 900 });
  await expect(comparison).toBeVisible();
  await expect.poll(() => page.evaluate(() =>
    document.documentElement.scrollWidth <= document.documentElement.clientWidth))
    .toBe(true);
});
