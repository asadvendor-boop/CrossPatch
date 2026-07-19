import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

import { fireEvent, render, screen } from "@testing-library/react";
import type { ComponentType } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

const webRoot = path.resolve(import.meta.dirname, "../..");

describe("Tracepaper error boundaries", () => {
  it("keeps recoverable route errors inside the application identity", async () => {
    const modulePath = path.join(webRoot, "app/error.tsx");
    expect(existsSync(modulePath), "app/error.tsx must exist").toBe(true);
    if (!existsSync(modulePath)) return;

    const { default: ErrorPage } = await vi.importActual<{ default: ComponentType<{
      error: Error & { digest?: string };
      reset: () => void;
    }> }>("@/app/error");
    const reset = vi.fn();
    render(<ErrorPage error={new Error("sensitive internal detail")} reset={reset} />);

    expect(screen.getByRole("heading", { name: /the incident view could not be rendered/i }))
      .toBeVisible();
    expect(screen.queryByText("sensitive internal detail")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /retry this view/i }));
    expect(reset).toHaveBeenCalledOnce();
    expect(screen.getByRole("link", { name: /browse verified cases/i }))
      .toHaveAttribute("href", "/cases");
    expect(screen.getByRole("link", { name: /return home/i }))
      .toHaveAttribute("href", "/");
  });

  it("supplies a self-contained Tracepaper global failure document", async () => {
    const modulePath = path.join(webRoot, "app/global-error.tsx");
    expect(existsSync(modulePath), "app/global-error.tsx must exist").toBe(true);
    if (!existsSync(modulePath)) return;

    const { default: GlobalError, GlobalErrorPanel } = await vi.importActual<{
      default: ComponentType<{
        error: Error & { digest?: string };
        reset: () => void;
      }>;
      GlobalErrorPanel: ComponentType<{
        error: Error & { digest?: string };
        reset: () => void;
      }>;
    }>("@/app/global-error");
    const reset = vi.fn();
    const error = Object.assign(new Error("private server detail"), { digest: "safe-digest" });
    const markup = renderToStaticMarkup(<GlobalError error={error} reset={reset} />);
    const errorDocument = new DOMParser().parseFromString(markup, "text/html");
    const { getByRole, getByText, queryByText } = render(
      <GlobalErrorPanel error={error} reset={reset} />,
    );

    expect(errorDocument.querySelector("html[lang='en']")).not.toBeNull();
    expect(errorDocument.querySelector("body[data-theme='tracepaper']")).not.toBeNull();
    expect(getByRole("heading", { name: /crosspatch could not load/i })).toBeVisible();
    expect(getByText("safe-digest")).toBeVisible();
    expect(queryByText("private server detail")).not.toBeInTheDocument();
    fireEvent.click(getByRole("button", { name: /retry crosspatch/i }));
    expect(reset).toHaveBeenCalledOnce();
    expect(getByRole("link", { name: /browse verified cases/i }))
      .toHaveAttribute("href", "/cases");
    expect(getByRole("link", { name: /return home/i }))
      .toHaveAttribute("href", "/");
  });

  it("ships a self-contained solid Tracepaper palette for a failed root layout", () => {
    const cssPath = path.join(webRoot, "app/error-boundary.module.css");
    expect(existsSync(cssPath), "error-boundary.module.css must exist").toBe(true);
    if (!existsSync(cssPath)) return;

    const css = readFileSync(cssPath, "utf8");
    expect(css).toMatch(/\.document,\s*\.page\s*\{/);
    for (const anchor of ["#f3f1ea", "#fbfaf5", "#16130e", "#1b1915", "#b8dc32"]) {
      expect(css).toContain(anchor);
    }
    expect(css).not.toMatch(/(?:linear|radial|conic|repeating-linear)-gradient\(/i);
  });

  it("lets the standalone failure document fit the browser content width below 320px", () => {
    const css = readFileSync(path.join(webRoot, "app/error-boundary.module.css"), "utf8");
    const documentRule = css.match(/\.document\s*\{([^}]*)\}/)?.[1] ?? "";
    const bodyRule = css.match(/\.body\s*\{([^}]*)\}/)?.[1] ?? "";

    expect(documentRule).toContain("min-width: 0");
    expect(bodyRule).toContain("min-width: 0");
    expect(`${documentRule}\n${bodyRule}`).not.toContain("min-width: 320px");
  });
});
