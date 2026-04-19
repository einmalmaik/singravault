import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { designTheme } from "@/design";

describe("central design system", () => {
  it("loads design tokens through the single global CSS entrypoint", () => {
    const indexCss = readFileSync("src/index.css", "utf-8");
    const tokensCss = readFileSync("src/design/tokens.css", "utf-8");

    expect(indexCss).toContain('@import "./design/tokens.css";');
    expect(indexCss).not.toContain("--background:");
    expect(tokensCss).toContain("--background: 206 31% 4%");
    expect(tokensCss).toContain("--primary: 193 45% 86%");
  });

  it("keeps static PWA/browser theme metadata aligned with design metadata", () => {
    const html = readFileSync("index.html", "utf-8");
    const manifest = JSON.parse(readFileSync("public/manifest.webmanifest", "utf-8")) as {
      background_color: string;
      theme_color: string;
    };

    expect(html).toContain(`<meta name="theme-color" content="${designTheme.themeColor}"`);
    expect(manifest.theme_color).toBe(designTheme.themeColor);
    expect(manifest.background_color).toBe(designTheme.backgroundColor);
  });
});
