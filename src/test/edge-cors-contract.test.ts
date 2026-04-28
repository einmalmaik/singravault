import { afterEach, describe, expect, it, vi } from "vitest";

describe("edge function CORS contract", () => {
  afterEach(() => {
    vi.resetModules();
    vi.unstubAllGlobals();
  });

  it("allows documented local development origins only through explicit opt-in", async () => {
    vi.stubGlobal("Deno", {
      env: {
        get(key: string) {
          switch (key) {
            case "ALLOWED_ORIGIN":
              return "https://singravault.mauntingstudios.de";
            case "ALLOW_LOCAL_DEV_ORIGINS":
              return "true";
            default:
              return "";
          }
        },
      },
    });

    const { getCorsHeaders } = await import("../../supabase/functions/_shared/cors");
    const localhostHeaders = getCorsHeaders(new Request("https://example.test", {
      headers: { Origin: "http://localhost:8080" },
    }));
    const loopbackHeaders = getCorsHeaders(new Request("https://example.test", {
      headers: { Origin: "http://127.0.0.1:8080" },
    }));

    expect(localhostHeaders["Access-Control-Allow-Origin"]).toBe("http://localhost:8080");
    expect(loopbackHeaders["Access-Control-Allow-Origin"]).toBe("http://127.0.0.1:8080");
    expect(localhostHeaders["Vary"]).toBe("Origin");
  });

  it("does not emit wildcard or null access-control origins for denied origins", async () => {
    vi.stubGlobal("Deno", {
      env: {
        get(key: string) {
          return key === "ALLOWED_ORIGIN" ? "https://singravault.mauntingstudios.de" : "";
        },
      },
    });

    const { getCorsHeaders } = await import("../../supabase/functions/_shared/cors");
    const headers = getCorsHeaders(new Request("https://example.test", {
      headers: { Origin: "https://evil.example" },
    }));

    expect(headers["Access-Control-Allow-Origin"]).toBeUndefined();
    expect(headers["Access-Control-Allow-Origin"]).not.toBe("*");
    expect(headers["Access-Control-Allow-Origin"]).not.toBe("null");
    expect(headers["Vary"]).toBe("Origin");
  });

  it("does not treat provider-level preview suffixes as hyphen-boundary allowlists", async () => {
    vi.stubGlobal("Deno", {
      env: {
        get(key: string) {
          switch (key) {
            case "ALLOWED_ORIGIN":
              return "https://singravault.mauntingstudios.de";
            case "ALLOW_PREVIEW_ORIGINS":
              return "true";
            case "ALLOWED_PREVIEW_ORIGIN_SUFFIXES":
              return "vercel.app";
            default:
              return "";
          }
        },
      },
    });

    const { getCorsHeaders } = await import("../../supabase/functions/_shared/cors");
    const headers = getCorsHeaders(new Request("https://example.test", {
      headers: { Origin: "https://evil-vercel.app" },
    }));

    expect(headers["Access-Control-Allow-Origin"]).toBeUndefined();
    expect(headers["Vary"]).toBe("Origin");
  });

  it("supports account-delete method narrowing without changing origin policy", async () => {
    vi.stubGlobal("Deno", {
      env: {
        get(key: string) {
          switch (key) {
            case "ALLOWED_ORIGIN":
              return "https://singravault.mauntingstudios.de";
            case "ALLOW_LOCAL_DEV_ORIGINS":
              return "true";
            default:
              return "";
          }
        },
      },
    });

    const { getCorsHeaders } = await import("../../supabase/functions/_shared/cors");
    const headers = getCorsHeaders(new Request("https://example.test", {
      headers: { Origin: "http://localhost:8080" },
    }), { allowedMethods: "POST, OPTIONS" });

    expect(headers["Access-Control-Allow-Origin"]).toBe("http://localhost:8080");
    expect(headers["Access-Control-Allow-Methods"]).toBe("POST, OPTIONS");
    expect(headers["Access-Control-Allow-Headers"]).toContain("authorization");
    expect(headers["Access-Control-Allow-Headers"]).toContain("apikey");
    expect(headers["Access-Control-Allow-Headers"]).toContain("content-type");
    expect(headers["Access-Control-Allow-Headers"]).toContain("x-client-info");
  });
});
