import { describe, expect, it } from "vitest";

import { serializeJsonLd } from "@/lib/jsonLd";

describe("SEO JSON-LD serialization", () => {
  it("escapes script-breaking characters before data reaches a script tag", () => {
    const serialized = serializeJsonLd({
      name: "</script><img src=x onerror=alert(1)>",
      text: "safe\u2028line\u2029break",
    });

    expect(serialized).not.toContain("</script>");
    expect(serialized).not.toContain("<img");
    expect(serialized).toContain("\\u003c/script\\u003e");
    expect(serialized).toContain("\\u2028");
    expect(serialized).toContain("\\u2029");
  });
});
