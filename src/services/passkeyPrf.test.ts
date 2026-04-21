import { describe, expect, it } from "vitest";

import { buildAuthenticationPrfExtension } from "@/services/passkeyPrf";

describe("buildAuthenticationPrfExtension", () => {
  it("returns undefined when no salts are available", () => {
    expect(buildAuthenticationPrfExtension({})).toBeUndefined();
  });

  it("always uses evalByCredential for authentication", () => {
    const extension = buildAuthenticationPrfExtension({
      credential123: "AQIDBA",
    });

    expect(extension).toBeDefined();
    expect(extension?.evalByCredential).toHaveProperty("credential123");
    expect(extension).not.toHaveProperty("eval");

    const bytes = Array.from(
      new Uint8Array(extension!.evalByCredential.credential123.first),
    );
    expect(bytes).toEqual([1, 2, 3, 4]);
  });
});
