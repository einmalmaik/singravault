import { describe, expect, it } from "vitest";

import { sanitizeExportFileName } from "@/services/exportFileService";

describe("exportFileService", () => {
  it("sanitizes export filenames before they reach browser or desktop download sinks", () => {
    expect(sanitizeExportFileName('..\\<svg onload=alert(1)>.json\u0000')).toBe('..--svg onload=alert(1)-.json');
    expect(sanitizeExportFileName('folder/../../vault.html')).toBe('folder-..-..-vault.html');
    expect(sanitizeExportFileName('CON.txt')).toBe('_CON.txt');
    expect(sanitizeExportFileName('safe\u202Egnp.js')).toBe('safe-gnp.js');
    expect(sanitizeExportFileName('   ...   ')).toBe('singra-vault-export');
  });
});
