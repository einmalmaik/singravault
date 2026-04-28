import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const capability = JSON.parse(
  readFileSync('src-tauri/capabilities/default.json', 'utf-8'),
) as { permissions: unknown[] };

describe('Tauri default capability contract', () => {
  it('does not grant recursive user-directory write, rename, or remove rights to the main webview', () => {
    expect(capability.permissions).not.toContain('fs:allow-write');
    expect(capability.permissions).not.toContain('fs:allow-rename');
    expect(capability.permissions).not.toContain('fs:allow-remove');
    expect(capability.permissions).not.toContain('fs:allow-open');
    expect(capability.permissions).not.toContain('fs:scope-desktop-recursive');
    expect(capability.permissions).not.toContain('fs:scope-document-recursive');
    expect(capability.permissions).not.toContain('fs:scope-download-recursive');
  });

  it('keeps only the narrow file write command needed after a user-selected save dialog', () => {
    expect(capability.permissions).toContain('dialog:allow-save');
    expect(capability.permissions).toContain('fs:allow-write-file');
    expect(capability.permissions).toContain('fs:create-app-specific-dirs');
    expect(capability.permissions).toContain('fs:allow-applog-write');
    expect(capability.permissions).not.toContain('fs:allow-applog-read');
  });

  it('does not expose opener file/path commands to the renderer', () => {
    expect(capability.permissions).not.toContain('opener:default');
    expect(capability.permissions).toContain('opener:allow-open-url');
    expect(capability.permissions).toContain('opener:allow-default-urls');
  });
});
