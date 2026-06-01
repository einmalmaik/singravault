// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Contract tests for Premium file attachment DB compatibility.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const migration = readFileSync(
  join(
    process.cwd(),
    "supabase",
    "migrations",
    "20260601181443_allow_file_attachments_for_oplog_items.sql",
  ),
  "utf8",
);

describe("file attachment OpLog migration contract", () => {
  it("removes the legacy vault_items-only foreign key without creating shadow items", () => {
    expect(migration).toContain("DROP CONSTRAINT IF EXISTS file_attachments_vault_item_id_fkey");
    expect(migration).not.toMatch(/INSERT\s+INTO\s+public\.vault_items/iu);
    expect(migration).not.toMatch(/UPDATE\s+public\.vault_items/iu);
  });

  it("allows attachments only for active own OpLog item records or legacy own vault_items", () => {
    expect(migration).toContain("FROM public.vault_records vr");
    expect(migration).toContain("vr.record_id = NEW.vault_item_id");
    expect(migration).toContain("vr.user_id = NEW.user_id");
    expect(migration).toContain("vr.record_type = 'item'");
    expect(migration).toContain("vr.is_tombstone IS FALSE");
    expect(migration).toContain("FROM public.vault_items vi");
    expect(migration).toContain("vi.id = NEW.vault_item_id");
    expect(migration).toContain("vi.user_id = NEW.user_id");
  });

  it("keeps paid entitlement and opaque encrypted metadata checks in the trigger", () => {
    expect(migration).toContain("public.user_has_active_paid_subscription(NEW.user_id)");
    expect(migration).toContain("NEW.encrypted_metadata NOT LIKE 'sv-file-manifest-v1:%'");
    expect(migration).toContain("Attachment storage_path must not contain plaintext file extensions");
    expect(migration).toContain("Attachment file_name must be an opaque placeholder");
    expect(migration).toContain("Attachment mime_type must be an opaque placeholder");
  });
});
