// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Phase 2 — Unit-Tests für fileAttachmentService mit DB-Mocks
 *
 * Testet die DB-abhängigen Funktionen: getAttachments, getStorageUsage,
 * uploadAttachment, downloadAttachment, deleteAttachment.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ---------------------------------------------------------------------------
// Supabase Mock
// ---------------------------------------------------------------------------
function createChainable(resolvedValue: unknown = { data: null, error: null }) {
  const chain: Record<string, (...args: unknown[]) => unknown> = {};
  const methods = ["select", "insert", "update", "delete", "eq", "in", "single", "maybeSingle", "limit", "order", "upsert"];
  for (const m of methods) {
    chain[m] = vi.fn().mockReturnValue(chain);
  }
  chain.then = (resolve: (v: unknown) => unknown) => resolve(resolvedValue);
  return chain;
}

const mockStorageBucket = vi.hoisted(() => {
  const mockBlob = { text: () => Promise.resolve("encrypted-content") };
  return {
    upload: vi.fn().mockResolvedValue({ data: { path: "test" }, error: null }),
    download: vi.fn().mockResolvedValue({ data: mockBlob, error: null }),
    remove: vi.fn().mockResolvedValue({ data: null, error: null }),
  };
});

const mockSupabase = vi.hoisted(() => {
  const chains: unknown[] = [];
  let chainIndex = 0;

  return {
    from: vi.fn().mockImplementation(() => {
      const idx = chainIndex++;
      return chains[idx] || createChainable();
    }),
    rpc: vi.fn(),
    auth: { getUser: vi.fn(), getSession: vi.fn().mockResolvedValue({ data: { session: { access_token: "test-token" } }, error: null }) },
    functions: { invoke: vi.fn() },
    storage: {
      from: vi.fn().mockReturnValue(mockStorageBucket),
    },
    _setChains: (newChains: unknown[]) => { chains.length = 0; chains.push(...newChains); chainIndex = 0; },
    _reset: () => { chains.length = 0; chainIndex = 0; },
  };
});

vi.mock("@/integrations/supabase/client", () => ({ supabase: mockSupabase }));

// ---------------------------------------------------------------------------
// Import after mocks
// ---------------------------------------------------------------------------
import {
  getAttachments,
  getStorageUsage,
  uploadAttachment,
  downloadAttachment,
  deleteAttachment,
} from "@/services/fileAttachmentService";
import type { FileAttachment } from "@/services/fileAttachmentService";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks();
  mockSupabase._reset();
  mockStorageBucket.upload.mockResolvedValue({ data: { path: "test" }, error: null });
  const mockBlob = { text: () => Promise.resolve("encrypted-content") };
  mockStorageBucket.download.mockResolvedValue({ data: mockBlob, error: null });
  mockStorageBucket.remove.mockResolvedValue({ data: null, error: null });
});

describe("getAttachments()", () => {
  it("returns list of attachments", async () => {
    const attachments = [
      { id: "a1", vault_item_id: "v1", file_name: "test.pdf", file_size: 1000, mime_type: "application/pdf", storage_path: "u/v/f", encrypted: true, created_at: "2026-01-01" },
    ];
    const chain = createChainable({ data: attachments, error: null });
    mockSupabase._setChains([chain]);

    const result = await getAttachments("v1");
    expect(result).toEqual(attachments);
    expect(mockSupabase.from).toHaveBeenCalledWith("file_attachments");
    expect(chain.eq).toHaveBeenCalledWith("vault_item_id", "v1");
  });

  it("decrypts metadata when decryptFn is provided", async () => {
    const attachments = [
      {
        id: "a1", vault_item_id: "v1", file_name: "encrypted", file_size: 1000,
        mime_type: "application/octet-stream", storage_path: "u/v/f", encrypted: true,
        encrypted_metadata: "encrypted-meta", created_at: "2026-01-01",
      },
    ];
    const chain = createChainable({ data: attachments, error: null });
    mockSupabase._setChains([chain]);

    const decryptFn = vi.fn().mockResolvedValue(JSON.stringify({ file_name: "secret.pdf", mime_type: "application/pdf" }));
    const result = await getAttachments("v1", decryptFn);

    expect(result).toHaveLength(1);
    expect(result[0].file_name).toBe("secret.pdf");
    expect(result[0].mime_type).toBe("application/pdf");
    expect(decryptFn).toHaveBeenCalledWith("encrypted-meta");
  });

  it("returns empty list when no attachments", async () => {
    const chain = createChainable({ data: [], error: null });
    mockSupabase._setChains([chain]);

    const result = await getAttachments("v1");
    expect(result).toEqual([]);
  });

  it("throws on DB error", async () => {
    const chain = createChainable({ data: null, error: { message: "DB error" } });
    mockSupabase._setChains([chain]);

    await expect(getAttachments("v1")).rejects.toEqual({ message: "DB error" });
  });
});

describe("getStorageUsage()", () => {
  it("returns used and limit", async () => {
    const data = [{ file_size: 500 }, { file_size: 300 }];
    const chain = createChainable({ data, error: null });
    mockSupabase._setChains([chain]);

    const result = await getStorageUsage("user-1");
    expect(result.used).toBe(800);
    expect(result.limit).toBe(1073741824); // 1 GB
  });

  it("returns 0 used when no files", async () => {
    const chain = createChainable({ data: [], error: null });
    mockSupabase._setChains([chain]);

    const result = await getStorageUsage("user-1");
    expect(result.used).toBe(0);
  });
});

describe("uploadAttachment()", () => {
  it("throws for file too large (>100MB)", async () => {
    const bigFile = new File(["x"], "big.bin");
    Object.defineProperty(bigFile, "size", { value: 101 * 1024 * 1024 });

    await expect(uploadAttachment("user-1", "v1", bigFile, vi.fn())).rejects.toThrow("File too large");
  });

  it("throws when storage limit reached", async () => {
    // Mock getStorageUsage to return near-limit
    const usageChain = createChainable({ data: [{ file_size: 1073741800 }], error: null });
    mockSupabase._setChains([usageChain]);

    const file = new File(["content"], "test.txt", { type: "text/plain" });
    Object.defineProperty(file, "size", { value: 100 });

    await expect(uploadAttachment("user-1", "v1", file, vi.fn())).rejects.toThrow("Storage limit reached");
  });

  it("encrypts file and metadata, stores in DB and storage", async () => {
    // Chain 1: getStorageUsage
    const usageChain = createChainable({ data: [], error: null });
    // Chain 2: file_attachments insert
    const insertChain = createChainable({
      data: { id: "att1", vault_item_id: "v1", file_name: "encrypted", file_size: 7, storage_path: "u/v/f", encrypted: true },
      error: null,
    });
    mockSupabase._setChains([usageChain, insertChain]);

    const encryptFn = vi.fn()
      .mockResolvedValueOnce("encrypted-file-content") // file content
      .mockResolvedValueOnce("encrypted-metadata"); // metadata

    const fileContent = new TextEncoder().encode("content");
    const file = new File([fileContent], "test.txt", { type: "text/plain" });
    // jsdom File may not support arrayBuffer(), so we polyfill it
    if (!file.arrayBuffer) {
      (file as unknown as Record<string, unknown>).arrayBuffer = () => Promise.resolve(fileContent.buffer);
    }

    const result = await uploadAttachment("user-1", "v1", file, encryptFn);

    expect(encryptFn).toHaveBeenCalledTimes(2);
    expect(mockStorageBucket.upload).toHaveBeenCalled();
    expect(mockSupabase.from).toHaveBeenCalledWith("file_attachments");
    // Result should have original file name (not "encrypted")
    expect(result.file_name).toBe("test.txt");
  });
});

describe("downloadAttachment()", () => {
  it("downloads, decrypts, and triggers browser download", async () => {
    const attachment: FileAttachment = {
      id: "a1", vault_item_id: "v1", file_name: "test.pdf", file_size: 100,
      mime_type: "application/pdf", storage_path: "u/v/f", encrypted: true, created_at: "2026-01-01",
    };

    // Mock atob/btoa for base64
    const decryptFn = vi.fn().mockResolvedValue(btoa("decrypted-content"));

    // Mock createElement and click
    const mockAnchor = { href: "", download: "", click: vi.fn() };
    vi.spyOn(document, "createElement").mockReturnValue(mockAnchor as unknown as HTMLElement);
    vi.spyOn(document.body, "appendChild").mockImplementation(() => mockAnchor as unknown as HTMLElement);
    vi.spyOn(document.body, "removeChild").mockImplementation(() => mockAnchor as unknown as HTMLElement);
    // jsdom doesn't have URL.createObjectURL — define it
    if (!URL.createObjectURL) {
      (URL as unknown as Record<string, unknown>).createObjectURL = vi.fn().mockReturnValue("blob:test");
      (URL as unknown as Record<string, unknown>).revokeObjectURL = vi.fn();
    } else {
      vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:test");
      vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => { });
    }

    await downloadAttachment(attachment, decryptFn);

    expect(mockStorageBucket.download).toHaveBeenCalledWith("u/v/f");
    expect(decryptFn).toHaveBeenCalled();
    expect(mockAnchor.click).toHaveBeenCalled();
    expect(mockAnchor.download).toBe("test.pdf");
  });

  it("throws when download fails", async () => {
    mockStorageBucket.download.mockResolvedValueOnce({ data: null, error: { message: "Not found" } });

    const attachment: FileAttachment = {
      id: "a1", vault_item_id: "v1", file_name: "test.pdf", file_size: 100,
      mime_type: null, storage_path: "u/v/f", encrypted: true, created_at: "2026-01-01",
    };

    await expect(downloadAttachment(attachment, vi.fn())).rejects.toEqual({ message: "Not found" });
  });
});

describe("deleteAttachment()", () => {
  it("deletes from storage and DB", async () => {
    const dbChain = createChainable({ data: null, error: null });
    mockSupabase._setChains([dbChain]);

    const attachment: FileAttachment = {
      id: "a1", vault_item_id: "v1", file_name: "test.pdf", file_size: 100,
      mime_type: null, storage_path: "u/v/f", encrypted: true, created_at: "2026-01-01",
    };

    await deleteAttachment(attachment);

    expect(mockStorageBucket.remove).toHaveBeenCalledWith(["u/v/f"]);
    expect(mockSupabase.from).toHaveBeenCalledWith("file_attachments");
    expect(dbChain.delete).toHaveBeenCalled();
    expect(dbChain.eq).toHaveBeenCalledWith("id", "a1");
  });

  it("throws on DB error", async () => {
    const dbChain = createChainable({ data: null, error: { message: "Delete failed" } });
    mockSupabase._setChains([dbChain]);

    const attachment: FileAttachment = {
      id: "a1", vault_item_id: "v1", file_name: "test.pdf", file_size: 100,
      mime_type: null, storage_path: "u/v/f", encrypted: true, created_at: "2026-01-01",
    };

    await expect(deleteAttachment(attachment)).rejects.toEqual({ message: "Delete failed" });
  });
});
