// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Unit tests for collectionService with mocked Supabase
 *
 * Phase 4 tests: all exported functions in collectionService.ts
 * Tests focus on control flow, error handling, and key wrapping/unwrapping logic.
 */

// ============ Hoisted Mocks ============

const mockSupabase = vi.hoisted(() => {
    const createChainable = () => {
        let _result: { data: unknown; error: unknown; count?: number } = {
            data: null,
            error: null,
        };

        const chain: Record<string, (...args: unknown[]) => unknown> = {};
        const methods = [
            "select",
            "insert",
            "update",
            "delete",
            "eq",
            "in",
            "single",
            "maybeSingle",
            "limit",
            "order",
            "upsert",
            "head",
        ];

        for (const method of methods) {
            chain[method] = vi.fn().mockImplementation((..._args: unknown[]) => {
                if (method === "single" || method === "maybeSingle") {
                    return Promise.resolve(_result);
                }
                return chain;
            });
        }

        chain.then = (
            resolve: (v: unknown) => void,
            reject?: (e: unknown) => void
        ) => Promise.resolve(_result).then(resolve, reject);

        chain._setResult = (
            data: unknown,
            error: unknown,
            count?: number
        ) => {
            _result = { data, error, count };
            return chain;
        };

        return chain;
    };

    return {
        from: vi.fn().mockImplementation(() => createChainable()),
        rpc: vi.fn(),
        auth: {
            getUser: vi.fn().mockResolvedValue({
                data: { user: { id: "mock-user-id", email: "user@test.com" } },
                error: null,
            }),
            getSession: vi.fn().mockResolvedValue({
                data: { session: { access_token: "mock-token" } },
                error: null,
            }),
        },
        functions: { invoke: vi.fn() },
        storage: { from: vi.fn() },
        _createChainable: createChainable,
    };
});

vi.mock("@/integrations/supabase/client", () => ({
    supabase: mockSupabase,
}));

// Mock cryptoService functions
const mockCryptoService = vi.hoisted(() => ({
    generateSharedKey: vi.fn(),
    encryptWithSharedKey: vi.fn(),
    decryptWithSharedKey: vi.fn(),
}));

vi.mock("../cryptoService", () => ({
    generateSharedKey: mockCryptoService.generateSharedKey,
    encryptWithSharedKey: mockCryptoService.encryptWithSharedKey,
    decryptWithSharedKey: mockCryptoService.decryptWithSharedKey,
}));

// Mock pqCryptoService functions
const mockPQCryptoService = vi.hoisted(() => ({
    hybridWrapKey: vi.fn(),
    hybridUnwrapKey: vi.fn(),
    isHybridEncrypted: vi.fn(),
}));

vi.mock("../pqCryptoService", () => ({
    hybridWrapKey: mockPQCryptoService.hybridWrapKey,
    hybridUnwrapKey: mockPQCryptoService.hybridUnwrapKey,
    isHybridEncrypted: mockPQCryptoService.isHybridEncrypted,
}));

// ============ Imports (after mocks) ============

import { describe, it, expect, vi, beforeEach } from "vitest";
import {
    getAllCollections,
    deleteCollection,
    removeMemberFromCollection,
    getCollectionMembers,
    updateMemberPermission,
    addItemToCollection,
    removeItemFromCollection,
    getCollectionItems,
    getCollectionAuditLog,
    rotateCollectionKey,
    createCollectionWithHybridKey,
    addMemberWithHybridKey,
    collectionUsesPQ,
    unwrapCollectionKey,
} from "../collectionService";

// ============ Test Suite ============

describe("collectionService", () => {
    beforeEach(() => {
        vi.clearAllMocks();

        // Default mock implementations
        mockCryptoService.generateSharedKey.mockResolvedValue("mock-shared-key");
        mockCryptoService.encryptWithSharedKey.mockResolvedValue("encrypted-data");
        mockCryptoService.decryptWithSharedKey.mockResolvedValue({ title: "Item" });

        mockPQCryptoService.hybridWrapKey.mockResolvedValue("hybrid-wrapped-key");
        mockPQCryptoService.hybridUnwrapKey.mockResolvedValue("unwrapped-pq-key");
        mockPQCryptoService.isHybridEncrypted.mockReturnValue(false);
    });

    // ============ getAllCollections() ============

    describe("getAllCollections()", () => {
        it("returns owned and member collections", async () => {
            const ownedChain = mockSupabase._createChainable();
            ownedChain._setResult(
                [
                    {
                        id: "owned-1",
                        owner_id: "mock-user-id",
                        name: "My Collection",
                        description: null,
                        created_at: "2024-01-01",
                        updated_at: "2024-01-01",
                    },
                ],
                null
            );

            const memberChain = mockSupabase._createChainable();
            memberChain._setResult(
                [
                    {
                        permission: "view",
                        shared_collections: {
                            id: "member-1",
                            owner_id: "other-user",
                            name: "Shared Collection",
                            description: "Team items",
                            created_at: "2024-01-01",
                            updated_at: "2024-01-01",
                        },
                    },
                ],
                null
            );

            mockSupabase.from
                .mockReturnValueOnce(ownedChain)
                .mockReturnValueOnce(memberChain);

            const collections = await getAllCollections();

            expect(collections).toHaveLength(2);
            expect(collections[0].is_owner).toBe(true);
            expect(collections[1].is_owner).toBe(false);
        });

        it("returns empty array when user not authenticated", async () => {
            mockSupabase.auth.getUser.mockResolvedValueOnce({
                data: { user: null },
                error: null,
            });

            const collections = await getAllCollections();
            expect(collections).toEqual([]);
        });

        it("handles empty collections", async () => {
            const ownedChain = mockSupabase._createChainable();
            ownedChain._setResult([], null);

            const memberChain = mockSupabase._createChainable();
            memberChain._setResult([], null);

            mockSupabase.from
                .mockReturnValueOnce(ownedChain)
                .mockReturnValueOnce(memberChain);

            const collections = await getAllCollections();
            expect(collections).toEqual([]);
        });
    });

    // ============ deleteCollection() ============

    describe("deleteCollection()", () => {
        it("deletes collection successfully", async () => {
            const deleteChain = mockSupabase._createChainable();
            deleteChain._setResult({ id: "collection-1" }, null);

            mockSupabase.from.mockReturnValue(deleteChain);

            await deleteCollection("collection-1");

            expect(mockSupabase.from).toHaveBeenCalledWith("shared_collections");
            expect(deleteChain.delete).toHaveBeenCalled();
            expect(deleteChain.eq).toHaveBeenCalledWith("id", "collection-1");
        });

        it("throws error if delete fails", async () => {
            const deleteChain = mockSupabase._createChainable();
            deleteChain._setResult(null, { message: "Permission denied" });

            mockSupabase.from.mockReturnValue(deleteChain);

            await expect(deleteCollection("collection-1")).rejects.toThrow();
        });
    });

    // ============ removeMemberFromCollection() ============

    describe("removeMemberFromCollection()", () => {
        it("removes member successfully", async () => {
            const deleteChain = mockSupabase._createChainable();
            deleteChain._setResult({ id: "member-entry-id" }, null);

            mockSupabase.from.mockReturnValue(deleteChain);

            await removeMemberFromCollection("collection-1", "member-id");

            expect(mockSupabase.from).toHaveBeenCalledWith("shared_collection_members");
            expect(deleteChain.delete).toHaveBeenCalled();
        });
    });

    // ============ getCollectionMembers() ============

    describe("getCollectionMembers()", () => {
        it("returns list of members with emails", async () => {
            const selectChain = mockSupabase._createChainable();
            selectChain._setResult(
                [
                    {
                        id: "member-1",
                        user_id: "user-1",
                        permission: "edit",
                        created_at: "2024-01-01",
                        profiles: { email: "user1@test.com" },
                    },
                ],
                null
            );

            mockSupabase.from.mockReturnValue(selectChain);

            const members = await getCollectionMembers("collection-1");

            expect(members).toHaveLength(1);
            expect(members[0].email).toBe("user1@test.com");
        });

        it("returns empty array when no members", async () => {
            const selectChain = mockSupabase._createChainable();
            selectChain._setResult([], null);

            mockSupabase.from.mockReturnValue(selectChain);

            const members = await getCollectionMembers("collection-1");
            expect(members).toEqual([]);
        });
    });

    // ============ updateMemberPermission() ============

    describe("updateMemberPermission()", () => {
        it("updates permission successfully", async () => {
            const updateChain = mockSupabase._createChainable();
            updateChain._setResult({ id: "member-entry-id" }, null);

            mockSupabase.from.mockReturnValue(updateChain);

            await updateMemberPermission("collection-1", "member-id", "edit");

            expect(updateChain.update).toHaveBeenCalledWith({ permission: "edit" });
        });
    });

    // ============ addItemToCollection() ============

    describe("addItemToCollection()", () => {
        it("unwraps key, encrypts item, and adds to collection", async () => {
            const keyChain = mockSupabase._createChainable();
            keyChain._setResult({
                wrapped_key: "collection-wrapped-key",
                pq_wrapped_key: "collection-pq-wrapped-key",
            }, null);

            const insertChain = mockSupabase._createChainable();
            insertChain._setResult({ id: "collection-item-id" }, null);

            mockSupabase.from
                .mockReturnValueOnce(keyChain)
                .mockReturnValueOnce(insertChain);

            const itemData = { title: "Password", username: "user", password: "pass" };
            mockPQCryptoService.isHybridEncrypted.mockReturnValueOnce(true);

            await addItemToCollection(
                "collection-1",
                "vault-item-id",
                itemData,
                "rsa-private-key",
                "pq-secret-key",
                "master-password"
            );

            expect(mockPQCryptoService.hybridUnwrapKey).toHaveBeenCalledWith(
                "collection-pq-wrapped-key",
                "pq-secret-key",
                "rsa-private-key"
            );
            expect(mockCryptoService.encryptWithSharedKey).toHaveBeenCalledWith(
                itemData,
                "unwrapped-pq-key",
                "vault-item-id"
            );
        });

        it("throws error when collection key not found", async () => {
            const keyChain = mockSupabase._createChainable();
            keyChain._setResult(null, { message: "Key not found" });

            mockSupabase.from.mockReturnValue(keyChain);

            await expect(
                addItemToCollection(
                    "collection-1",
                    "vault-item-id",
                    { title: "Test" },
                    "rsa-private-key",
                    "pq-secret-key",
                    "password"
                )
            ).rejects.toThrow();
        });
    });

    // ============ removeItemFromCollection() ============

    describe("removeItemFromCollection()", () => {
        it("removes item by id", async () => {
            const deleteChain = mockSupabase._createChainable();
            deleteChain._setResult({ id: "item-id" }, null);

            mockSupabase.from.mockReturnValue(deleteChain);

            await removeItemFromCollection("collection-1", "item-id");

            expect(mockSupabase.from).toHaveBeenCalledWith("shared_collection_items");
            expect(deleteChain.eq).toHaveBeenCalledWith("id", "item-id");
            expect(deleteChain.eq).toHaveBeenCalledWith("collection_id", "collection-1");
        });
    });

    // ============ getCollectionItems() ============

    describe("getCollectionItems()", () => {
        it("unwraps key and decrypts all items", async () => {
            const keyChain = mockSupabase._createChainable();
            keyChain._setResult({
                wrapped_key: "collection-wrapped-key",
                pq_wrapped_key: "collection-pq-wrapped-key",
            }, null);

            const itemsChain = mockSupabase._createChainable();
            itemsChain._setResult(
                [
                    {
                        id: "item-1",
                        vault_item_id: "vault-1",
                        encrypted_data: "encrypted-1",
                        added_by: "user-1",
                        created_at: "2024-01-01",
                        collection_id: "collection-1",
                    },
                ],
                null
            );

            mockSupabase.from
                .mockReturnValueOnce(keyChain)
                .mockReturnValueOnce(itemsChain);

            mockCryptoService.decryptWithSharedKey.mockResolvedValueOnce({ title: "Item 1" });
            mockPQCryptoService.isHybridEncrypted.mockReturnValueOnce(true);

            const items = await getCollectionItems(
                "collection-1",
                "rsa-private-key",
                "pq-secret-key",
                "password",
            );

            expect(items).toHaveLength(1);
            expect(items[0].decrypted_data).toEqual({ title: "Item 1" });
            expect(mockPQCryptoService.hybridUnwrapKey).toHaveBeenCalled();
        });

        it("returns empty array when no items", async () => {
            const keyChain = mockSupabase._createChainable();
            keyChain._setResult({ wrapped_key: "key", pq_wrapped_key: "pq-key" }, null);

            const itemsChain = mockSupabase._createChainable();
            itemsChain._setResult([], null);

            mockSupabase.from
                .mockReturnValueOnce(keyChain)
                .mockReturnValueOnce(itemsChain);

            mockPQCryptoService.isHybridEncrypted.mockReturnValueOnce(true);
            const items = await getCollectionItems("collection-1", "key", "pq-secret", "pass");
            expect(items).toEqual([]);
        });
    });

    // ============ getCollectionAuditLog() ============

    describe("getCollectionAuditLog()", () => {
        it("returns audit log entries", async () => {
            const auditChain = mockSupabase._createChainable();
            auditChain._setResult(
                [
                    {
                        id: "log-1",
                        collection_id: "collection-1",
                        user_id: "user-1",
                        action: "item_added",
                        details: { item_id: "vault-1" },
                        created_at: "2024-01-01",
                    },
                ],
                null
            );

            mockSupabase.from.mockReturnValue(auditChain);

            const logs = await getCollectionAuditLog("collection-1");

            expect(logs).toHaveLength(1);
            expect(logs[0].action).toBe("item_added");
        });
    });

    // ============ rotateCollectionKey() ============

    describe("rotateCollectionKey()", () => {
        it("generates new key and re-encrypts items", async () => {
            const keyChain = mockSupabase._createChainable();
            keyChain._setResult({
                wrapped_key: "old-wrapped-key",
                pq_wrapped_key: "old-pq-wrapped-key",
            }, null);

            const itemsChain = mockSupabase._createChainable();
            itemsChain._setResult(
                [
                    {
                        id: "item-1",
                        encrypted_data: "old-encrypted-1",
                        vault_item_id: "vault-1",
                    },
                ],
                null
            );

            const membersChain = mockSupabase._createChainable();
            membersChain._setResult(
                [{ user_id: "owner-id" }],
                null
            );

            const publicKeysChain = mockSupabase._createChainable();
            publicKeysChain._setResult(
                [{ user_id: "owner-id", public_key: "owner-rsa-key" }],
                null
            );

            const pqProfilesChain = mockSupabase._createChainable();
            pqProfilesChain._setResult(
                [{ user_id: "owner-id", pq_public_key: "owner-pq-key" }],
                null
            );

            mockSupabase.rpc = vi.fn().mockResolvedValue({ data: null, error: null });
            mockPQCryptoService.isHybridEncrypted.mockReturnValueOnce(true);

            mockSupabase.from
                .mockReturnValueOnce(keyChain) // get old key
                .mockReturnValueOnce(itemsChain) // get items
                .mockReturnValueOnce(membersChain) // get members
                .mockReturnValueOnce(publicKeysChain) // get rsa public keys
                .mockReturnValueOnce(pqProfilesChain); // get pq public keys

            await rotateCollectionKey("collection-1", "rsa-private-key", "pq-secret-key", "password");

            expect(mockCryptoService.generateSharedKey).toHaveBeenCalled();
            expect(mockPQCryptoService.hybridUnwrapKey).toHaveBeenCalled();
            expect(mockCryptoService.decryptWithSharedKey).toHaveBeenCalled();
            expect(mockCryptoService.encryptWithSharedKey).toHaveBeenCalled();
            expect(mockPQCryptoService.hybridWrapKey).toHaveBeenCalled();
        });
    });

    // ============ createCollectionWithHybridKey() ============

    describe("createCollectionWithHybridKey()", () => {
        it("creates collection with hybrid-wrapped key", async () => {
            const mockCollection = {
                id: "collection-1",
                name: "PQ Collection",
                owner_id: "mock-user-id",
            };

            const insertChain = mockSupabase._createChainable();
            insertChain._setResult(mockCollection, null);

            const keyChain = mockSupabase._createChainable();
            keyChain._setResult({ collection_id: "collection-1" }, null);

            mockSupabase.from
                .mockReturnValueOnce(insertChain)
                .mockReturnValueOnce(keyChain);

            // Mock hybridWrapKey to return a string instead of object
            mockPQCryptoService.hybridWrapKey.mockResolvedValueOnce("pq-wrapped-string");

            const collectionId = await createCollectionWithHybridKey(
                "PQ Collection",
                "PQ-enabled",
                "rsa-public-key",
                "pq-public-key"
            );

            expect(collectionId).toBe("collection-1");
            expect(mockPQCryptoService.hybridWrapKey).toHaveBeenCalledWith(
                "mock-shared-key",
                "pq-public-key",
                "rsa-public-key"
            );
        });
    });

    // ============ addMemberWithHybridKey() ============

    describe("addMemberWithHybridKey()", () => {
        it("adds member with hybrid-wrapped key", async () => {
            const keyChain = mockSupabase._createChainable();
            keyChain._setResult({
                wrapped_key: "owner-rsa-key",
                pq_wrapped_key: "owner-pq-key",
            }, null);

            const memberChain = mockSupabase._createChainable();
            memberChain._setResult({ id: "member-entry-id" }, null);

            const memberKeyChain = mockSupabase._createChainable();
            memberKeyChain._setResult({ id: "key-entry-id" }, null);

            mockSupabase.from
                .mockReturnValueOnce(keyChain)
                .mockReturnValueOnce(memberChain)
                .mockReturnValueOnce(memberKeyChain);

            mockPQCryptoService.isHybridEncrypted.mockReturnValue(true);
            mockPQCryptoService.hybridWrapKey.mockResolvedValueOnce("member-pq-wrapped");

            await addMemberWithHybridKey(
                "collection-1",
                "new-member-id",
                "view",
                "member-rsa-key",
                "member-pq-key",
                "owner-private-key",
                "owner-pq-secret",
                "master-password"
            );

            expect(mockPQCryptoService.isHybridEncrypted).toHaveBeenCalledWith("owner-pq-key");
            expect(mockPQCryptoService.hybridUnwrapKey).toHaveBeenCalledWith(
                "owner-pq-key",
                "owner-pq-secret",
                "owner-private-key"
            );
            expect(mockPQCryptoService.hybridWrapKey).toHaveBeenCalledWith(
                "unwrapped-pq-key",
                "member-pq-key",
                "member-rsa-key"
            );
        });
    });

    // ============ collectionUsesPQ() ============

    describe("collectionUsesPQ()", () => {
        it("returns true when pq_wrapped_key exists and is hybrid encrypted", async () => {
            const keyChain = mockSupabase._createChainable();
            keyChain._setResult({ pq_wrapped_key: "pq-key-data" }, null);

            mockSupabase.from.mockReturnValue(keyChain);
            mockPQCryptoService.isHybridEncrypted.mockReturnValue(true);

            const usesPQ = await collectionUsesPQ("collection-1");
            expect(usesPQ).toBe(true);
            expect(mockPQCryptoService.isHybridEncrypted).toHaveBeenCalledWith("pq-key-data");
        });

        it("returns false when pq_wrapped_key is null", async () => {
            const keyChain = mockSupabase._createChainable();
            keyChain._setResult({ pq_wrapped_key: null }, null);

            mockSupabase.from.mockReturnValue(keyChain);

            const usesPQ = await collectionUsesPQ("collection-1");
            expect(usesPQ).toBe(false);
        });

        it("returns false when key not found", async () => {
            const keyChain = mockSupabase._createChainable();
            keyChain._setResult(null, null);

            mockSupabase.from.mockReturnValue(keyChain);

            const usesPQ = await collectionUsesPQ("collection-1");
            expect(usesPQ).toBe(false);
        });
    });

    // ============ unwrapCollectionKey() ============

    describe("unwrapCollectionKey()", () => {
        it("unwraps hybrid key when pq_wrapped_key exists", async () => {
            mockPQCryptoService.isHybridEncrypted.mockReturnValue(true);

            const unwrappedKey = await unwrapCollectionKey(
                "rsa-key",
                "pq-key",
                "rsa-private-key",
                "pq-secret-key",
                "master-password"
            );

            expect(unwrappedKey).toBe("unwrapped-pq-key");
            expect(mockPQCryptoService.hybridUnwrapKey).toHaveBeenCalledWith(
                "pq-key",
                "pq-secret-key",
                "rsa-private-key"
            );
        });

        it("rejects RSA-only fallback when pq_wrapped_key is missing", async () => {
            mockPQCryptoService.isHybridEncrypted.mockReturnValue(false);
            await expect(
                unwrapCollectionKey(
                    "rsa-key",
                    null,
                    "rsa-private-key",
                    null,
                    "master-password"
                )
            ).rejects.toThrow("Security Standard v1 requires hybrid ML-KEM-768 + RSA-4096 key wrapping.");
        });
    });
});
