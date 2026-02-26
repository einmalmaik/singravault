// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Collection Service for Shared Collections
 *
 * Implements secure sharing of vault items using hybrid encryption:
 * - ML-KEM-768 + RSA-4096 for post-quantum key wrapping
 * - AES-256-GCM for item encryption
 */

import { supabase } from '@/integrations/supabase/client';
import {
    generateSharedKey,
    encryptWithSharedKey,
    decryptWithSharedKey,
    VaultItemData
} from './cryptoService';
import {
    hybridWrapKey,
    hybridUnwrapKey,
    isHybridEncrypted
} from './pqCryptoService';

// ============ Constants ============

const SECURITY_STANDARD_V1_ERROR =
    'Security Standard v1 requires hybrid ML-KEM-768 + RSA-4096 key wrapping.';

// ============ Type Definitions ============

export interface CollectionMember {
    id: string;
    user_id: string;
    email: string;
    permission: 'view' | 'edit';
    created_at: string;
}

export interface CollectionItem {
    id: string;
    vault_item_id: string;
    added_by: string;
    created_at: string;
    encrypted_data: string;
    decrypted_data?: VaultItemData;
}

export interface SharedCollection {
    id: string;
    owner_id: string;
    name: string;
    description: string | null;
    member_count: number;
    item_count: number;
    created_at: string;
    updated_at: string;
    is_owner?: boolean;
    user_permission?: 'view' | 'edit';
}

export interface AuditLogEntry {
    id: string;
    collection_id: string;
    user_id: string | null;
    action: string;
    details: Record<string, unknown> | null;
    created_at: string;
}

// ============ Collection Management ============

/**
 * Gets all collections (owned + member)
 * 
 * @returns Array of collections with role/permission info
 */
export async function getAllCollections(): Promise<SharedCollection[]> {
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return [];

    // Get owned collections
    const { data: ownedCollections, error: ownedError } = await supabase
        .from('shared_collections')
        .select('*')
        .eq('owner_id', user.id)
        .order('created_at', { ascending: false });

    if (ownedError) throw ownedError;

    // Get collections where user is a member
    const { data: memberCollections, error: memberError } = await supabase
        .from('shared_collection_members')
        .select(`
            permission,
            shared_collections (*)
        `)
        .eq('user_id', user.id);

    if (memberError) throw memberError;

    // Combine and mark ownership
    const owned = (ownedCollections || []).map(c => ({
        ...c,
        is_owner: true,
        user_permission: undefined,
    }));

    const member = (memberCollections || []).map(m => ({
        ...(m.shared_collections as any),
        is_owner: false,
        user_permission: m.permission,
    }));

    return [...owned, ...member];
}

/**
 * Deletes a collection (owner only)
 * 
 * @param collectionId - Collection ID
 */
export async function deleteCollection(collectionId: string): Promise<void> {
    const { error } = await supabase
        .from('shared_collections')
        .delete()
        .eq('id', collectionId);

    if (error) throw error;
}

// ============ Member Management ============

/**
 * Removes a member from a collection
 * 
 * @param collectionId - Collection ID
 * @param userId - User ID to remove
 */
export async function removeMemberFromCollection(
    collectionId: string,
    userId: string
): Promise<void> {
    // 1. Remove Member
    const { error: memberError } = await supabase
        .from('shared_collection_members')
        .delete()
        .eq('collection_id', collectionId)
        .eq('user_id', userId);

    if (memberError) throw memberError;

    // 2. Delete wrapped Key
    const { error: keyError } = await supabase
        .from('collection_keys')
        .delete()
        .eq('collection_id', collectionId)
        .eq('user_id', userId);

    if (keyError) throw keyError;
}

/**
 * Gets all members of a collection
 * 
 * @param collectionId - Collection ID
 * @returns Array of collection members
 */
export async function getCollectionMembers(collectionId: string): Promise<CollectionMember[]> {
    const { data, error } = await supabase
        .from('shared_collection_members')
        .select(`
            id,
            user_id,
            permission,
            created_at,
            profiles!inner(email)
        `)
        .eq('collection_id', collectionId);

    if (error) throw error;

    return (data || []).map(m => ({
        id: m.id,
        user_id: m.user_id,
        email: (m.profiles as unknown as { email: string }).email,
        permission: m.permission as 'view' | 'edit',
        created_at: m.created_at,
    }));
}

/**
 * Updates a member's permission
 * 
 * @param collectionId - Collection ID
 * @param userId - User ID
 * @param permission - New permission ('view' or 'edit')
 */
export async function updateMemberPermission(
    collectionId: string,
    userId: string,
    permission: 'view' | 'edit'
): Promise<void> {
    const { error } = await supabase
        .from('shared_collection_members')
        .update({ permission })
        .eq('collection_id', collectionId)
        .eq('user_id', userId);

    if (error) throw error;
}

// ============ Item Management ============

/**
 * Adds an item to a collection
 * 
 * @param collectionId - Collection ID
 * @param vaultItemId - Vault item ID
 * @param itemData - Decrypted item data
 * @param rsaPrivateKey - User's RSA private key (JWK string)
 * @param pqSecretKey - User's ML-KEM-768 secret key (base64)
 * @param masterPassword - User's master password
 */
export async function addItemToCollection(
    collectionId: string,
    vaultItemId: string,
    itemData: VaultItemData,
    rsaPrivateKey: string,
    pqSecretKey: string,
    masterPassword: string
): Promise<void> {
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) throw new Error('Not authenticated');

    // 1. Load wrapped Shared Key
    const { data: keyData, error: keyError } = await supabase
        .from('collection_keys')
        .select('wrapped_key, pq_wrapped_key')
        .eq('collection_id', collectionId)
        .eq('user_id', user.id)
        .single() as {
            data: { wrapped_key: string; pq_wrapped_key: string | null } | null;
            error: unknown;
        };

    if (keyError || !keyData) throw new Error('Collection key not found');

    // 2. Unwrap Shared Key (Security Standard v1 hybrid path only)
    const sharedKey = await unwrapCollectionKey(
        keyData.wrapped_key,
        keyData.pq_wrapped_key,
        rsaPrivateKey,
        pqSecretKey,
        masterPassword,
    );

    // 3. Encrypt Item with Shared Key
    const encryptedData = await encryptWithSharedKey(itemData, sharedKey, vaultItemId);

    // 4. Add Item
    const { error } = await supabase
        .from('shared_collection_items')
        .insert({
            collection_id: collectionId,
            vault_item_id: vaultItemId,
            encrypted_data: encryptedData,
            added_by: user.id,
        });

    if (error) throw error;
}

/**
 * Removes an item from a collection
 * 
 * @param collectionId - Collection ID
 * @param itemId - Collection item ID (not vault_item_id)
 */
export async function removeItemFromCollection(
    collectionId: string,
    itemId: string
): Promise<void> {
    const { error } = await supabase
        .from('shared_collection_items')
        .delete()
        .eq('id', itemId)
        .eq('collection_id', collectionId);

    if (error) throw error;
}

/**
 * Gets all items in a collection (decrypted)
 * 
 * @param collectionId - Collection ID
 * @param rsaPrivateKey - User's RSA private key (JWK string)
 * @param pqSecretKey - User's ML-KEM-768 secret key (base64)
 * @param masterPassword - User's master password
 * @returns Array of collection items with decrypted data
 */
export async function getCollectionItems(
    collectionId: string,
    rsaPrivateKey: string,
    pqSecretKey: string,
    masterPassword: string
): Promise<CollectionItem[]> {
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) throw new Error('Not authenticated');

    // 1. Load wrapped Shared Key
    const { data: keyData, error: keyError } = await supabase
        .from('collection_keys')
        .select('wrapped_key, pq_wrapped_key')
        .eq('collection_id', collectionId)
        .eq('user_id', user.id)
        .single() as {
            data: { wrapped_key: string; pq_wrapped_key: string | null } | null;
            error: unknown;
        };

    if (keyError || !keyData) throw new Error('Collection key not found');

    // 2. Unwrap Shared Key (Security Standard v1 hybrid path only)
    const sharedKey = await unwrapCollectionKey(
        keyData.wrapped_key,
        keyData.pq_wrapped_key,
        rsaPrivateKey,
        pqSecretKey,
        masterPassword,
    );

    // 3. Load Items
    const { data: items, error } = await supabase
        .from('shared_collection_items')
        .select('*')
        .eq('collection_id', collectionId);

    if (error) throw error;

    // 4. Decrypt Items
    const decryptedItems = await Promise.all(
        (items || []).map(async (item) => {
            try {
                const decrypted_data = await decryptWithSharedKey(item.encrypted_data, sharedKey, item.vault_item_id);
                return {
                    ...item,
                    decrypted_data,
                };
            } catch (error) {
                console.error('Failed to decrypt item:', item.id, error);
                return {
                    ...item,
                    decrypted_data: undefined,
                };
            }
        })
    );

    return decryptedItems;
}

// ============ Audit Log ============

/**
 * Gets audit log for a collection
 * 
 * @param collectionId - Collection ID
 * @returns Array of audit log entries
 */
export async function getCollectionAuditLog(collectionId: string): Promise<AuditLogEntry[]> {
    const { data, error } = await supabase
        .from('collection_audit_log')
        .select('*')
        .eq('collection_id', collectionId)
        .order('created_at', { ascending: false })
        .limit(100);

    if (error) throw error;

    return (data || []) as any;
}

// ============ Key Rotation ============

/**
 * Rotates the shared key for a collection
 * Re-encrypts all items with a new key
 * 
 * @param collectionId - Collection ID
 * @param rsaPrivateKey - Owner's RSA private key (JWK string)
 * @param pqSecretKey - Owner's ML-KEM-768 secret key (base64)
 * @param masterPassword - Owner's master password
 */
export async function rotateCollectionKey(
    collectionId: string,
    rsaPrivateKey: string,
    pqSecretKey: string,
    masterPassword: string
): Promise<void> {
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) throw new Error('Not authenticated');

    // 1. Load old wrapped key
    const { data: oldKeyData, error: oldKeyError } = await supabase
        .from('collection_keys')
        .select('wrapped_key, pq_wrapped_key')
        .eq('collection_id', collectionId)
        .eq('user_id', user.id)
        .single() as {
            data: { wrapped_key: string; pq_wrapped_key: string | null } | null;
            error: unknown;
        };

    if (oldKeyError || !oldKeyData) throw new Error('Collection key not found');

    // 2. Unwrap old key (Security Standard v1 hybrid path only)
    const oldSharedKey = await unwrapCollectionKey(
        oldKeyData.wrapped_key,
        oldKeyData.pq_wrapped_key,
        rsaPrivateKey,
        pqSecretKey,
        masterPassword,
    );

    // 3. Load all items
    const { data: items, error: itemsError } = await supabase
        .from('shared_collection_items')
        .select('*')
        .eq('collection_id', collectionId);

    if (itemsError) throw itemsError;

    // 4. Generate new shared key
    const newSharedKey = await generateSharedKey();

    // 5. Re-encrypt all items
    const reencryptedItems = await Promise.all(
        (items || []).map(async (item) => {
            const decrypted = await decryptWithSharedKey(item.encrypted_data, oldSharedKey, item.vault_item_id);
            const encrypted = await encryptWithSharedKey(decrypted, newSharedKey, item.vault_item_id);
            return {
                id: item.id,
                encrypted_data: encrypted,
            };
        })
    );

    // 6. Load all members (including owner)
    const { data: members, error: membersError } = await supabase
        .from('collection_keys')
        .select('user_id')
        .eq('collection_id', collectionId);

    if (membersError) throw membersError;

    // 7. Load RSA public keys for all members
    const { data: publicKeys, error: publicKeysError } = await supabase
        .from('user_keys')
        .select('user_id, public_key')
        .in('user_id', (members || []).map(m => m.user_id));

    if (publicKeysError) throw publicKeysError;

    // 8. Load PQ public keys for all members
    const { data: pqProfiles, error: pqProfilesError } = await supabase
        .from('profiles')
        .select('user_id, pq_public_key')
        .in('user_id', (members || []).map(m => m.user_id));

    if (pqProfilesError) throw pqProfilesError;

    const pqByUserId = new Map(
        (pqProfiles || []).map((profile) => [profile.user_id, profile.pq_public_key]),
    );

    // 9. Wrap new key for all members with hybrid encryption
    const newWrappedKeys = await Promise.all(
        (publicKeys || []).map(async (pk) => {
            const memberPqPublicKey = pqByUserId.get(pk.user_id);
            if (!memberPqPublicKey) {
                throw new Error('Security Standard v1 requires PQ key material for all collection members.');
            }

            const wrapped = await hybridWrapKey(newSharedKey, memberPqPublicKey, pk.public_key);
            return {
                collection_id: collectionId,
                user_id: pk.user_id,
                wrapped_key: wrapped,
                pq_wrapped_key: wrapped,
            };
        })
    );

    // 10. Update database atomically via server-side transaction
    const { error: rpcError } = await supabase.rpc('rotate_collection_key_atomic', {
        p_collection_id: collectionId,
        p_items: reencryptedItems.map(item => ({
            id: item.id,
            encrypted_data: item.encrypted_data,
        })),
        p_new_keys: newWrappedKeys,
    });

    if (rpcError) {
        console.error('Key rotation failed:', rpcError);
        throw new Error('Key rotation failed. Please try again.');
    }
}

// ============ Post-Quantum Encryption Helpers ============

/**
 * Creates a new collection with hybrid (PQ + RSA) key wrapping.
 * This provides quantum-resistant protection for shared data.
 * 
 * @param name - Collection name
 * @param description - Optional description
 * @param rsaPublicKey - Owner's RSA-4096 public key (JWK string)
 * @param pqPublicKey - Owner's ML-KEM-768 public key (base64)
 * @returns Collection ID
 */
export async function createCollectionWithHybridKey(
    name: string,
    description: string | null,
    rsaPublicKey: string,
    pqPublicKey: string
): Promise<string> {
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) throw new Error('Not authenticated');

    // 1. Create Collection
    const { data: collection, error: collectionError } = await supabase
        .from('shared_collections')
        .insert({ name, description, owner_id: user.id })
        .select()
        .single();

    if (collectionError) throw collectionError;

    try {
        // 2. Generate Shared Key
        const sharedKey = await generateSharedKey();

        // 3. Wrap Shared Key with hybrid encryption (PQ + RSA)
        const hybridWrappedKey = await hybridWrapKey(sharedKey, pqPublicKey, rsaPublicKey);

        // 4. Store hybrid ciphertext in both columns for strict v1 compatibility.
        // `wrapped_key` stays populated due current DB NOT NULL constraints.
        const { error: keyError } = await supabase
            .from('collection_keys')
            .insert({
                collection_id: collection.id,
                user_id: user.id,
                wrapped_key: hybridWrappedKey,
                pq_wrapped_key: hybridWrappedKey,
            });

        if (keyError) throw keyError;

        return collection.id;
    } catch (error) {
        // Rollback: Delete collection if key creation failed
        await supabase
            .from('shared_collections')
            .delete()
            .eq('id', collection.id);
        throw error;
    }
}

/**
 * Adds a member to a collection with hybrid key wrapping.
 * Both PQ and RSA keys are required for quantum-resistant sharing.
 * 
 * @param collectionId - Collection ID
 * @param userId - New member's user ID
 * @param permission - Member's permission level
 * @param memberRsaPublicKey - Member's RSA-4096 public key (JWK string)
 * @param memberPqPublicKey - Member's ML-KEM-768 public key (base64)
 * @param ownerPrivateKey - Owner's RSA-4096 private key for unwrapping
 * @param ownerPqSecretKey - Owner's ML-KEM-768 secret key for unwrapping
 * @param masterPassword - Owner's master password
 */
export async function addMemberWithHybridKey(
    collectionId: string,
    userId: string,
    permission: 'view' | 'edit',
    memberRsaPublicKey: string,
    memberPqPublicKey: string,
    ownerPrivateKey: string,
    ownerPqSecretKey: string,
    _masterPassword: string
): Promise<void> {
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) throw new Error('Not authenticated');

    // 1. Load owner's wrapped keys
    const { data: ownerKey, error: keyError } = await supabase
        .from('collection_keys')
        .select('wrapped_key, pq_wrapped_key')
        .eq('collection_id', collectionId)
        .eq('user_id', user.id)
        .single() as { data: { wrapped_key: string; pq_wrapped_key: string | null } | null; error: unknown };

    if (keyError || !ownerKey) throw new Error('Collection key not found');

    // 2. Unwrap shared key (Security Standard v1 requires hybrid key material)
    if (!ownerKey.pq_wrapped_key || !isHybridEncrypted(ownerKey.pq_wrapped_key)) {
        throw new Error(SECURITY_STANDARD_V1_ERROR);
    }

    const sharedKey = await hybridUnwrapKey(
        ownerKey.pq_wrapped_key,
        ownerPqSecretKey,
        ownerPrivateKey
    );

    // 3. Wrap for new member with hybrid encryption
    const hybridWrappedKey = await hybridWrapKey(sharedKey, memberPqPublicKey, memberRsaPublicKey);
    const rsaWrappedKey = hybridWrappedKey;

    // 4. Add Member
    const { error: memberError } = await supabase
        .from('shared_collection_members')
        .insert({
            collection_id: collectionId,
            user_id: userId,
            permission,
        });

    if (memberError) throw memberError;

    // 5. Store wrapped keys for member
    const { error: memberKeyError } = await supabase
        .from('collection_keys')
        .insert({
            collection_id: collectionId,
            user_id: userId,
            wrapped_key: rsaWrappedKey,
            pq_wrapped_key: hybridWrappedKey,
        } as any);

    if (memberKeyError) {
        // Rollback
        await supabase
            .from('shared_collection_members')
            .delete()
            .eq('collection_id', collectionId)
            .eq('user_id', userId);
        throw memberKeyError;
    }
}

/**
 * Checks if a collection uses post-quantum encryption.
 * 
 * @param collectionId - Collection ID
 * @returns true if PQ encryption is enabled for this collection
 */
export async function collectionUsesPQ(collectionId: string): Promise<boolean> {
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return false;

    const { data: keyData } = await supabase
        .from('collection_keys')
        .select('pq_wrapped_key')
        .eq('collection_id', collectionId)
        .eq('user_id', user.id)
        .single() as { data: { pq_wrapped_key: string | null } | null };

    return !!(keyData?.pq_wrapped_key && isHybridEncrypted(keyData.pq_wrapped_key));
}

/**
 * Unwraps a collection key using Security Standard v1 hybrid decryption.
 * 
 * @param wrappedKey - Legacy compatibility placeholder
 * @param pqWrappedKey - Hybrid-wrapped key (optional)
 * @param rsaPrivateKey - User's RSA private key
 * @param pqSecretKey - User's ML-KEM-768 secret key (required)
 * @param masterPassword - User's master password (unused, kept for API compatibility)
 * @returns Unwrapped shared key (JWK string)
 */
export async function unwrapCollectionKey(
    wrappedKey: string,
    pqWrappedKey: string | null | undefined,
    rsaPrivateKey: string,
    pqSecretKey: string | null | undefined,
    _masterPassword: string
): Promise<string> {
    if (pqWrappedKey && pqSecretKey && isHybridEncrypted(pqWrappedKey)) {
        return hybridUnwrapKey(pqWrappedKey, pqSecretKey, rsaPrivateKey);
    }

    if (wrappedKey && isHybridEncrypted(wrappedKey) && pqSecretKey) {
        return hybridUnwrapKey(wrappedKey, pqSecretKey, rsaPrivateKey);
    }

    throw new Error(SECURITY_STANDARD_V1_ERROR);
}
