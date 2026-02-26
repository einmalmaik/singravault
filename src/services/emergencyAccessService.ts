// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
import { supabase } from "@/integrations/supabase/client";
import { invokeAuthedFunction } from '@/services/edgeFunctionService';
import {
    hybridEncrypt,
    hybridDecrypt,
    isHybridEncrypted
} from './pqCryptoService';

interface ProfileRow {
    user_id: string;
    display_name: string | null;
    avatar_url: string | null;
}

export interface EmergencyAccess {
    id: string;
    grantor_id: string;
    trusted_email: string;
    trusted_user_id: string | null;
    status: 'invited' | 'accepted' | 'pending' | 'granted' | 'rejected' | 'expired';
    wait_days: number;
    requested_at: string | null;
    granted_at: string | null;
    created_at: string;
    trustee_public_key: string | null;
    encrypted_master_key: string | null;
    // Post-quantum fields
    trustee_pq_public_key?: string | null;
    pq_encrypted_master_key?: string | null;
    grantor?: {
        display_name: string | null;
        avatar_url: string | null;
    };
    trustee?: {
        display_name: string | null;
        avatar_url: string | null;
    };
}

export const emergencyAccessService = {
    // Get people who I trust (I am the grantor)
    async getTrustees() {
        const { data: userData } = await supabase.auth.getUser();
        if (!userData.user) return [];

        const { data, error } = await supabase
            .from('emergency_access')
            .select('*')
            .eq('grantor_id', userData.user.id)
            .order('created_at', { ascending: false });

        if (error) throw error;

        const rows = (data || []) as unknown as EmergencyAccess[];
        const trustedIds = Array.from(new Set(rows.map(r => r.trusted_user_id).filter(Boolean))) as string[];

        let profileMap = new Map<string, { display_name: string | null; avatar_url: string | null }>();
        if (trustedIds.length > 0) {
            const { data: profiles } = await supabase
                .from('profiles')
                .select('user_id, display_name, avatar_url')
                .in('user_id', trustedIds);

            profileMap = new Map(((profiles || []) as ProfileRow[]).map((p) => [p.user_id, {
                display_name: p.display_name,
                avatar_url: p.avatar_url,
            }]));
        }

        return rows.map(row => ({
            ...row,
            trustee: row.trusted_user_id ? profileMap.get(row.trusted_user_id) : undefined,
        }));
    },

    // Get people who trust me (I am the trustee)
    async getGrantors() {
        const { data: userData } = await supabase.auth.getUser();
        if (!userData.user?.email) return [];

        const { data, error } = await supabase
            .from('emergency_access')
            .select('*')
            .or(`trusted_user_id.eq.${userData.user.id},trusted_email.eq.${userData.user.email}`)
            .order('created_at', { ascending: false });

        if (error) throw error;

        const rows = (data || []) as unknown as EmergencyAccess[];
        const grantorIds = Array.from(new Set(rows.map(r => r.grantor_id).filter(Boolean))) as string[];

        let profileMap = new Map<string, { display_name: string | null; avatar_url: string | null }>();
        if (grantorIds.length > 0) {
            const { data: profiles } = await supabase
                .from('profiles')
                .select('user_id, display_name, avatar_url')
                .in('user_id', grantorIds);

            profileMap = new Map(((profiles || []) as ProfileRow[]).map((p) => [p.user_id, {
                display_name: p.display_name,
                avatar_url: p.avatar_url,
            }]));
        }

        return rows.map(row => ({
            ...row,
            grantor: profileMap.get(row.grantor_id),
        }));
    },

    // Invite someone to be my trustee
    async inviteTrustee(email: string, waitDays: number) {
        await invokeAuthedFunction('invite-emergency-access', {
            email,
            wait_days: waitDays,
        });
        return {
            id: '',
            grantor_id: '',
            trusted_email: email,
            trusted_user_id: null,
            status: 'invited',
            wait_days: waitDays,
            requested_at: null,
            granted_at: null,
            created_at: new Date().toISOString(),
            trustee_public_key: null,
            encrypted_master_key: null,
            trustee_pq_public_key: null,
            pq_encrypted_master_key: null,
        } as EmergencyAccess;
    },

    // Revoke access (delete invite or remove trustee)
    async revokeAccess(id: string) {
        const { error } = await supabase
            .from('emergency_access')
            .delete()
            .eq('id', id);

        if (error) throw error;
    },

    // Request access (as trustee) - starts the timer
    async requestAccess(accessId: string) {
        const { data, error } = await supabase
            .from('emergency_access')
            .update({
                status: 'pending',
                requested_at: new Date().toISOString()
            })
            .eq('id', accessId)
            .select()
            .single();

        if (error) throw error;
        return data as unknown as EmergencyAccess;
    },

    // Reject access request (as grantor) — setzt Status auf 'rejected' und löscht den Timer
    async rejectAccess(accessId: string) {
        const { data, error } = await supabase
            .from('emergency_access')
            .update({
                status: 'rejected',
                requested_at: null
            })
            .eq('id', accessId)
            .select()
            .single();

        if (error) throw error;
        return data as unknown as EmergencyAccess;
    },

    // Grant access immediately (as grantor)
    async approveAccess(accessId: string) {
        const { data, error } = await supabase
            .from('emergency_access')
            .update({
                status: 'granted',
                granted_at: new Date().toISOString()
            })
            .eq('id', accessId)
            .select()
            .single();

        if (error) throw error;
        return data as unknown as EmergencyAccess;
    },

    // ============ Post-Quantum Encryption Methods ============

    /**
     * Accept invitation with post-quantum keys (as trustee).
     * Generates both RSA and ML-KEM-768 keys for hybrid encryption.
     * 
     * @param accessId - Emergency access record ID
     * @param rsaPublicKeyJwk - RSA-4096 public key (JWK string)
     * @param pqPublicKey - ML-KEM-768 public key (base64)
     * @returns Updated EmergencyAccess record
     */
    async acceptInviteWithPQ(
        accessId: string,
        rsaPublicKeyJwk: string,
        pqPublicKey: string
    ) {
        const { data: userData } = await supabase.auth.getUser();
        if (!userData.user) throw new Error("Not authenticated");

        const { data, error } = await supabase
            .from('emergency_access')
            .update({
                status: 'accepted',
                trusted_user_id: userData.user.id,
                trustee_public_key: rsaPublicKeyJwk,
                trustee_pq_public_key: pqPublicKey
            } as Record<string, unknown>)
            .eq('id', accessId)
            .select()
            .single();

        if (error) throw error;
        return data as unknown as EmergencyAccess;
    },

    /**
     * Set encrypted master key with hybrid encryption (as grantor).
     * Uses both RSA-4096 and ML-KEM-768 for quantum-resistant encryption.
     * 
     * @param accessId - Emergency access record ID
     * @param masterKey - Raw master key to encrypt
     * @param trusteePqPublicKey - Trustee's ML-KEM-768 public key (base64)
     * @param trusteeRsaPublicKey - Trustee's RSA-4096 public key (JWK string)
     */
    async setHybridEncryptedMasterKey(
        accessId: string,
        masterKey: string,
        trusteePqPublicKey: string,
        trusteeRsaPublicKey: string
    ) {
        // Encrypt with hybrid scheme (ML-KEM-768 + RSA-4096)
        const hybridCiphertext = await hybridEncrypt(
            masterKey,
            trusteePqPublicKey,
            trusteeRsaPublicKey
        );

        const { error } = await supabase
            .from('emergency_access')
            .update({
                encrypted_master_key: null,
                pq_encrypted_master_key: hybridCiphertext,
                updated_at: new Date().toISOString()
            } as Record<string, unknown>)
            .eq('id', accessId);

        if (error) throw error;
    },

    /**
     * Decrypt master key using hybrid decryption (as trustee).
     * Requires both RSA and ML-KEM-768 private keys.
     * 
     * @param pqEncryptedMasterKey - Hybrid encrypted master key
     * @param pqSecretKey - Trustee's ML-KEM-768 secret key (base64)
     * @param rsaPrivateKey - Trustee's RSA-4096 private key (JWK string)
     * @returns Decrypted master key
     */
    async decryptHybridMasterKey(
        pqEncryptedMasterKey: string,
        pqSecretKey: string,
        rsaPrivateKey: string
    ): Promise<string> {
        return hybridDecrypt(
            pqEncryptedMasterKey,
            pqSecretKey,
            rsaPrivateKey
        );
    },

    /**
     * Check if an emergency access record uses post-quantum encryption.
     * 
     * @param access - EmergencyAccess record
     * @returns true if PQ encryption is enabled
     */
    hasPQEncryption(access: EmergencyAccess): boolean {
        return !!(
            access.trustee_pq_public_key &&
            access.pq_encrypted_master_key &&
            isHybridEncrypted(access.pq_encrypted_master_key)
        );
    },

    /**
     * Check if a ciphertext uses hybrid encryption format.
     */
    isHybridEncrypted
};
