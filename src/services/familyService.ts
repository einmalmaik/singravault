// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
import { supabase } from '@/integrations/supabase/client';
import { invokeAuthedFunction } from '@/services/edgeFunctionService';

export interface FamilyMember {
  id: string;
  family_owner_id: string;
  member_email: string;
  member_user_id: string | null;
  role: string;
  status: string;
  invited_at: string;
  joined_at: string | null;
}

export interface SharedCollection {
  id: string;
  owner_id: string;
  name: string;
  description: string | null;
  created_at: string;
  updated_at: string;
}

export async function getFamilyMembers(ownerId: string): Promise<FamilyMember[]> {
  const { data, error } = await supabase
    .from('family_members')
    .select('*')
    .eq('family_owner_id', ownerId)
    .order('invited_at', { ascending: false });

  if (error) throw error;
  return (data || []) as FamilyMember[];
}

export async function inviteFamilyMember(_ownerId: string, email: string): Promise<void> {
  await invokeAuthedFunction('invite-family-member', { email });
}

export async function removeFamilyMember(id: string): Promise<void> {
  const { error } = await supabase.from('family_members').delete().eq('id', id);
  if (error) throw error;
}

export async function getSharedCollections(ownerId: string): Promise<SharedCollection[]> {
  const { data, error } = await supabase
    .from('shared_collections')
    .select('*')
    .eq('owner_id', ownerId)
    .order('created_at', { ascending: false });

  if (error) throw error;
  return (data || []) as SharedCollection[];
}

export async function createSharedCollection(ownerId: string, name: string, description?: string): Promise<void> {
  const { error } = await supabase
    .from('shared_collections')
    .insert({ owner_id: ownerId, name, description: description || null });

  if (error) throw error;
}

export async function deleteSharedCollection(id: string): Promise<void> {
  const { error } = await supabase.from('shared_collections').delete().eq('id', id);
  if (error) throw error;
}

// =====================================================
// FAMILY INVITATION MANAGEMENT
// =====================================================

/**
 * Get pending family invitations for the current user
 * @returns Array of pending invitations
 */
export async function getPendingInvitations(): Promise<FamilyMember[]> {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return [];

  const { data, error } = await supabase
    .from('family_members')
    .select('*')
    .eq('member_email', user.email)
    .eq('status', 'invited')
    .order('invited_at', { ascending: false });

  if (error) throw error;
  return (data || []) as FamilyMember[];
}

/**
 * Accept a family invitation
 * @param invitationId - ID of the invitation to accept
 */
export async function acceptFamilyInvitation(invitationId: string): Promise<void> {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) throw new Error('Not authenticated');

  const { error } = await supabase
    .from('family_members')
    .update({
      member_user_id: user.id,
      status: 'active',
      joined_at: new Date().toISOString(),
    })
    .eq('id', invitationId)
    .eq('member_email', user.email)
    .eq('status', 'invited');

  if (error) throw error;
}

/**
 * Decline a family invitation
 * @param invitationId - ID of the invitation to decline
 */
export async function declineFamilyInvitation(invitationId: string): Promise<void> {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) throw new Error('Not authenticated');

  const { error } = await supabase
    .from('family_members')
    .delete()
    .eq('id', invitationId)
    .eq('member_email', user.email)
    .eq('status', 'invited');

  if (error) throw error;
}
