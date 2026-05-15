// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Vault Sidebar Types
 *
 * Local-only data shapes for the sidebar so the hooks and components do not
 * have to redeclare the small `Category` projection on every import.
 */

export interface Category {
  id: string;
  name: string;
  icon: string | null;
  color: string | null;
  count?: number;
}

export const ENCRYPTED_CATEGORY_PREFIX = 'enc:cat:v1:';
export const VAULT_ITEM_DRAG_MIME = 'application/x-singra-vault-item-id';

export function getDraggedVaultItemId(event: React.DragEvent): string {
  return event.dataTransfer.getData(VAULT_ITEM_DRAG_MIME) || event.dataTransfer.getData('text/plain');
}
