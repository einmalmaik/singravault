// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Sidebar Category List
 *
 * Renders the scrollable categories block: header with "+" button, empty
 * state CTA, and the per-category rows with their hover action menu and
 * drag-and-drop target for moving items.
 *
 * The drag handlers own the local `dropTargetCategoryId` highlight; the
 * actual write is delegated to the parent through `onCategoryDrop`.
 */

import { useCallback, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Folder,
  MoreHorizontal,
  Pencil,
  Plus,
  Trash2,
} from 'lucide-react';

import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { cn } from '@/lib/utils';

import { CategoryIcon } from '../CategoryIcon';
import { VaultSidebarItem } from './VaultSidebarItem';
import type { Category } from './vaultSidebarTypes';
import { getDraggedVaultItemId } from './vaultSidebarTypes';

interface VaultSidebarCategoryListProps {
  readonly collapsed: boolean;
  readonly loading: boolean;
  readonly categories: readonly Category[];
  readonly selectedCategory: string | null;
  readonly onAddCategory: () => void;
  readonly onSelectCategory: (categoryId: string) => void;
  readonly onEditCategory: (category: Category) => void;
  readonly onDeleteCategory: (category: Category) => void;
  readonly onCategoryDrop: (categoryId: string, itemId: string) => void;
}

export function VaultSidebarCategoryList({
  collapsed,
  loading,
  categories,
  selectedCategory,
  onAddCategory,
  onSelectCategory,
  onEditCategory,
  onDeleteCategory,
  onCategoryDrop,
}: VaultSidebarCategoryListProps) {
  const { t } = useTranslation();
  const [dropTargetCategoryId, setDropTargetCategoryId] = useState<string | null>(null);

  // A drop event fires the underlying click handler too. Without this short
  // grace window the freshly-targeted category would also be selected, which
  // confuses the user who only intended to move the item.
  const suppressedCategorySelectRef = useRef<{ categoryId: string; until: number } | null>(null);

  const consumeSuppressedCategorySelect = useCallback((categoryId: string): boolean => {
    const suppressed = suppressedCategorySelectRef.current;
    if (!suppressed) {
      return false;
    }
    if (suppressed.until < Date.now()) {
      suppressedCategorySelectRef.current = null;
      return false;
    }
    if (suppressed.categoryId !== categoryId) {
      return false;
    }
    suppressedCategorySelectRef.current = null;
    return true;
  }, []);

  return (
    <ScrollArea className="flex-1 p-2">
      <div className="space-y-1">
        {!collapsed && (
          <div className="flex items-center justify-between px-2 py-1.5">
            <span className="text-xs font-medium text-muted-foreground uppercase">
              {t('vault.sidebar.categories')}
            </span>
            <Button
              variant="ghost"
              size="icon"
              className="h-10 w-10 lg:h-8 lg:w-8"
              onClick={onAddCategory}
            >
              <Plus className="w-3 h-3" />
            </Button>
          </div>
        )}

        {loading ? (
          <div className="px-3 py-2 text-sm text-muted-foreground">
            {t('common.loading')}...
          </div>
        ) : categories.length === 0 ? (
          !collapsed && (
            <div className="px-3 py-4 text-center">
              <Folder className="w-8 h-8 mx-auto mb-2 text-muted-foreground" />
              <p className="text-sm text-muted-foreground">
                {t('categories.empty')}
              </p>
              <Button
                variant="link"
                size="sm"
                onClick={onAddCategory}
                className="mt-1"
              >
                {t('categories.addFirst')}
              </Button>
            </div>
          )
        ) : (
          categories.map((category) => (
            <CategoryRow
              key={category.id}
              category={category}
              collapsed={collapsed}
              active={selectedCategory === category.id}
              isDropTarget={dropTargetCategoryId === category.id}
              onSelect={() => {
                if (consumeSuppressedCategorySelect(category.id)) {
                  return;
                }
                onSelectCategory(category.id);
              }}
              onEdit={() => onEditCategory(category)}
              onDelete={() => onDeleteCategory(category)}
              onDragEnterTarget={() => setDropTargetCategoryId(category.id)}
              onDragLeaveTarget={() => setDropTargetCategoryId((current) => (
                current === category.id ? null : current
              ))}
              onDropTarget={(itemId) => {
                suppressedCategorySelectRef.current = {
                  categoryId: category.id,
                  until: Date.now() + 500,
                };
                setDropTargetCategoryId(null);
                onCategoryDrop(category.id, itemId);
              }}
            />
          ))
        )}
      </div>
    </ScrollArea>
  );
}

interface CategoryRowProps {
  readonly category: Category;
  readonly collapsed: boolean;
  readonly active: boolean;
  readonly isDropTarget: boolean;
  readonly onSelect: () => void;
  readonly onEdit: () => void;
  readonly onDelete: () => void;
  readonly onDragEnterTarget: () => void;
  readonly onDragLeaveTarget: () => void;
  readonly onDropTarget: (itemId: string) => void;
}

function CategoryRow({
  category,
  collapsed,
  active,
  isDropTarget,
  onSelect,
  onEdit,
  onDelete,
  onDragEnterTarget,
  onDragLeaveTarget,
  onDropTarget,
}: CategoryRowProps) {
  const { t } = useTranslation();

  return (
    <div
      data-vault-category-drop-id={category.id}
      className={cn(
        'group relative rounded-lg',
        isDropTarget && 'ring-2 ring-primary/55',
      )}
      onDragEnter={(event) => {
        event.preventDefault();
        event.dataTransfer.dropEffect = 'move';
        onDragEnterTarget();
      }}
      onDragOver={(event) => {
        event.preventDefault();
        event.dataTransfer.dropEffect = 'move';
        onDragEnterTarget();
      }}
      onDragLeave={onDragLeaveTarget}
      onDrop={(event) => {
        event.preventDefault();
        event.stopPropagation();
        const itemId = getDraggedVaultItemId(event);
        if (!itemId) {
          onDragLeaveTarget();
          return;
        }
        onDropTarget(itemId);
      }}
    >
      <VaultSidebarItem
        icon={
          collapsed
            ? <Folder className="w-4 h-4" />
            : <CategoryIcon icon={category.icon} />
        }
        label={category.name}
        count={category.count}
        collapsed={collapsed}
        active={active}
        onClick={onSelect}
        color={category.color}
      />

      {!collapsed && (
        <div className="absolute right-2 top-1/2 -translate-y-1/2 opacity-100 transition-opacity lg:opacity-0 lg:group-hover:opacity-100 lg:focus-within:opacity-100">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" className="h-10 w-10 lg:h-8 lg:w-8">
                <MoreHorizontal className="w-3 h-3" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onClick={onEdit}>
                <Pencil className="w-4 h-4 mr-2" />
                {t('common.edit')}
              </DropdownMenuItem>
              <DropdownMenuItem
                className="text-destructive focus:text-destructive"
                onClick={onDelete}
              >
                <Trash2 className="w-4 h-4 mr-2" />
                {t('common.delete')}
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      )}
    </div>
  );
}
