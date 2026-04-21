import type { SettingsSurface, SettingsTabId } from '@/extensions/types';

export const SETTINGS_TABS_BY_SURFACE: Record<SettingsSurface, SettingsTabId[]> = {
  profile: ['general', 'security', 'billing-support', 'data-legal'],
  vault: ['security', 'data', 'sharing-emergency'],
};

export function getDefaultSettingsTab(surface: SettingsSurface): SettingsTabId {
  return SETTINGS_TABS_BY_SURFACE[surface][0];
}

export function isSettingsTabId(
  value: string | null,
  surface: SettingsSurface,
): value is SettingsTabId {
  return value !== null && SETTINGS_TABS_BY_SURFACE[surface].includes(value as SettingsTabId);
}

export function filterSettingsSections<T extends { title: string; keywords: string[] }>(
  sections: T[],
  query: string,
): T[] {
  const normalizedQuery = query.trim().toLowerCase();
  if (!normalizedQuery) {
    return sections;
  }

  return sections.filter((section) => {
    if (section.title.toLowerCase().includes(normalizedQuery)) {
      return true;
    }

    return section.keywords.some((keyword) => keyword.toLowerCase().includes(normalizedQuery));
  });
}

export function sortSettingsSections<T extends { order: number; title: string }>(sections: T[]): T[] {
  return [...sections].sort((left, right) => {
    if (left.order !== right.order) {
      return left.order - right.order;
    }

    return left.title.localeCompare(right.title);
  });
}
