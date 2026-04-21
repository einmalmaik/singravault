import { describe, expect, it } from 'vitest';

import {
  filterSettingsSections,
  getDefaultSettingsTab,
  isSettingsTabId,
  sortSettingsSections,
} from '@/services/settingsSectionService';

describe('settingsSectionService', () => {
  const sampleSections = [
    { title: 'Support', keywords: ['hilfe', 'ticket'], order: 20 },
    { title: 'Abonnement', keywords: ['billing', 'premium'], order: 10 },
  ];

  it('sorts sections by order and title', () => {
    expect(sortSettingsSections(sampleSections).map((section) => section.title)).toEqual([
      'Abonnement',
      'Support',
    ]);
  });

  it('filters by title and keywords', () => {
    expect(filterSettingsSections(sampleSections, 'premium')).toEqual([sampleSections[1]]);
    expect(filterSettingsSections(sampleSections, 'support')).toEqual([sampleSections[0]]);
    expect(filterSettingsSections(sampleSections, '')).toEqual(sampleSections);
  });

  it('validates tabs per surface', () => {
    expect(getDefaultSettingsTab('profile')).toBe('general');
    expect(getDefaultSettingsTab('vault')).toBe('security');
    expect(isSettingsTabId('data-legal', 'profile')).toBe(true);
    expect(isSettingsTabId('data-legal', 'vault')).toBe(false);
    expect(isSettingsTabId('data', 'vault')).toBe(true);
  });
});
