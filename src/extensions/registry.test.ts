import { beforeEach, describe, expect, it } from 'vitest';

import { clearRegistry, getExtension, hasExtension, isPremiumActive, registerExtension } from './registry';

describe('extension registry', () => {
  beforeEach(() => {
    clearRegistry();
  });

  it('starts without premium landing extensions', () => {
    expect(isPremiumActive()).toBe(false);
    expect(hasExtension('landing.after-hero')).toBe(false);
    expect(getExtension('landing.after-hero')).toBeNull();
  });

  it('marks premium as active once a landing extension is registered', () => {
    const StubComponent = () => null;

    registerExtension('landing.after-hero', StubComponent);

    expect(isPremiumActive()).toBe(true);
    expect(hasExtension('landing.after-hero')).toBe(true);
    expect(getExtension('landing.after-hero')).toBe(StubComponent);
  });
});
