// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { describe, expect, it } from 'vitest';

import { getHostname, normalizeProviderText, resolveBrandIconId } from './providerMatcher';

describe('providerMatcher', () => {
  it('normalizes provider text defensively', () => {
    expect(normalizeProviderText('  GitHub 2FA!!! ')).toBe('github 2fa');
    expect(normalizeProviderText('https://mail.google.com/login')).toContain('mail.google.com');
  });

  it('extracts hostnames without exposing dynamic icon paths', () => {
    expect(getHostname('github.com/login')).toBe('github.com');
    expect(getHostname('https://mail.google.com/mail/u/0')).toBe('mail.google.com');
    expect(getHostname('<svg onload=alert(1)>')).toBeNull();
  });

  it('prefers specific Google products over generic Google', () => {
    expect(resolveBrandIconId({ title: 'Google Gmail', websiteUrl: 'https://mail.google.com' })).toBe('gmail');
    expect(resolveBrandIconId({ title: 'Google Maps', websiteUrl: 'https://maps.google.com' })).toBe('google-maps');
    expect(resolveBrandIconId({ title: 'Google', websiteUrl: 'https://accounts.google.com' })).toBe('google');
  });

  it('matches common vault and authenticator providers', () => {
    expect(resolveBrandIconId({ title: 'GitHub 2FA', websiteUrl: 'https://github.com' })).toBe('github');
    expect(resolveBrandIconId({ issuer: 'AWS Root' })).toBe('aws');
    expect(resolveBrandIconId({ issuer: 'Stripe' })).toBe('stripe');
    expect(resolveBrandIconId({ issuer: 'Proton Mail' })).toBe('proton');
    expect(resolveBrandIconId({ issuer: 'Binance' })).toBe('binance');
    expect(resolveBrandIconId({ title: 'BMW ConnectedDrive', websiteUrl: 'https://bmw.de' })).toBe('bmw');
    expect(resolveBrandIconId({ title: 'McDonalds App' })).toBe('mcdonalds');
    expect(resolveBrandIconId({ title: 'Proton Drive', websiteUrl: 'https://drive.proton.me' })).toBe('proton-drive');
    expect(resolveBrandIconId({ title: 'OpenAI ChatGPT', websiteUrl: 'https://chatgpt.com' })).toBe('openai');
    expect(resolveBrandIconId({ title: 'Tinder Premium', websiteUrl: 'https://tinder.com' })).toBe('tinder');
    expect(resolveBrandIconId({ title: 'Only Fans Creator', websiteUrl: 'https://onlyfans.com' })).toBe('onlyfans');
    expect(resolveBrandIconId({ title: 'Pornhub 2FA', websiteUrl: 'https://www.pornhub.com' })).toBe('pornhub');
    expect(resolveBrandIconId({ title: 'GOG Games', websiteUrl: 'https://gog.com' })).toBe('gog');
    expect(resolveBrandIconId({ title: 'Riot' })).toBe('riotgames');
    expect(resolveBrandIconId({ title: 'Docker Desktop', websiteUrl: 'https://docker.com' })).toBe('docker');
    expect(resolveBrandIconId({ title: 'JetBrains Toolbox', websiteUrl: 'https://jetbrains.com' })).toBe('jetbrains');
    expect(resolveBrandIconId({ title: 'Epic Games Store', websiteUrl: 'https://epicgames.com' })).toBe('epicgames');
  });

  it('falls back for unknown providers', () => {
    expect(resolveBrandIconId({ title: 'Unknown Internal Tool' })).toBe('generic');
    expect(resolveBrandIconId({ title: 'Hytale Account' })).toBe('generic');
  });
});
