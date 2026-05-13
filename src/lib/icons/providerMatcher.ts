// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Controlled provider matching for vault and authenticator UI.
 *
 * This module never returns a user-controlled path or remote URL. It only
 * resolves user text and URLs to developer-approved registry IDs.
 */

export interface ProviderMatchInput {
  title?: string | null;
  websiteUrl?: string | null;
  issuer?: string | null;
  label?: string | null;
}

export interface ProviderMatcher {
  id: string;
  keywords: string[];
  hostnames?: string[];
}

const PROVIDER_MATCHERS: ProviderMatcher[] = [
  { id: 'gmail', keywords: ['gmail', 'google mail'], hostnames: ['gmail.com', 'mail.google.com'] },
  { id: 'google-maps', keywords: ['google maps', 'maps'], hostnames: ['maps.google.com'] },
  { id: 'google-drive', keywords: ['google drive', 'drive'], hostnames: ['drive.google.com'] },
  { id: 'google', keywords: ['google', 'accounts google'], hostnames: ['google.com', 'accounts.google.com'] },
  { id: '1password', keywords: ['1password', 'one password'], hostnames: ['1password.com'] },
  { id: 'bitwarden', keywords: ['bitwarden'], hostnames: ['bitwarden.com'] },
  { id: 'lastpass', keywords: ['lastpass', 'last pass'], hostnames: ['lastpass.com'] },
  { id: 'yubico', keywords: ['yubico', 'yubikey'], hostnames: ['yubico.com'] },
  { id: 'auth0', keywords: ['auth0'], hostnames: ['auth0.com'] },
  { id: 'github', keywords: ['github', 'github 2fa'], hostnames: ['github.com'] },
  { id: 'gitlab', keywords: ['gitlab'], hostnames: ['gitlab.com'] },
  { id: 'bitbucket', keywords: ['bitbucket'], hostnames: ['bitbucket.org'] },
  { id: 'discord', keywords: ['discord'], hostnames: ['discord.com', 'discordapp.com'] },
  { id: 'slack', keywords: ['slack'], hostnames: ['slack.com'] },
  { id: 'aws', keywords: ['aws', 'amazon web services'], hostnames: ['aws.amazon.com', 'console.aws.amazon.com'] },
  { id: 'azure', keywords: ['azure', 'microsoft azure'], hostnames: ['portal.azure.com', 'azure.microsoft.com'] },
  { id: 'cloudflare', keywords: ['cloudflare'], hostnames: ['cloudflare.com', 'dash.cloudflare.com'] },
  { id: 'digitalocean', keywords: ['digitalocean', 'digital ocean'], hostnames: ['digitalocean.com', 'cloud.digitalocean.com'] },
  { id: 'notion', keywords: ['notion'], hostnames: ['notion.so'] },
  { id: 'figma', keywords: ['figma'], hostnames: ['figma.com'] },
  { id: 'stripe', keywords: ['stripe'], hostnames: ['stripe.com', 'dashboard.stripe.com'] },
  { id: 'visa', keywords: ['visa'], hostnames: ['visa.com'] },
  { id: 'mastercard', keywords: ['mastercard', 'master card'], hostnames: ['mastercard.com'] },
  { id: 'americanexpress', keywords: ['american express', 'amex'], hostnames: ['americanexpress.com'] },
  { id: 'paypal', keywords: ['paypal'], hostnames: ['paypal.com'] },
  { id: 'revolut', keywords: ['revolut'], hostnames: ['revolut.com'] },
  { id: 'wise', keywords: ['wise', 'transferwise'], hostnames: ['wise.com'] },
  { id: 'chase', keywords: ['chase'], hostnames: ['chase.com'] },
  { id: 'bankofamerica', keywords: ['bank of america', 'bofa'], hostnames: ['bankofamerica.com'] },
  { id: 'wellsfargo', keywords: ['wells fargo'], hostnames: ['wellsfargo.com'] },
  { id: 'proton-drive', keywords: ['proton drive'], hostnames: ['drive.proton.me'] },
  { id: 'proton', keywords: ['proton', 'proton mail', 'protonmail'], hostnames: ['proton.me', 'protonmail.com'] },
  { id: 'binance', keywords: ['binance'], hostnames: ['binance.com'] },
  { id: 'microsoft', keywords: ['microsoft', 'office', 'outlook'], hostnames: ['microsoft.com', 'office.com', 'outlook.live.com'] },
  { id: 'apple', keywords: ['apple', 'icloud'], hostnames: ['apple.com', 'icloud.com'] },
  { id: 'dropbox', keywords: ['dropbox'], hostnames: ['dropbox.com'] },
  { id: 'docker', keywords: ['docker'], hostnames: ['docker.com', 'hub.docker.com'] },
  { id: 'kubernetes', keywords: ['kubernetes', 'k8s'] },
  { id: 'postgresql', keywords: ['postgres', 'postgresql'] },
  { id: 'mongodb', keywords: ['mongodb', 'mongo'], hostnames: ['mongodb.com'] },
  { id: 'reddit', keywords: ['reddit'], hostnames: ['reddit.com'] },
  { id: 'x', keywords: ['twitter', 'x.com'], hostnames: ['x.com', 'twitter.com'] },
  { id: 'linkedin', keywords: ['linkedin'], hostnames: ['linkedin.com'] },
  { id: 'facebook', keywords: ['facebook', 'meta'], hostnames: ['facebook.com', 'meta.com'] },
  { id: 'instagram', keywords: ['instagram'], hostnames: ['instagram.com'] },
  { id: 'youtube', keywords: ['youtube'], hostnames: ['youtube.com'] },
  { id: 'netflix', keywords: ['netflix'], hostnames: ['netflix.com'] },
  { id: 'spotify', keywords: ['spotify'], hostnames: ['spotify.com'] },
  { id: 'tiktok', keywords: ['tiktok', 'tik tok'], hostnames: ['tiktok.com'] },
  { id: 'snapchat', keywords: ['snapchat'], hostnames: ['snapchat.com'] },
  { id: 'twitch', keywords: ['twitch'], hostnames: ['twitch.tv'] },
  { id: 'telegram', keywords: ['telegram'], hostnames: ['telegram.org', 't.me'] },
  { id: 'whatsapp', keywords: ['whatsapp', 'whats app'], hostnames: ['whatsapp.com'] },
  { id: 'steam', keywords: ['steam'], hostnames: ['steampowered.com', 'steamcommunity.com'] },
  { id: 'playstation', keywords: ['playstation', 'psn'], hostnames: ['playstation.com'] },
  { id: 'epicgames', keywords: ['epic games', 'epicgames'], hostnames: ['epicgames.com'] },
  { id: 'roblox', keywords: ['roblox'], hostnames: ['roblox.com'] },
  { id: 'shopify', keywords: ['shopify'], hostnames: ['shopify.com'] },
  { id: 'amazon', keywords: ['amazon'], hostnames: ['amazon.com', 'amazon.de'] },
  { id: 'ebay', keywords: ['ebay', 'e bay'], hostnames: ['ebay.com', 'ebay.de'] },
  { id: 'wordpress', keywords: ['wordpress'], hostnames: ['wordpress.com', 'wordpress.org'] },
  { id: 'wix', keywords: ['wix'], hostnames: ['wix.com'] },
  { id: 'webflow', keywords: ['webflow'], hostnames: ['webflow.com'] },
  { id: 'vercel', keywords: ['vercel'], hostnames: ['vercel.com'] },
  { id: 'netlify', keywords: ['netlify'], hostnames: ['netlify.com'] },
  { id: 'linear', keywords: ['linear'], hostnames: ['linear.app'] },
  { id: 'jira', keywords: ['jira', 'atlassian jira'], hostnames: ['atlassian.net'] },
  { id: 'confluence', keywords: ['confluence'], hostnames: ['confluence.atlassian.com'] },
  { id: 'trello', keywords: ['trello'], hostnames: ['trello.com'] },
  { id: 'asana', keywords: ['asana'], hostnames: ['asana.com'] },
  { id: 'mailchimp', keywords: ['mailchimp'], hostnames: ['mailchimp.com'] },
  { id: 'zoom', keywords: ['zoom'], hostnames: ['zoom.us'] },
  { id: 'airbnb', keywords: ['airbnb', 'air bnb'], hostnames: ['airbnb.com'] },
  { id: 'booking', keywords: ['booking.com', 'booking'], hostnames: ['booking.com'] },
  { id: 'uber', keywords: ['uber'], hostnames: ['uber.com'] },
  { id: 'adobe', keywords: ['adobe'], hostnames: ['adobe.com'] },
  { id: 'canva', keywords: ['canva'], hostnames: ['canva.com'] },
  { id: 'openai', keywords: ['openai', 'chatgpt', 'chat gpt'], hostnames: ['openai.com', 'chatgpt.com'] },
  { id: 'anthropic', keywords: ['anthropic', 'claude'], hostnames: ['anthropic.com', 'claude.ai'] },
  { id: 'bmw', keywords: ['bmw'], hostnames: ['bmw.com', 'bmw.de'] },
  { id: 'mcdonalds', keywords: ['mcdonalds', "mcdonald's", 'mcdonald'], hostnames: ['mcdonalds.com', 'mcdonalds.de'] },
  { id: 'burgerking', keywords: ['burger king', 'burgerking'], hostnames: ['burgerking.com'] },
  { id: 'tesla', keywords: ['tesla'], hostnames: ['tesla.com'] },
  { id: 'toyota', keywords: ['toyota'], hostnames: ['toyota.com'] },
  { id: 'volkswagen', keywords: ['volkswagen', 'vw'], hostnames: ['volkswagen.com', 'vw.com'] },
  { id: 'audi', keywords: ['audi'], hostnames: ['audi.com'] },
  { id: 'zendesk', keywords: ['zendesk'], hostnames: ['zendesk.com'] },
  { id: 'intercom', keywords: ['intercom'], hostnames: ['intercom.com'] },
  { id: 'hubspot', keywords: ['hubspot'], hostnames: ['hubspot.com'] },
  { id: 'calendly', keywords: ['calendly'], hostnames: ['calendly.com'] },
  { id: 'todoist', keywords: ['todoist'], hostnames: ['todoist.com'] },
  { id: 'cloudinary', keywords: ['cloudinary'], hostnames: ['cloudinary.com'] },
  { id: 'supabase', keywords: ['supabase'], hostnames: ['supabase.com'] },
  { id: 'firebase', keywords: ['firebase'], hostnames: ['firebase.google.com'] },
  { id: 'ubuntu', keywords: ['ubuntu'], hostnames: ['ubuntu.com'] },
  { id: 'linux', keywords: ['linux'], hostnames: ['kernel.org'] },
  { id: 'duolingo', keywords: ['duolingo'], hostnames: ['duolingo.com'] },
  { id: 'coursera', keywords: ['coursera'], hostnames: ['coursera.org'] },
  { id: 'udemy', keywords: ['udemy'], hostnames: ['udemy.com'] },
  { id: 'deepl', keywords: ['deepl', 'deep l'], hostnames: ['deepl.com'] },
];

export function normalizeProviderText(value: string | null | undefined): string {
  return (value ?? '')
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/https?:\/\//g, ' ')
    .replace(/[^a-z0-9.]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

export function getHostname(value: string | null | undefined): string | null {
  const raw = value?.trim();
  if (!raw) {
    return null;
  }

  try {
    return new URL(raw.includes('://') ? raw : `https://${raw}`).hostname.toLowerCase().replace(/^www\./, '');
  } catch {
    return null;
  }
}

export function resolveBrandIconId(input: ProviderMatchInput): string {
  const hostname = getHostname(input.websiteUrl);
  const text = normalizeProviderText([
    input.title,
    input.issuer,
    input.label,
    hostname,
  ].filter(Boolean).join(' '));

  for (const matcher of PROVIDER_MATCHERS) {
    if (hostname && matcher.hostnames?.some((candidate) => hostname === candidate || hostname.endsWith(`.${candidate}`))) {
      return matcher.id;
    }
  }

  for (const matcher of PROVIDER_MATCHERS) {
    if (matcher.keywords.some((keyword) => text.includes(normalizeProviderText(keyword)))) {
      return matcher.id;
    }
  }

  return 'generic';
}

export const providerMatchersForTests = PROVIDER_MATCHERS;
