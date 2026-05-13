// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Developer-controlled provider icon registry.
 *
 * Brand SVGs are served from the reviewed Simple Icons subset in
 * public/icons/brands. There are no runtime downloads from third parties and
 * no dynamic paths from user input. Lucide icons remain the fallback for
 * brands not bundled.
 */

import {
  AppWindow,
  BadgeDollarSign,
  Blocks,
  Bot,
  Boxes,
  Briefcase,
  BookOpen,
  Cloud,
  CloudCog,
  Code2,
  Container,
  CreditCard,
  Database,
  Figma,
  FileText,
  Film,
  Gamepad2,
  Github,
  GitFork,
  Globe,
  HardDrive,
  Home,
  Link as LinkIcon,
  Car,
  LockKeyhole,
  Mail,
  Map,
  MessageCircle,
  MessagesSquare,
  Music2,
  Network,
  NotebookTabs,
  PanelsTopLeft,
  RadioTower,
  Server,
  Shield,
  ShoppingBag,
  Store,
  Ticket,
  Tv,
  Users,
  Video,
  type LucideIcon,
} from 'lucide-react';

export interface BrandIconDefinition {
  id: string;
  label: string;
  accent: string;
  Icon: LucideIcon;
  svgSrc: string | null;
}

type BrandIconBaseDefinition = Omit<BrandIconDefinition, 'svgSrc'> & {
  simpleIconSlug?: string;
};

function simpleIconUrl(slug: string | undefined): string | null {
  if (!slug) {
    return null;
  }

  return `/icons/brands/${slug}.svg`;
}

function brand(
  id: string,
  label: string,
  accent: string,
  Icon: LucideIcon,
  simpleIconSlug: string | null = id,
): BrandIconBaseDefinition {
  return { id, label, accent, Icon, simpleIconSlug: simpleIconSlug ?? undefined };
}

const BRAND_ICON_BASE_REGISTRY: Record<string, BrandIconBaseDefinition> = {
  generic: brand('generic', 'Website', 'hsl(var(--accent))', Globe, null),
  google: brand('google', 'Google', '#8ab4f8', Globe),
  gmail: brand('gmail', 'Gmail', '#ea4335', Mail),
  'google-maps': brand('google-maps', 'Google Maps', '#34a853', Map, 'googlemaps'),
  'google-drive': brand('google-drive', 'Google Drive', '#fbbc04', HardDrive, 'googledrive'),
  github: brand('github', 'GitHub', '#ffffff', Github),
  gitlab: brand('gitlab', 'GitLab', '#fc6d26', GitFork),
  bitbucket: brand('bitbucket', 'Bitbucket', '#2684ff', GitFork),
  discord: brand('discord', 'Discord', '#5865f2', MessagesSquare),
  slack: brand('slack', 'Slack', '#36c5f0', MessageCircle, null),
  aws: brand('aws', 'AWS', '#ff9900', CloudCog, null),
  azure: brand('azure', 'Azure', '#3b82f6', Cloud, null),
  cloudflare: brand('cloudflare', 'Cloudflare', '#f97316', Cloud),
  digitalocean: brand('digitalocean', 'DigitalOcean', '#0080ff', Cloud),
  notion: brand('notion', 'Notion', '#f8fafc', NotebookTabs),
  figma: brand('figma', 'Figma', '#a259ff', Figma),
  stripe: brand('stripe', 'Stripe', '#635bff', CreditCard),
  paypal: brand('paypal', 'PayPal', '#0070ba', BadgeDollarSign),
  proton: brand('proton', 'Proton', '#6d4aff', Mail, 'protonmail'),
  'proton-drive': brand('proton-drive', 'Proton Drive', '#6d4aff', HardDrive, 'protondrive'),
  binance: brand('binance', 'Binance', '#f0b90b', BadgeDollarSign),
  microsoft: brand('microsoft', 'Microsoft', '#7fba00', AppWindow, null),
  apple: brand('apple', 'Apple', '#f8fafc', AppWindow),
  dropbox: brand('dropbox', 'Dropbox', '#0061ff', Boxes),
  docker: brand('docker', 'Docker', '#2496ed', Container),
  kubernetes: brand('kubernetes', 'Kubernetes', '#326ce5', Blocks),
  postgresql: brand('postgresql', 'PostgreSQL', '#336791', Database),
  mongodb: brand('mongodb', 'MongoDB', '#47a248', Database),
  reddit: brand('reddit', 'Reddit', '#ff4500', MessagesSquare),
  x: brand('x', 'X', '#f8fafc', RadioTower),
  linkedin: brand('linkedin', 'LinkedIn', '#0a66c2', Briefcase, null),
  facebook: brand('facebook', 'Facebook', '#1877f2', Users),
  instagram: brand('instagram', 'Instagram', '#e1306c', PanelsTopLeft),
  youtube: brand('youtube', 'YouTube', '#ff0000', Tv),
  netflix: brand('netflix', 'Netflix', '#e50914', Film),
  spotify: brand('spotify', 'Spotify', '#1db954', Music2),
  steam: brand('steam', 'Steam', '#66c0f4', Gamepad2),
  shopify: brand('shopify', 'Shopify', '#95bf47', ShoppingBag),
  wordpress: brand('wordpress', 'WordPress', '#21759b', FileText),
  vercel: brand('vercel', 'Vercel', '#f8fafc', Code2),
  netlify: brand('netlify', 'Netlify', '#00c7b7', Network),
  linear: brand('linear', 'Linear', '#5e6ad2', Ticket),
  jira: brand('jira', 'Jira', '#0052cc', Ticket),
  confluence: brand('confluence', 'Confluence', '#172b4d', FileText),
  trello: brand('trello', 'Trello', '#0079bf', PanelsTopLeft),
  asana: brand('asana', 'Asana', '#fc636b', Bot),
  mailchimp: brand('mailchimp', 'Mailchimp', '#ffe01b', Mail),
  zoom: brand('zoom', 'Zoom', '#2d8cff', Video),
  airbnb: brand('airbnb', 'Airbnb', '#ff5a5f', Home),
  booking: brand('booking', 'Booking.com', '#003b95', Ticket, 'bookingdotcom'),
  uber: brand('uber', 'Uber', '#f8fafc', Car),
  tiktok: brand('tiktok', 'TikTok', '#00f2ea', Video),
  snapchat: brand('snapchat', 'Snapchat', '#fffc00', MessageCircle),
  twitch: brand('twitch', 'Twitch', '#9146ff', Tv),
  telegram: brand('telegram', 'Telegram', '#26a5e4', MessageCircle),
  whatsapp: brand('whatsapp', 'WhatsApp', '#25d366', MessageCircle),
  amazon: brand('amazon', 'Amazon', '#ff9900', ShoppingBag, null),
  ebay: brand('ebay', 'eBay', '#e53238', ShoppingBag),
  adobe: brand('adobe', 'Adobe', '#ff0000', AppWindow, null),
  canva: brand('canva', 'Canva', '#00c4cc', Figma, null),
  openai: brand('openai', 'OpenAI', '#f8fafc', Bot, null),
  anthropic: brand('anthropic', 'Anthropic', '#d4a373', Bot),
  bmw: brand('bmw', 'BMW', '#0066b1', Store),
  mcdonalds: brand('mcdonalds', 'McDonald’s', '#ffbc0d', Store),
  burgerking: brand('burgerking', 'Burger King', '#d62300', Store),
  visa: brand('visa', 'Visa', '#1a1f71', CreditCard),
  mastercard: brand('mastercard', 'Mastercard', '#eb001b', CreditCard),
  americanexpress: brand('americanexpress', 'American Express', '#2e77bc', CreditCard),
  revolut: brand('revolut', 'Revolut', '#f8fafc', CreditCard),
  wise: brand('wise', 'Wise', '#9fe870', BadgeDollarSign),
  chase: brand('chase', 'Chase', '#005eb8', BadgeDollarSign),
  bankofamerica: brand('bankofamerica', 'Bank of America', '#e31837', BadgeDollarSign),
  wellsfargo: brand('wellsfargo', 'Wells Fargo', '#d71e28', BadgeDollarSign),
  tesla: brand('tesla', 'Tesla', '#cc0000', Store),
  toyota: brand('toyota', 'Toyota', '#eb0a1e', Store),
  volkswagen: brand('volkswagen', 'Volkswagen', '#001e50', Store),
  audi: brand('audi', 'Audi', '#f8fafc', Store),
  wix: brand('wix', 'Wix', '#0c6efc', PanelsTopLeft),
  webflow: brand('webflow', 'Webflow', '#146ef5', PanelsTopLeft),
  zendesk: brand('zendesk', 'Zendesk', '#03363d', Ticket),
  intercom: brand('intercom', 'Intercom', '#1f8ded', MessageCircle),
  hubspot: brand('hubspot', 'HubSpot', '#ff7a59', Briefcase),
  calendly: brand('calendly', 'Calendly', '#006bff', Ticket),
  todoist: brand('todoist', 'Todoist', '#e44332', Ticket),
  '1password': brand('1password', '1Password', '#0094f5', LockKeyhole),
  bitwarden: brand('bitwarden', 'Bitwarden', '#175ddc', LockKeyhole),
  lastpass: brand('lastpass', 'LastPass', '#d32d27', LockKeyhole),
  yubico: brand('yubico', 'Yubico', '#84bd00', Shield),
  auth0: brand('auth0', 'Auth0', '#eb5424', Shield),
  cloudinary: brand('cloudinary', 'Cloudinary', '#3448c5', Cloud),
  supabase: brand('supabase', 'Supabase', '#3ecf8e', Database),
  firebase: brand('firebase', 'Firebase', '#ffca28', Database),
  ubuntu: brand('ubuntu', 'Ubuntu', '#e95420', Server),
  linux: brand('linux', 'Linux', '#f8fafc', Server),
  playstation: brand('playstation', 'PlayStation', '#0070cc', Gamepad2),
  epicgames: brand('epicgames', 'Epic Games', '#f8fafc', Gamepad2),
  roblox: brand('roblox', 'Roblox', '#f8fafc', Gamepad2),
  duolingo: brand('duolingo', 'Duolingo', '#58cc02', BookOpen),
  coursera: brand('coursera', 'Coursera', '#0056d2', BookOpen),
  udemy: brand('udemy', 'Udemy', '#a435f0', BookOpen),
  deepl: brand('deepl', 'DeepL', '#0f2b46', FileText),
  api: brand('api', 'API', 'hsl(var(--primary))', LinkIcon, null),
  server: brand('server', 'Server', 'hsl(var(--warning))', Server, null),
  database: brand('database', 'Database', 'hsl(var(--success))', Database, null),
  cloud: brand('cloud', 'Cloud', 'hsl(var(--accent))', Cloud, null),
  shop: brand('shop', 'Shop', 'hsl(var(--warning))', Store, null),
};

export const BRAND_ICON_REGISTRY: Record<string, BrandIconDefinition> = Object.fromEntries(
  Object.entries(BRAND_ICON_BASE_REGISTRY).map(([id, definition]) => [
    id,
    {
      ...definition,
      svgSrc: simpleIconUrl(definition.simpleIconSlug),
    },
  ]),
) as Record<string, BrandIconDefinition>;

export function getBrandIconDefinition(id: string | null | undefined): BrandIconDefinition {
  return BRAND_ICON_REGISTRY[id ?? 'generic'] ?? BRAND_ICON_REGISTRY.generic;
}
