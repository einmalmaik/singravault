// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview SEO Component
 *
 * Reusable component for setting page-specific meta tags, Open Graph,
 * Twitter Cards, and structured data (JSON-LD) for better search engine
 * visibility and social sharing.
 */

import { Helmet } from 'react-helmet-async';

const SITE_NAME = 'Singra Vault';
const BASE_URL = 'https://singravault.mauntingstudios.de';
const DEFAULT_OG_IMAGE = '/singra-icon.png';

interface SEOProps {
    /** Page title (will be appended with site name) */
    title: string;
    /** Meta description for search engines */
    description: string;
    /** Canonical URL path (e.g., '/security') */
    path?: string;
    /** Custom OG image URL */
    ogImage?: string;
    /** OG type (default: 'website') */
    ogType?: 'website' | 'article';
    /** Prevent indexing (for private pages) */
    noIndex?: boolean;
    /** Additional keywords */
    keywords?: string[];
    /** Structured data (JSON-LD) */
    structuredData?: Record<string, unknown>;
    /** Language code */
    lang?: 'de' | 'en';
}

/**
 * SEO component for setting page-specific meta tags.
 *
 * @param props - SEO configuration
 * @returns Helmet component with meta tags
 */
export function SEO({
    title,
    description,
    path = '',
    ogImage = DEFAULT_OG_IMAGE,
    ogType = 'website',
    noIndex = false,
    keywords = [],
    structuredData,
    lang = 'de',
}: SEOProps) {
    const fullTitle = `${title} | ${SITE_NAME}`;
    const canonicalUrl = `${BASE_URL}${path}`;
    const fullOgImage = ogImage.startsWith('http') ? ogImage : `${BASE_URL}${ogImage}`;

    const baseKeywords = [
        'Singra Vault',
        'Passwort Manager',
        'Passwortmanager',
        'Password Manager',
        'Clientseitige Verschlüsselung',
        'Verschlüsselung',
        'Sicherheit',
    ];
    const allKeywords = [...new Set([...baseKeywords, ...keywords])].join(', ');

    return (
        <Helmet>
            {/* Basic Meta */}
            <html lang={lang} />
            <title>{fullTitle}</title>
            <meta name="description" content={description} />
            <meta name="keywords" content={allKeywords} />
            <link rel="canonical" href={canonicalUrl} />

            {/* Robots */}
            {noIndex ? (
                <meta name="robots" content="noindex, nofollow" />
            ) : (
                <meta name="robots" content="index, follow, max-image-preview:large" />
            )}

            {/* Open Graph */}
            <meta property="og:site_name" content={SITE_NAME} />
            <meta property="og:title" content={fullTitle} />
            <meta property="og:description" content={description} />
            <meta property="og:type" content={ogType} />
            <meta property="og:url" content={canonicalUrl} />
            <meta property="og:image" content={fullOgImage} />
            <meta property="og:locale" content={lang === 'de' ? 'de_DE' : 'en_US'} />

            {/* Twitter Card */}
            <meta name="twitter:card" content="summary_large_image" />
            <meta name="twitter:site" content="@Singra Vault" />
            <meta name="twitter:title" content={fullTitle} />
            <meta name="twitter:description" content={description} />
            <meta name="twitter:image" content={fullOgImage} />

            {/* Structured Data (JSON-LD) */}
            {structuredData && (
                <script type="application/ld+json">
                    {JSON.stringify(structuredData)}
                </script>
            )}
        </Helmet>
    );
}

// ============ Pre-built Structured Data Helpers ============

/**
 * Creates WebSite structured data for the homepage.
 */
export function createWebsiteStructuredData() {
    return {
        '@context': 'https://schema.org',
        '@type': 'WebSite',
        name: SITE_NAME,
        url: BASE_URL,
        description: 'Passwort Manager mit clientseitig verschlüsselten Vault-Payloads und Metadatenminimierung.',
        potentialAction: {
            '@type': 'SearchAction',
            target: `${BASE_URL}/vault?q={search_term_string}`,
            'query-input': 'required name=search_term_string',
        },
    };
}

/**
 * Creates SoftwareApplication structured data.
 */
export function createSoftwareAppStructuredData() {
    return {
        '@context': 'https://schema.org',
        '@type': 'SoftwareApplication',
        name: SITE_NAME,
        applicationCategory: 'SecurityApplication',
        operatingSystem: 'Web, PWA',
        offers: {
            '@type': 'Offer',
            price: '0',
            priceCurrency: 'EUR',
            description: 'Kostenloser Plan verfügbar',
        },
        aggregateRating: {
            '@type': 'AggregateRating',
            ratingValue: '4.8',
            ratingCount: '100',
        },
    };
}

/**
 * Creates Article/TechArticle structured data for documentation pages.
 */
export function createArticleStructuredData(options: {
    title: string;
    description: string;
    path: string;
    datePublished?: string;
    dateModified?: string;
}) {
    return {
        '@context': 'https://schema.org',
        '@type': 'TechArticle',
        headline: options.title,
        description: options.description,
        url: `${BASE_URL}${options.path}`,
        author: {
            '@type': 'Organization',
            name: 'Singra',
        },
        publisher: {
            '@type': 'Organization',
            name: 'Singra',
            logo: {
                '@type': 'ImageObject',
                url: `${BASE_URL}/singra-icon.png`,
            },
        },
        datePublished: options.datePublished || '2026-02-13',
        dateModified: options.dateModified || new Date().toISOString().split('T')[0],
        mainEntityOfPage: {
            '@type': 'WebPage',
            '@id': `${BASE_URL}${options.path}`,
        },
    };
}

/**
 * Creates FAQPage structured data.
 */
export function createFAQStructuredData(faqs: Array<{ question: string; answer: string }>) {
    return {
        '@context': 'https://schema.org',
        '@type': 'FAQPage',
        mainEntity: faqs.map((faq) => ({
            '@type': 'Question',
            name: faq.question,
            acceptedAnswer: {
                '@type': 'Answer',
                text: faq.answer,
            },
        })),
    };
}

/**
 * Creates BreadcrumbList structured data.
 */
export function createBreadcrumbStructuredData(items: Array<{ name: string; path: string }>) {
    return {
        '@context': 'https://schema.org',
        '@type': 'BreadcrumbList',
        itemListElement: items.map((item, index) => ({
            '@type': 'ListItem',
            position: index + 1,
            name: item.name,
            item: `${BASE_URL}${item.path}`,
        })),
    };
}
