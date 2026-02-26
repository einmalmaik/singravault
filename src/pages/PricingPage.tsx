// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Pricing Page
 *
 * Displays subscription plans (FREE / PREMIUM / FAMILIES)
 * with monthly/yearly toggle and checkout CTAs.
 * Accessible without login — uses global Header/Footer.
 */

import { useState } from 'react';
import { Navigate, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
    Shield,
    Check,
    Crown,
    Users,
    Zap,
    Lock,
    Clock3,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { useAuth } from '@/contexts/AuthContext';
import { useSubscription } from '@/contexts/SubscriptionContext';
import { CheckoutDialog } from '@/components/Subscription/CheckoutDialog';
import { Header } from '@/components/landing/Header';
import { Footer } from '@/components/landing/Footer';
import { SEO } from '@/components/SEO';
import type { PlanKey } from '@/config/planConfig';

const FREE_FEATURES = [
    'subscription.features.unlimited_passwords',
    'subscription.features.device_sync',
    'subscription.features.password_generator',
    'subscription.features.secure_notes',
    'subscription.features.external_2fa',
    'subscription.features.argon2id_encryption',
    'subscription.features.clipboard_auto_clear',
    'subscription.features.post_quantum',
    'subscription.features.passkey_unlock',
    'subscription.features.vault_integrity',
    'subscription.features.core_features',
];

const PREMIUM_FEATURES = [
    'subscription.features.duress_password',
    'subscription.features.file_attachments',
    'subscription.features.builtin_authenticator',
    'subscription.features.emergency_access',
    'subscription.features.vault_health',
    'subscription.features.priority_support',
];

const FAMILIES_FEATURES = [
    'subscription.features.six_accounts',
    'subscription.features.shared_collections',
    'subscription.features.family_organization',
];

export default function PricingPage() {
    const { t } = useTranslation();
    const navigate = useNavigate();
    const { user } = useAuth();
    const { tier, billingDisabled } = useSubscription();
    const [yearly, setYearly] = useState(false);
    const [checkoutPlan, setCheckoutPlan] = useState<PlanKey | null>(null);

    if (billingDisabled) {
        return <Navigate to="/settings" replace />;
    }

    const handleUpgrade = (plan: 'premium' | 'families') => {
        if (!user) {
            navigate('/auth');
            return;
        }
        const planKey: PlanKey = `${plan}_${yearly ? 'yearly' : 'monthly'}`;
        setCheckoutPlan(planKey);
    };

    return (
        <div className="min-h-screen flex flex-col bg-gradient-to-br from-primary/5 via-background to-primary/10">
            <SEO
                title="Preise & Pläne"
                description="Wähle den passenden Plan für Singra Vault: Kostenlos für Einzelnutzer, Premium für erweiterte Sicherheitsfunktionen, oder Families für bis zu 6 Personen."
                path="/pricing"
                keywords={[
                    'Passwort Manager Preise',
                    'Passwortmanager kostenlos',
                    'Password Manager Premium',
                    'Familien Passwort Manager',
                    'Abo Preise',
                ]}
            />
            {/* Global Header */}
            <Header />

            <main className="container max-w-6xl mx-auto px-4 py-12 flex-1">
                {/* Page Title */}
                <div className="text-center mb-8">
                    <h1 className="text-3xl md:text-4xl font-bold mb-3">
                        {t('subscription.pricing_title')}
                    </h1>
                    <p className="text-muted-foreground max-w-xl mx-auto">
                        {t('subscription.free_description')}
                    </p>
                </div>

                {/* Billing Toggle */}
                <div className="flex items-center justify-center gap-3 mb-12">
                    <Label className={`text-sm font-medium ${!yearly ? 'text-foreground' : 'text-muted-foreground'}`}>
                        {t('subscription.monthly')}
                    </Label>
                    <Switch checked={yearly} onCheckedChange={setYearly} />
                    <Label className={`text-sm font-medium ${yearly ? 'text-foreground' : 'text-muted-foreground'}`}>
                        {t('subscription.yearly')}
                        <span className="ml-1 text-xs text-green-600 dark:text-green-400 font-semibold">
                            {t('subscription.save_yearly')}
                        </span>
                    </Label>
                </div>

                {/* Plan Cards */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-5xl mx-auto">
                    {/* FREE */}
                    <div className="relative rounded-2xl border bg-card p-6 flex flex-col">
                        <div className="mb-6">
                            <div className="flex items-center gap-2 mb-2">
                                <Shield className="w-6 h-6 text-primary" />
                                <h3 className="text-lg font-bold">FREE</h3>
                            </div>
                            <div className="flex items-baseline gap-1 mb-2">
                                <span className="text-4xl font-extrabold">€0</span>
                                <span className="text-muted-foreground text-sm">/{t('subscription.forever')}</span>
                            </div>
                            <p className="text-sm text-muted-foreground">
                                {t('subscription.free_description')}
                            </p>
                        </div>
                        <ul className="space-y-3 flex-1 mb-6">
                            {FREE_FEATURES.map((feat) => (
                                <li key={feat} className="flex items-start gap-2 text-sm">
                                    <Check className="w-4 h-4 text-green-500 mt-0.5 shrink-0" />
                                    <span>{t(feat)}</span>
                                </li>
                            ))}
                        </ul>
                        <Button variant="outline" className="w-full" disabled={tier === 'free'}>
                            {tier === 'free' ? t('subscription.current_plan') : t('subscription.select_plan')}
                        </Button>
                        <div className="mt-3 flex items-center gap-1.5 justify-center text-xs text-muted-foreground">
                            <Lock className="w-3.5 h-3.5" />
                            <span>{t('subscription.free_security_note')}</span>
                        </div>
                        <div className="mt-1.5 flex items-center gap-1.5 justify-center text-xs text-muted-foreground">
                            <Clock3 className="w-3.5 h-3.5" />
                            <span>{t('subscription.support.free_sla')}</span>
                        </div>
                    </div>

                    {/* PREMIUM */}
                    <div className="relative rounded-2xl border-2 border-primary bg-card p-6 flex flex-col shadow-lg shadow-primary/10">
                        <div className="absolute -top-3 left-1/2 -translate-x-1/2">
                            <span className="bg-primary text-primary-foreground text-xs font-bold px-3 py-1 rounded-full">
                                {t('subscription.popular')}
                            </span>
                        </div>
                        <div className="mb-6">
                            <div className="flex items-center gap-2 mb-2">
                                <Crown className="w-6 h-6 text-yellow-500" />
                                <h3 className="text-lg font-bold">PREMIUM</h3>
                            </div>
                            <div className="flex items-baseline gap-1 mb-2">
                                <span className="text-4xl font-extrabold">
                                    €{yearly ? '19,80' : '1,65'}
                                </span>
                                <span className="text-muted-foreground text-sm">
                                    /{yearly ? t('subscription.year') : t('subscription.month')}
                                </span>
                            </div>
                            <p className="text-sm text-muted-foreground">
                                {t('subscription.premium_description')}
                            </p>
                            {!yearly && (
                                <p className="text-xs text-green-600 dark:text-green-400 mt-1 font-medium">
                                    {t('subscription.intro_discount')}
                                </p>
                            )}
                        </div>
                        <ul className="space-y-3 flex-1 mb-6">
                            <li className="text-xs text-muted-foreground font-medium uppercase tracking-wider mb-1">
                                {t('subscription.includes_free')}
                            </li>
                            {PREMIUM_FEATURES.map((feat) => (
                                <li key={feat} className="flex items-start gap-2 text-sm">
                                    <Zap className="w-4 h-4 text-yellow-500 mt-0.5 shrink-0" />
                                    <span>{t(feat)}</span>
                                </li>
                            ))}
                        </ul>
                        <Button
                            className="w-full"
                            onClick={() => handleUpgrade('premium')}
                            disabled={tier === 'premium'}
                        >
                            {tier === 'premium' ? t('subscription.current_plan') : t('subscription.upgrade')}
                        </Button>
                        <div className="mt-3 flex items-center gap-1.5 justify-center text-xs text-muted-foreground">
                            <Clock3 className="w-3.5 h-3.5" />
                            <span>{t('subscription.support.premium_sla')}</span>
                        </div>
                    </div>

                    {/* FAMILIES */}
                    <div className="relative rounded-2xl border bg-card p-6 flex flex-col">
                        <div className="mb-6">
                            <div className="flex items-center gap-2 mb-2">
                                <Users className="w-6 h-6 text-blue-500" />
                                <h3 className="text-lg font-bold">FAMILIES</h3>
                            </div>
                            <div className="flex items-baseline gap-1 mb-2">
                                <span className="text-4xl font-extrabold">
                                    €{yearly ? '47,88' : '3,99'}
                                </span>
                                <span className="text-muted-foreground text-sm">
                                    /{yearly ? t('subscription.year') : t('subscription.month')}
                                </span>
                            </div>
                            <p className="text-sm text-muted-foreground">
                                {t('subscription.families_description')}
                            </p>
                            {!yearly && (
                                <p className="text-xs text-green-600 dark:text-green-400 mt-1 font-medium">
                                    {t('subscription.intro_discount')}
                                </p>
                            )}
                        </div>
                        <ul className="space-y-3 flex-1 mb-6">
                            <li className="text-xs text-muted-foreground font-medium uppercase tracking-wider mb-1">
                                {t('subscription.includes_premium')}
                            </li>
                            {FAMILIES_FEATURES.map((feat) => (
                                <li key={feat} className="flex items-start gap-2 text-sm">
                                    <Users className="w-4 h-4 text-blue-500 mt-0.5 shrink-0" />
                                    <span>{t(feat)}</span>
                                </li>
                            ))}
                        </ul>
                        <Button
                            variant="outline"
                            className="w-full"
                            onClick={() => handleUpgrade('families')}
                            disabled={tier === 'families'}
                        >
                            {tier === 'families' ? t('subscription.current_plan') : t('subscription.upgrade')}
                        </Button>
                        <div className="mt-3 flex items-center gap-1.5 justify-center text-xs text-muted-foreground text-center">
                            <Clock3 className="w-3.5 h-3.5" />
                            <span>{t('subscription.support.families_sla')}</span>
                        </div>
                    </div>
                </div>

                {/* Legal Info */}
                <div className="mt-12 text-center text-xs text-muted-foreground max-w-2xl mx-auto space-y-2">
                    <p>{t('subscription.support.sla_note')}</p>
                    <p>{t('subscription.legal_info')}</p>
                    <p>{t('subscription.refund_info')}</p>
                </div>
            </main>

            {/* Global Footer */}
            <Footer />

            {/* Checkout Dialog */}
            {checkoutPlan && (
                <CheckoutDialog
                    planKey={checkoutPlan}
                    open={!!checkoutPlan}
                    onClose={() => setCheckoutPlan(null)}
                />
            )}
        </div>
    );
}
