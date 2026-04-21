// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Header/Navigation Component
 * 
 * Top navigation bar with logo, links, and auth buttons.
 */

import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useNavigate } from 'react-router-dom';
import { Menu, X, Download, CreditCard, ChevronDown, UserRound, Wrench } from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
} from '@/components/ui/dropdown-menu';
import { useAuth } from '@/contexts/AuthContext';

import { getServiceHooks, isPremiumActive } from '@/extensions/registry';
import { getAdminEntryPath, getSubscriptionEntryPath } from '@/platform/appShell';

// Type for the BeforeInstallPromptEvent
interface BeforeInstallPromptEvent extends Event {
  prompt: () => Promise<void>;
  userChoice: Promise<{ outcome: 'accepted' | 'dismissed' }>;
}

export function Header() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { user, signOut, authReady } = useAuth();
  
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [deferredPrompt, setDeferredPrompt] = useState<BeforeInstallPromptEvent | null>(null);
  const [isInstallable, setIsInstallable] = useState(false);
  const [showAdminButton, setShowAdminButton] = useState(false);
  const pricingEntryPath = getSubscriptionEntryPath();
  const adminEntryPath = getAdminEntryPath();

  useEffect(() => {
    const handleBeforeInstallPrompt = (e: Event) => {
      // Prevent the mini-infobar from appearing on mobile
      e.preventDefault();
      // Save the event so it can be triggered later
      setDeferredPrompt(e as BeforeInstallPromptEvent);
      setIsInstallable(true);
    };

    const handleAppInstalled = () => {
      setDeferredPrompt(null);
      setIsInstallable(false);
    };

    window.addEventListener('beforeinstallprompt', handleBeforeInstallPrompt);
    window.addEventListener('appinstalled', handleAppInstalled);

    return () => {
      window.removeEventListener('beforeinstallprompt', handleBeforeInstallPrompt);
      window.removeEventListener('appinstalled', handleAppInstalled);
    };
  }, []);

  useEffect(() => {
    let isCancelled = false;

    const loadAdminAccess = async () => {
      if (!authReady || !user || !isPremiumActive()) {
        if (!isCancelled) {
          setShowAdminButton(false);
        }
        return;
      }

      const hooks = getServiceHooks();
      if (!hooks.getTeamAccess) {
        if (!isCancelled) {
          setShowAdminButton(false);
        }
        return;
      }

      const { access, error } = await hooks.getTeamAccess();
      if (isCancelled) {
        return;
      }

      if (error || !access) {
        setShowAdminButton(false);
        return;
      }

      setShowAdminButton(access.can_access_admin);
    };

    void loadAdminAccess();

    return () => {
      isCancelled = true;
    };
  }, [authReady, user]);

  const handleInstallClick = async () => {
    if (!deferredPrompt) return;

    // Show the install prompt
    await deferredPrompt.prompt();

    // Wait for the user's response
    const { outcome } = await deferredPrompt.userChoice;

    if (outcome === 'accepted') {
      setDeferredPrompt(null);
      setIsInstallable(false);
    }
  };

  const handleLogout = async () => {
    try {
      await signOut();
    } catch (error) {
      console.error('[Header] Failed to sign out:', error);
    } finally {
      setMobileMenuOpen(false);
      navigate('/', { replace: true });
    }
  };

  return (
    <header className="ms-glass-header sticky top-0 z-50 w-full">
      <div className="container px-4">
        <div className="flex h-16 items-center justify-between">
          {/* Logo */}
          <Link to="/" className="flex items-center gap-3 decoration-0">
            <img src="/singra-icon.png" alt="Singra Vault" className="w-7 h-7 rounded-full shadow-lg shadow-primary/20 ring-1 ring-border/70" />
            <span className="text-xl font-bold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-foreground to-foreground/80">
              Singra Vault
            </span>
          </Link>

          {/* Desktop Navigation */}
          <nav className="hidden md:flex items-center gap-6">
            <a href="/#security" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
              {t('landing.footer.security')}
            </a>
            <a href="/#features" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
              Features
            </a>
            <a href="/#comparison" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
              Vergleich
            </a>
            {isPremiumActive() && pricingEntryPath && (
              <Link to={pricingEntryPath} className="text-sm text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1">
                <CreditCard className="w-3.5 h-3.5" />
                {t('subscription.pricing_title', 'Preise')}
              </Link>
            )}
          </nav>

          {/* Actions */}
          <div className="flex items-center gap-2">
            {/* PWA Install Button */}
            {isInstallable && (
              <Button
                variant="ghost"
                size="icon"
                onClick={handleInstallClick}
                aria-label={t('pwa.install', 'App installieren')}
                title={t('pwa.install', 'App installieren')}
                className="ms-header-utility-button min-h-[44px] rounded-full px-3"
              >
                <Download className="w-5 h-5" />
              </Button>
            )}

            {/* Auth Buttons */}
            <div className="hidden sm:flex items-center gap-2">
              {user ? (
                <>
                  <Button asChild className="ms-header-primary-button min-h-[44px] rounded-full px-4 text-sm font-medium">
                    <Link to="/vault">{t('nav.vault')}</Link>
                  </Button>
                  {showAdminButton && adminEntryPath && (
                    <Button asChild className="ms-header-secondary-button min-h-[44px] rounded-full px-3 text-sm font-medium gap-2">
                      <Link to={adminEntryPath}>
                        <Wrench className="w-4 h-4" />
                        {t('admin.title')}
                      </Link>
                    </Button>
                  )}
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button className="ms-header-utility-button min-h-[44px] rounded-full px-3 text-sm font-medium gap-2">
                        <UserRound className="w-4 h-4" />
                        {t('nav.account')}
                        <ChevronDown className="w-4 h-4" />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end" className="ms-header-dropdown w-48">
                      <DropdownMenuItem asChild>
                        <Link to="/settings">{t('nav.settings')}</Link>
                      </DropdownMenuItem>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem onClick={() => void handleLogout()}>
                        {t('nav.logout')}
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </>
              ) : (
                <>
                  <Button asChild className="ms-header-utility-button min-h-[44px] rounded-full px-4 text-sm font-medium">
                    <Link to="/auth">{t('nav.login')}</Link>
                  </Button>
                  <Button asChild className="ms-header-primary-button min-h-[44px] rounded-full px-4 text-sm font-medium">
                    <Link to="/auth?mode=signup">{t('nav.signup')}</Link>
                  </Button>
                </>
              )}
            </div>

            {/* Mobile Menu Button */}
            <Button
              variant="ghost"
              size="icon"
              className="md:hidden"
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              aria-label="Toggle menu"
            >
              {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </Button>
          </div>
        </div>

        {/* Mobile Menu */}
        {mobileMenuOpen && (
          <div className="md:hidden py-4 border-t animate-fade-in">
            <nav className="flex flex-col gap-4">
              <a
                href="/#security"
                className="text-sm text-muted-foreground hover:text-foreground transition-colors"
                onClick={() => setMobileMenuOpen(false)}
              >
                {t('landing.footer.security')}
              </a>
              <a
                href="/#features"
                className="text-sm text-muted-foreground hover:text-foreground transition-colors"
                onClick={() => setMobileMenuOpen(false)}
              >
                Features
              </a>
              <a
                href="/#comparison"
                className="text-sm text-muted-foreground hover:text-foreground transition-colors"
                onClick={() => setMobileMenuOpen(false)}
              >
              Vergleich
              </a>
              {isPremiumActive() && pricingEntryPath && (
                <Link
                  to={pricingEntryPath}
                  className="text-sm text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1"
                  onClick={() => setMobileMenuOpen(false)}
                >
                  <CreditCard className="w-3.5 h-3.5" />
                  {t('subscription.pricing_title', 'Preise')}
                </Link>
              )}
              <div className="flex flex-col gap-2 pt-4 border-t">
                {/* PWA Install Button for Mobile */}
                {isInstallable && (
                  <Button
                    onClick={() => {
                      handleInstallClick();
                      setMobileMenuOpen(false);
                    }}
                    variant="outline"
                    className="w-full"
                  >
                    <Download className="w-4 h-4 mr-2" />
                    {t('pwa.install', 'App installieren')}
                  </Button>
                )}
                {user ? (
                  <>
                    <Button asChild className="flex-1">
                      <Link to="/vault">{t('nav.vault')}</Link>
                    </Button>
                    {showAdminButton && adminEntryPath && (
                      <Button asChild variant="outline" className="flex-1">
                        <Link to={adminEntryPath}>{t('admin.title')}</Link>
                      </Button>
                    )}
                    <Button asChild variant="outline" className="flex-1">
                      <Link to="/settings">{t('nav.settings')}</Link>
                    </Button>
                    <Button
                      variant="ghost"
                      className="flex-1"
                      onClick={() => void handleLogout()}
                    >
                      {t('nav.logout')}
                    </Button>
                  </>
                ) : (
                  <>
                    <Button asChild variant="outline" className="flex-1">
                      <Link to="/auth">{t('nav.login')}</Link>
                    </Button>
                    <Button asChild className="flex-1">
                      <Link to="/auth?mode=signup">{t('nav.signup')}</Link>
                    </Button>
                  </>
                )}
              </div>
            </nav>
          </div>
        )}
      </div>
    </header>
  );
}
