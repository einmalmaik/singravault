-- Migration: 20260224160000_auth_hardening_tables.sql

-- Tabellen für sichere Passwort-Hashes
CREATE TABLE IF NOT EXISTS public.user_security (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    argon2_hash TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- RLS aktivieren
ALTER TABLE public.user_security ENABLE ROW LEVEL SECURITY;
-- Sicherheit: Keine RLS-Policies! Nur der Service-Role-Key der Edge-Functions darf hierauf zugreifen.

-- Tabellen für CSPRNG Recovery Tokens
CREATE TABLE IF NOT EXISTS public.recovery_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL,
    token_hash TEXT NOT NULL, -- SHA-256 Hash des CSPRNG Tokens
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- RLS aktivieren
ALTER TABLE public.recovery_tokens ENABLE ROW LEVEL SECURITY;
-- Sicherheit: Keine RLS-Policies! Nur der Service-Role-Key der Edge-Functions darf hierauf zugreifen.

-- Index für schnelles Finden & Löschen
CREATE INDEX IF NOT EXISTS idx_recovery_tokens_email ON public.recovery_tokens(email);
