// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE

/**
 * @fileoverview Rate Limiting Edge Function
 *
 * Diese Edge Function implementiert ein serverseitiges Rate-Limiting-System
 * zum Schutz gegen Brute-Force-Angriffe auf sicherheitskritische Aktionen.
 *
 * ## Funktionsweise
 *
 * Das Rate-Limiting arbeitet auf zwei Ebenen:
 * 1. **Benutzer-Identität**: Tracking nach authentifiziertem User-ID
 * 2. **IP-Adresse**: Zusätzliches Tracking zur Verhinderung verteilter Angriffe
 *
 * ## Geschützte Aktionen
 *
 * | Aktion     | Max. Versuche | Zeitfenster | Sperrzeit |
 * |------------|---------------|-------------|-----------|
 * | `unlock`   | 5             | 15 Min      | 15 Min    |
 * | `2fa`      | 3             | 5 Min       | 30 Min    |
 * | `passkey`  | 5             | 10 Min      | 10 Min    |
 * | `emergency`| 3             | 1 Stunde    | 24 Stunden|
 *
 * ## Sicherheitskonzept
 *
 * - **Fail-Closed**: Bei Fehlern wird der Zugriff verweigert (nicht erlaubt)
 * - **Exponentielles Backoff**: Wiederholte Fehlversuche verdoppeln die Sperrzeit
 * - **Client-Misstrauen**: Erfolgs-/Fehler-Meldungen vom Client werden ignoriert
 * - **IP-Extraktion**: Nur aus vertrauenswürdigen Proxy-Headern (CF-Connecting-IP)
 *
 * ## Aufruf aus dem Frontend
 *
 * Diese Function wird NICHT direkt vom Frontend aufgerufen. Stattdessen nutzen
 * andere Edge Functions das `_shared/authRateLimit.ts` Modul, das intern auf
 * die `rate_limit_attempts` Tabelle zugreift.
 *
 * Legacy-Aufrufe via `invokeAuthedFunction('rate-limit', {...})` existieren
 * noch für Vault-Unlock und 2FA-Verifikation.
 *
 * ## Datenbankstruktur
 *
 * Tabelle: `rate_limit_attempts`
 * - `identifier`: User-ID oder E-Mail
 * - `action`: Aktionstyp (unlock, 2fa, passkey, emergency)
 * - `ip_address`: Client-IP (aus Proxy-Headern)
 * - `locked_until`: Zeitstempel bis wann gesperrt
 * - `attempted_at`: Zeitstempel des Versuchs
 *
 * @see src/services/rateLimiterService.ts - Frontend-Wrapper
 * @see _shared/authRateLimit.ts - Shared Rate-Limit-Logik für andere Edge Functions
 */

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { getCorsHeaders } from "../_shared/cors.ts";

// ============================================================================
// Konfiguration
// ============================================================================

/**
 * Supabase-URL aus Umgebungsvariablen.
 * Wird automatisch vom Supabase Edge Function Runtime gesetzt.
 */
const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;

/**
 * Anonymer Schlüssel für Client-Authentifizierung.
 * Wird verwendet, um den JWT des Benutzers zu validieren.
 */
const SUPABASE_ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY")!;

/**
 * Service Role Key für Admin-Operationen.
 * ACHTUNG: Umgeht RLS - nur für Datenbankschreib-/-leseoperationen verwenden!
 */
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

// ============================================================================
// Rate-Limit-Konfiguration
// ============================================================================

/**
 * Konfiguration der Rate-Limits pro Aktionstyp.
 *
 * Sicherheitsüberlegungen:
 * - `unlock`: Moderate Limits, da Master-Passwort bereits stark ist
 * - `2fa`: Strenge Limits, da TOTP-Codes nur 6 Ziffern haben
 * - `passkey`: Moderate Limits, WebAuthn hat eigene Sicherheit
 * - `emergency`: Sehr streng, kritische Aktionen wie Account-Wiederherstellung
 */
const RATE_LIMITS = {
  unlock: {
    maxAttempts: 5,
    window: 15 * 60 * 1000, // 15 minutes
    lockout: 15 * 60 * 1000, // 15 minutes
  },
  '2fa': {
    maxAttempts: 3,
    window: 5 * 60 * 1000, // 5 minutes
    lockout: 30 * 60 * 1000, // 30 minutes - higher for 2FA brute force protection
  },
  passkey: {
    maxAttempts: 5,
    window: 10 * 60 * 1000, // 10 minutes
    lockout: 10 * 60 * 1000, // 10 minutes
  },
  emergency: {
    maxAttempts: 3,
    window: 60 * 60 * 1000, // 1 hour
    lockout: 24 * 60 * 60 * 1000, // 24 hours - critical action
  },
};

// ============================================================================
// Typen
// ============================================================================

/**
 * Request-Payload für Rate-Limit-Prüfung.
 *
 * WICHTIG: `success` und `ipAddress` sind deprecated und werden ignoriert.
 * Der Client kann nicht vertrauenswürdig melden, ob ein Versuch erfolgreich war.
 */
interface RateLimitRequest {
  userId?: string;
  email?: string;
  action: 'unlock' | '2fa' | 'passkey' | 'emergency';
  success?: boolean; // Deprecated and ignored (cannot be trusted from client)
  ipAddress?: string; // Deprecated and ignored (cannot be trusted from client)
}

/**
 * Response-Payload für Rate-Limit-Status.
 *
 * - `allowed`: False wenn Benutzer gesperrt oder Limit erreicht
 * - `attemptsRemaining`: Verbleibende Versuche im aktuellen Zeitfenster
 * - `lockedUntil`: ISO-Timestamp bis wann gesperrt (nur wenn gesperrt)
 */
interface RateLimitResponse {
  allowed: boolean;
  attemptsRemaining: number;
  lockedUntil?: string;
}

// ============================================================================
// Hilfsfunktionen
// ============================================================================

/**
 * Extrahiert die vertrauenswürdige Client-IP aus Proxy-Headern.
 *
 * Priorität:
 * 1. CF-Connecting-IP (Cloudflare, am vertrauenswürdigsten)
 * 2. X-Forwarded-For (erster Eintrag, von Load Balancern)
 * 3. 'unknown' als Fallback
 *
 * WICHTIG: Client-übermittelte IP-Adressen werden NIEMALS verwendet,
 * da diese trivial gefälscht werden können.
 *
 * @param req - Eingehender Request
 * @returns Vertrauenswürdige Client-IP oder 'unknown'
 */
function getTrustedClientIp(req: Request): string {
  const cfConnectingIp = req.headers.get('CF-Connecting-IP');
  if (cfConnectingIp && cfConnectingIp.trim().length > 0) {
    return cfConnectingIp.trim();
  }

  const xForwardedFor = req.headers.get('X-Forwarded-For');
  if (xForwardedFor) {
    const forwardedClientIp = xForwardedFor.split(',')[0]?.trim();
    if (forwardedClientIp && forwardedClientIp.length > 0) {
      return forwardedClientIp;
    }
  }

  return 'unknown';
}

// ============================================================================
// Request Handler
// ============================================================================

/**
 * Haupteinstiegspunkt der Edge Function.
 *
 * Verarbeitet Rate-Limit-Prüfungen für sicherheitskritische Aktionen.
 * Jeder Request muss authentifiziert sein (Bearer Token).
 *
 * Workflow:
 * 1. CORS-Preflight behandeln
 * 2. JWT validieren und User-ID extrahieren
 * 3. Rate-Limit-Status für User+IP prüfen
 * 4. Fehlversuch protokollieren (jeder Aufruf gilt als Versuch)
 * 5. Aktuellen Status zurückgeben
 */
serve(async (req) => {
  const corsHeaders = getCorsHeaders(req);

  // Handle CORS
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return new Response(
      JSON.stringify({ error: "Method not allowed" }),
      { status: 405, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  try {
    const authHeader = req.headers.get("Authorization");
    if (!authHeader) {
      return new Response(
        JSON.stringify({ error: "Missing authorization header" }),
        { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const authClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
      global: { headers: { Authorization: authHeader } },
    });
    const { data: { user }, error: authError } = await authClient.auth.getUser();
    if (authError || !user) {
      return new Response(
        JSON.stringify({ error: "Unauthorized" }),
        { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

    const { userId, email, action }: RateLimitRequest = await req.json();

    // Validate action
    if (!RATE_LIMITS[action]) {
      return new Response(
        JSON.stringify({ error: "Invalid action" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const limits = RATE_LIMITS[action];

    // SECURITY: Bind rate-limit identity to authenticated user.
    if (userId && userId !== user.id) {
      return new Response(
        JSON.stringify({ error: "userId does not match authenticated user" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const normalizedEmail = email?.trim().toLowerCase();
    const authenticatedEmail = user.email?.trim().toLowerCase();
    if (normalizedEmail && normalizedEmail !== authenticatedEmail) {
      return new Response(
        JSON.stringify({ error: "email does not match authenticated user" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }
    const identifier = user.id;

    // SECURITY: Derive IP only from trusted proxy headers.
    const clientIp = getTrustedClientIp(req);

    const now = new Date();
    const windowStart = new Date(now.getTime() - limits.window);

    // Get recent attempts for BOTH identifier AND IP address
    const [identifierAttempts, ipAttempts] = await Promise.all([
      // Check by user identifier
      supabase
        .from('rate_limit_attempts')
        .select('*')
        .eq('identifier', identifier)
        .eq('action', action)
        .gte('attempted_at', windowStart.toISOString())
        .order('attempted_at', { ascending: false }),

      // Check by IP address (prevent distributed attacks)
      clientIp !== 'unknown' ? supabase
        .from('rate_limit_attempts')
        .select('*')
        .eq('ip_address', clientIp)
        .eq('action', action)
        .gte('attempted_at', windowStart.toISOString())
        .order('attempted_at', { ascending: false })
      : { data: [], error: null }
    ]);

    if (identifierAttempts.error || ipAttempts.error) {
      console.error('Error fetching rate limit attempts:', identifierAttempts.error || ipAttempts.error);
      // Fail closed for security - deny if we can't check
      return new Response(
        JSON.stringify({
          allowed: false,
          attemptsRemaining: 0,
          error: "Rate limit check failed"
        }),
        { status: 503, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Combine attempts from identifier and IP
    const allAttempts = [
      ...(identifierAttempts.data || []),
      ...(ipAttempts.data || [])
    ];

    // Check if currently locked out (by identifier OR IP)
    const lockedAttempt = allAttempts.find(a => a.locked_until && new Date(a.locked_until) > now);
    if (lockedAttempt) {
      // Log potential attack
      console.warn(`Rate limit lockout for ${action}: identifier=${identifier}, ip=${clientIp}`);

      return new Response(
        JSON.stringify({
          allowed: false,
          attemptsRemaining: 0,
          lockedUntil: lockedAttempt.locked_until
        }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Count failed attempts in window (use higher count from identifier or IP)
    const identifierFailed = (identifierAttempts.data?.filter(a => !a.success).length || 0);
    const ipFailed = (ipAttempts.data?.filter(a => !a.success).length || 0);
    const failedAttempts = Math.max(identifierFailed, ipFailed);

    // Exponential backoff for repeated failures
    const backoffMultiplier = Math.min(Math.pow(2, Math.floor(failedAttempts / limits.maxAttempts)), 8);
    const effectiveLockout = limits.lockout * backoffMultiplier;

    // SECURITY: Each call is treated as a failed attempt. Caller-reported
    // "success" cannot be trusted for lockout enforcement decisions.
    const lockUntil = (failedAttempts >= limits.maxAttempts - 1)
      ? new Date(now.getTime() + effectiveLockout).toISOString()
      : null;

    const { error: insertError } = await supabase
      .from('rate_limit_attempts')
      .insert({
        identifier,
        action,
        success: false,
        attempted_at: now.toISOString(),
        locked_until: lockUntil,
        ip_address: clientIp,
        user_agent: req.headers.get('user-agent') || 'unknown'
      });

    if (insertError) {
      console.error('Error recording rate limit attempt:', insertError);
    }

    // Clean up old attempts (older than 7 days for audit trail)
    const cleanupTime = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    await supabase
      .from('rate_limit_attempts')
      .delete()
      .lt('attempted_at', cleanupTime.toISOString());

    const attemptsRemaining = Math.max(0, limits.maxAttempts - failedAttempts - 1);

    return new Response(
      JSON.stringify({
        allowed: !lockUntil,
        attemptsRemaining,
        lockedUntil: lockUntil
      }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );

  } catch (error) {
    console.error('Rate limit error:', error);
    // SECURITY: Fail closed on error - deny access if rate limiting fails
    return new Response(
      JSON.stringify({
        allowed: false,
        attemptsRemaining: 0,
        error: "Rate limiting service unavailable"
      }),
      { status: 503, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
