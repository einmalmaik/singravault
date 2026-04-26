// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { getCorsHeaders } from "../_shared/cors.ts";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY")!;
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

// Rate limiting configuration - HARDENED
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

interface RateLimitRequest {
  userId?: string;
  email?: string;
  action: 'unlock' | '2fa' | 'passkey' | 'emergency';
  success?: boolean; // Deprecated and ignored (cannot be trusted from client)
  ipAddress?: string; // Deprecated and ignored (cannot be trusted from client)
}

interface RateLimitResponse {
  allowed: boolean;
  attemptsRemaining: number;
  lockedUntil?: string;
}

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
