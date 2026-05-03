# Security Hardening Updates (2026-02-19)

This document records critical security fixes applied on February 19, 2026.

## Summary

1. Duress unlock now derives keys with the correct KDF version while keeping dual-derive behavior to limit timing leaks.
2. Emergency access trustee updates are validated via trigger logic (no invalid RLS references), aligned to real schema fields.
3. Server-side rate-limit schema updated to match Edge Function payload (emergency action + user_agent).
4. Backup code hashing migration completed (hash_version column) with legacy verification fallback restored.
5. Security tests stabilized to reflect real schema and deterministic validation of constant-structure unlock behavior.
6. Follow-up hardening removed client-controlled `ipAddress` and `success` from lockout enforcement decisions in the rate-limit Edge Function; IP is now derived only from trusted proxy headers.
7. Generated Supabase TypeScript schema was synchronized with `backup_codes.hash_version`.
