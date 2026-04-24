# AuthContext — Authentication State

> **File:** `src/contexts/AuthContext.tsx`
> **Purpose:** Holds React-facing auth state and exposes logout. It does not implement app-password login.

## Boundary

`AuthContext` is intentionally thin. It tracks the current Supabase session/user, hydrates persisted sessions via `authSessionManager`, and signs out. Login flows live in `src/pages/Auth.tsx`:

- App-owned password login: OPAQUE only (`auth-opaque`).
- OAuth/social login: Supabase OAuth + `auth-session` `oauth-sync`.
- Vault unlock/master password: separate vault flow after an app session exists.

`AuthContext` must not call `supabase.auth.signInWithPassword()` and must not accept an app password.

## Context Interface

```typescript
interface AuthContextType {
  user: User | null;
  session: Session | null;
  loading: boolean;
  authReady: boolean;
  authMode: AuthMode;
  isOfflineSession: boolean;
  signOut: () => Promise<void>;
}
```

## Initialization

1. Registers `supabase.auth.onAuthStateChange()`.
2. Hydrates an existing session via `hydrateAuthSession()`.
3. Applies session/user state when a valid session exists.
4. Supports the local Tauri dev bypass when explicitly enabled.

## Sign Out

`signOut()` clears local persistence, signs out of Supabase memory auth, and deletes the BFF session cookie through `auth-session` `DELETE` in normal web runtime.

`auth-session` is not a password-login endpoint. Its current responsibilities are session hydration/logout and OAuth sync only.
