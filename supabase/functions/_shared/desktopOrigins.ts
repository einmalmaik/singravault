/**
 * Shared first-party desktop origins for Tauri/WebView surfaces.
 *
 * Keep this list aligned with the frontend runtime detection so Edge Function
 * CORS checks and WebAuthn RP/origin verification do not drift apart.
 */
export const FIRST_PARTY_DESKTOP_ORIGINS = [
    "tauri://localhost",
    "http://tauri.localhost",
    "https://tauri.localhost",
    "https://asset.localhost",
    "https://ipc.localhost",
] as const;

export const FIRST_PARTY_LOCAL_DEV_ORIGINS = [
    "http://localhost:8080",
    "http://127.0.0.1:8080",
] as const;

