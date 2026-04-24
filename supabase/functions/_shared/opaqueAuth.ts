export const OPAQUE_SESSION_BINDING_VERSION = "opaque-session-binding-v1";

export function normalizeOpaqueIdentifier(identifier: unknown): string {
    return String(identifier ?? "").trim().toLowerCase();
}

export function isValidOpaqueIdentifier(identifier: string): boolean {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(identifier);
}

export function createUnusableGotruePassword(): string {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    let binary = "";
    bytes.forEach((byte) => {
        binary += String.fromCharCode(byte);
    });
    return `${btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "")}.opaque-only`;
}

export async function sha256Hex(value: string): Promise<string> {
    const data = new TextEncoder().encode(value);
    const digest = await crypto.subtle.digest("SHA-256", data);
    return hexEncode(new Uint8Array(digest));
}

export async function createOpaqueSessionBindingProof(params: {
    sessionKey: string;
    userId: string;
    accessToken: string;
}): Promise<string> {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
        "raw",
        encoder.encode(params.sessionKey),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"],
    );
    const signature = await crypto.subtle.sign(
        "HMAC",
        key,
        encoder.encode(createOpaqueSessionBindingMessage(params.userId, params.accessToken)),
    );
    return hexEncode(new Uint8Array(signature));
}

export function createOpaqueSessionBindingMessage(userId: string, accessToken: string): string {
    return `${OPAQUE_SESSION_BINDING_VERSION}\n${userId}\n${accessToken}`;
}

function hexEncode(bytes: Uint8Array): string {
    return Array.from(bytes)
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join("");
}
