// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview SecureBuffer — Memory-safe wrapper for sensitive key material
 *
 * Provides a controlled way to handle sensitive binary data (like encryption keys)
 * with automatic zeroing on destruction. Inspired by KeePass CVE-2023-32784 which
 * demonstrated that memory dumps can expose key material in password managers.
 *
 * JavaScript Limitations:
 *   - No guaranteed memory wiping (GC is non-deterministic)
 *   - Strings are immutable (cannot be overwritten in-place)
 *   - ArrayBuffer contents CAN be overwritten via Uint8Array.fill(0)
 *
 * This class provides:
 *   1. Controlled access via callback (no leaked references)
 *   2. Explicit destroy() method that zeros the buffer
 *   3. FinalizationRegistry fallback if destroy() is forgotten
 *   4. Use-after-destroy detection
 *
 * SECURITY NOTE: This is defense-in-depth, not a guarantee.
 * Browser/V8 memory is still vulnerable to sophisticated attacks.
 *
 * @example
 * ```ts
 * const secret = SecureBuffer.fromBytes(keyBytes);
 * keyBytes.fill(0); // Zero the original
 *
 * // Access only via callback
 * const result = secret.use((data) => {
 *     return someCryptoOperation(data);
 * });
 *
 * // When done, explicitly destroy
 * secret.destroy();
 * ```
 */

// ============ FinalizationRegistry for Fallback Cleanup ============

// FinalizationRegistry is available in ES2021+ but tsconfig targets ES2020.
// Declare the type to satisfy TypeScript while runtime support is universal
// in modern browsers (Chrome 84+, Firefox 79+, Safari 14.1+).
declare class FinalizationRegistry<T> {
    constructor(callback: (heldValue: T) => void);
    register(target: object, heldValue: T, unregisterToken?: object): void;
    unregister(unregisterToken: object): void;
}

/**
 * Registry that auto-zeros buffers if they are garbage collected
 * without explicit destroy() call. This is a fallback — always
 * prefer calling destroy() explicitly.
 */
const cleanupRegistry = new FinalizationRegistry<Uint8Array>((buffer) => {
    try {
        buffer.fill(0);
    } catch {
        // Buffer may already be detached or GC'd
    }
});

// ============ SecureBuffer Class ============

/**
 * A wrapper for sensitive binary data with controlled access and
 * automatic memory zeroing.
 */
export class SecureBuffer {
    /** The underlying buffer holding sensitive data */
    private buffer: Uint8Array;

    /** Flag indicating if the buffer has been destroyed */
    private destroyed = false;

    /** Timestamp when the buffer was created (for debugging) */
    private readonly createdAt: number;

    /**
     * Creates a new SecureBuffer with the given size.
     * The buffer is initialized to zero.
     *
     * @param size - Number of bytes to allocate
     */
    constructor(size: number) {
        if (size <= 0 || !Number.isInteger(size)) {
            throw new Error('SecureBuffer size must be a positive integer');
        }
        this.buffer = new Uint8Array(size);
        this.createdAt = Date.now();

        // Register for fallback cleanup
        cleanupRegistry.register(this, this.buffer, this);
    }

    /**
     * Creates a SecureBuffer from existing bytes.
     * The source bytes are NOT automatically zeroed — caller should do that.
     *
     * @param bytes - Source bytes to copy into the secure buffer
     * @returns New SecureBuffer containing a copy of the bytes
     */
    static fromBytes(bytes: Uint8Array): SecureBuffer {
        const secure = new SecureBuffer(bytes.length);
        secure.buffer.set(bytes);
        return secure;
    }

    /**
     * Creates a SecureBuffer from a hex string.
     * SECURITY: The hex string cannot be securely wiped (JS strings are immutable),
     * but this method minimizes intermediate allocations.
     *
     * @param hex - Hexadecimal string (case-insensitive, spaces/dashes allowed)
     * @returns New SecureBuffer containing the decoded bytes
     * @throws Error if hex string is invalid
     */
    static fromHex(hex: string): SecureBuffer {
        // Remove any spaces or dashes for flexibility
        const cleanHex = hex.replace(/[\s-]/g, '');

        if (cleanHex.length % 2 !== 0) {
            throw new Error('Hex string must have even length');
        }

        const secure = new SecureBuffer(cleanHex.length / 2);

        for (let i = 0; i < secure.buffer.length; i++) {
            const hexByte = cleanHex.substr(i * 2, 2);
            const value = parseInt(hexByte, 16);

            if (isNaN(value)) {
                // Clear partial data before throwing
                secure.destroy();
                throw new Error(`Invalid hex byte at position ${i * 2}: ${hexByte}`);
            }

            secure.buffer[i] = value;
        }

        return secure;
    }

    /**
     * Creates a SecureBuffer filled with cryptographically secure random bytes.
     *
     * @param size - Number of random bytes to generate
     * @returns New SecureBuffer with random data
     */
    static random(size: number): SecureBuffer {
        const secure = new SecureBuffer(size);
        crypto.getRandomValues(secure.buffer);
        return secure;
    }

    /**
     * Provides controlled access to the buffer contents.
     * The callback receives the raw Uint8Array but should not store
     * references to it outside the callback scope.
     *
     * @param fn - Callback that receives the buffer and returns a result
     * @returns The result of the callback
     * @throws Error if the buffer has been destroyed
     */
    use<T>(fn: (data: Uint8Array) => T): T {
        if (this.destroyed) {
            throw new Error('SecureBuffer has been destroyed');
        }
        return fn(this.buffer);
    }

    /**
     * Provides async controlled access to the buffer contents.
     *
     * @param fn - Async callback that receives the buffer
     * @returns Promise resolving to the callback result
     * @throws Error if the buffer has been destroyed
     */
    async useAsync<T>(fn: (data: Uint8Array) => Promise<T>): Promise<T> {
        if (this.destroyed) {
            throw new Error('SecureBuffer has been destroyed');
        }
        return fn(this.buffer);
    }

    /**
     * Returns the size of the buffer in bytes.
     *
     * @returns Buffer size
     * @throws Error if the buffer has been destroyed
     */
    get size(): number {
        if (this.destroyed) {
            throw new Error('SecureBuffer has been destroyed');
        }
        return this.buffer.length;
    }

    /**
     * Checks if the buffer has been destroyed.
     *
     * @returns true if destroyed
     */
    get isDestroyed(): boolean {
        return this.destroyed;
    }

    /**
     * Zeros and marks the buffer as destroyed.
     * After this call, any attempt to access the buffer will throw.
     * Safe to call multiple times.
     */
    destroy(): void {
        if (this.destroyed) return;

        // Zero the buffer contents
        this.buffer.fill(0);

        // Unregister from FinalizationRegistry (no longer needed)
        cleanupRegistry.unregister(this);

        this.destroyed = true;
    }

    /**
     * Copies the buffer contents to a new Uint8Array.
     * Use sparingly — creates a copy that must be manually zeroed.
     *
     * @returns Copy of the buffer contents
     * @throws Error if the buffer has been destroyed
     */
    toBytes(): Uint8Array {
        if (this.destroyed) {
            throw new Error('SecureBuffer has been destroyed');
        }
        return new Uint8Array(this.buffer);
    }

    /**
     * Compares this buffer with another in constant time.
     * Prevents timing attacks when comparing secrets.
     *
     * @param other - Buffer to compare with
     * @returns true if buffers are equal
     * @throws Error if the buffer has been destroyed
     */
    equals(other: SecureBuffer | Uint8Array): boolean {
        if (this.destroyed) {
            throw new Error('SecureBuffer has been destroyed');
        }

        const otherBytes = other instanceof SecureBuffer ? other.buffer : other;

        if (this.buffer.length !== otherBytes.length) {
            return false;
        }

        // Constant-time comparison
        let result = 0;
        for (let i = 0; i < this.buffer.length; i++) {
            result |= this.buffer[i] ^ otherBytes[i];
        }
        return result === 0;
    }
}

// ============ Helper Functions ============

/**
 * Executes a function with a temporary SecureBuffer that is
 * automatically destroyed after use.
 *
 * @param bytes - Source bytes (will NOT be auto-zeroed)
 * @param fn - Function to execute with the secure buffer
 * @returns Result of the function
 */
export async function withSecureBuffer<T>(
    bytes: Uint8Array,
    fn: (secure: SecureBuffer) => Promise<T>,
): Promise<T> {
    const secure = SecureBuffer.fromBytes(bytes);
    try {
        return await fn(secure);
    } finally {
        secure.destroy();
    }
}

/**
 * Zeros multiple Uint8Array buffers.
 * Convenience function for cleanup.
 *
 * @param buffers - Buffers to zero
 */
export function zeroBuffers(...buffers: (Uint8Array | null | undefined)[]): void {
    for (const buffer of buffers) {
        if (buffer) {
            buffer.fill(0);
        }
    }
}
