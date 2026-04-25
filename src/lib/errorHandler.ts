// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Global error handler for production-safe error responses
 *
 * SECURITY: Prevents information disclosure by:
 * - Mapping internal errors to generic error codes
 * - Hiding stack traces and implementation details
 * - Providing correlation IDs for debugging without exposing internals
 */

import { logger } from '@/lib/logger';

/**
 * Standard error codes exposed to clients
 */
export enum ErrorCode {
    // Authentication & Authorization
    AUTH_FAILED = 'ERR_AUTH_FAILED',
    AUTH_EXPIRED = 'ERR_AUTH_EXPIRED',
    AUTH_INVALID_CREDENTIALS = 'ERR_AUTH_INVALID_CREDENTIALS',
    AUTH_2FA_REQUIRED = 'ERR_AUTH_2FA_REQUIRED',
    AUTH_2FA_FAILED = 'ERR_AUTH_2FA_FAILED',
    AUTH_RATE_LIMITED = 'ERR_AUTH_RATE_LIMITED',

    // Vault Operations
    VAULT_LOCKED = 'ERR_VAULT_LOCKED',
    VAULT_SETUP_REQUIRED = 'ERR_VAULT_SETUP_REQUIRED',
    VAULT_DECRYPT_FAILED = 'ERR_VAULT_DECRYPT_FAILED',
    VAULT_ENCRYPT_FAILED = 'ERR_VAULT_ENCRYPT_FAILED',
    VAULT_INTEGRITY_FAILED = 'ERR_VAULT_INTEGRITY_FAILED',

    // Data Validation
    VALIDATION_FAILED = 'ERR_VALIDATION_FAILED',
    INVALID_INPUT = 'ERR_INVALID_INPUT',
    MISSING_REQUIRED_FIELD = 'ERR_MISSING_REQUIRED_FIELD',

    // Network & External Services
    NETWORK_ERROR = 'ERR_NETWORK_ERROR',
    SERVICE_UNAVAILABLE = 'ERR_SERVICE_UNAVAILABLE',
    TIMEOUT = 'ERR_TIMEOUT',

    // Generic
    UNKNOWN_ERROR = 'ERR_UNKNOWN',
    OPERATION_FAILED = 'ERR_OPERATION_FAILED',
    NOT_FOUND = 'ERR_NOT_FOUND',
    CONFLICT = 'ERR_CONFLICT',
    FORBIDDEN = 'ERR_FORBIDDEN',
}

/**
 * User-facing error with safe information
 */
export class AppError extends Error {
    constructor(
        public readonly code: ErrorCode,
        public readonly userMessage: string,
        public readonly correlationId: string = generateCorrelationId(),
        public readonly statusCode: number = 500,
        public readonly originalError?: Error
    ) {
        super(userMessage);
        this.name = 'AppError';
    }

    /**
     * Returns safe error object for client
     */
    toJSON() {
        return {
            error: {
                code: this.code,
                message: this.userMessage,
                correlationId: this.correlationId,
                timestamp: new Date().toISOString(),
            },
        };
    }
}

/**
 * Generates a correlation ID for error tracking
 */
function generateCorrelationId(): string {
    return `err-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

/**
 * Maps Supabase errors to safe error codes
 */
const SUPABASE_ERROR_MAP: Record<string, { code: ErrorCode; message: string }> = {
    'Invalid login credentials': {
        code: ErrorCode.AUTH_INVALID_CREDENTIALS,
        message: 'Invalid email or password',
    },
    'Email not confirmed': {
        code: ErrorCode.AUTH_FAILED,
        message: 'Please verify your email address',
    },
    'User already registered': {
        code: ErrorCode.CONFLICT,
        message: 'An account with this email already exists',
    },
    'JWT expired': {
        code: ErrorCode.AUTH_EXPIRED,
        message: 'Your session has expired. Please sign in again',
    },
    'Row level security violation': {
        code: ErrorCode.FORBIDDEN,
        message: 'You do not have permission to perform this action',
    },
    'Network request failed': {
        code: ErrorCode.NETWORK_ERROR,
        message: 'Network error. Please check your connection',
    },
};

/**
 * Maps error patterns to safe error codes
 */
const ERROR_PATTERNS: Array<{ pattern: RegExp; code: ErrorCode; message: string }> = [
    {
        pattern: /rate.?limit/i,
        code: ErrorCode.AUTH_RATE_LIMITED,
        message: 'Too many attempts. Please try again later',
    },
    {
        pattern: /timeout|timed.?out/i,
        code: ErrorCode.TIMEOUT,
        message: 'Request timed out. Please try again',
    },
    {
        pattern: /network|fetch|connection/i,
        code: ErrorCode.NETWORK_ERROR,
        message: 'Network error. Please check your connection',
    },
    {
        pattern: /decrypt|decryption/i,
        code: ErrorCode.VAULT_DECRYPT_FAILED,
        message: 'Unable to decrypt data. Wrong password or corrupted data',
    },
    {
        pattern: /encrypt|encryption/i,
        code: ErrorCode.VAULT_ENCRYPT_FAILED,
        message: 'Unable to encrypt data. Please try again',
    },
    {
        pattern: /integrity|tamper|corrupt/i,
        code: ErrorCode.VAULT_INTEGRITY_FAILED,
        message: 'Data integrity check failed',
    },
    {
        pattern: /2fa|totp|two.?factor/i,
        code: ErrorCode.AUTH_2FA_FAILED,
        message: 'Two-factor authentication failed',
    },
];

/**
 * Global error handler that converts any error to a safe AppError
 */
export function handleError(error: unknown, context?: Record<string, unknown>): AppError {
    const correlationId = generateCorrelationId();

    // Already an AppError
    if (error instanceof AppError) {
        return error;
    }

    // Extract error details
    let errorMessage = 'An unexpected error occurred';
    let errorCode = ErrorCode.UNKNOWN_ERROR;
    let statusCode = 500;
    let originalError: Error | undefined;

    if (error instanceof Error) {
        originalError = error;
        errorMessage = error.message;

        // Check Supabase error mappings
        for (const [pattern, mapping] of Object.entries(SUPABASE_ERROR_MAP)) {
            if (errorMessage.includes(pattern)) {
                errorCode = mapping.code;
                errorMessage = mapping.message;
                break;
            }
        }

        // Check error patterns if no exact match
        if (errorCode === ErrorCode.UNKNOWN_ERROR) {
            for (const { pattern, code, message } of ERROR_PATTERNS) {
                if (pattern.test(errorMessage)) {
                    errorCode = code;
                    errorMessage = message;
                    break;
                }
            }
        }

        // Map HTTP-like status codes
        if ('status' in error && typeof error.status === 'number') {
            statusCode = error.status;
            switch (error.status) {
                case 401:
                    errorCode = ErrorCode.AUTH_FAILED;
                    errorMessage = 'Authentication required';
                    break;
                case 403:
                    errorCode = ErrorCode.FORBIDDEN;
                    errorMessage = 'Access denied';
                    break;
                case 404:
                    errorCode = ErrorCode.NOT_FOUND;
                    errorMessage = 'Resource not found';
                    break;
                case 409:
                    errorCode = ErrorCode.CONFLICT;
                    errorMessage = 'Conflict with existing data';
                    break;
                case 429:
                    errorCode = ErrorCode.AUTH_RATE_LIMITED;
                    errorMessage = 'Too many requests. Please try again later';
                    break;
                case 503:
                    errorCode = ErrorCode.SERVICE_UNAVAILABLE;
                    errorMessage = 'Service temporarily unavailable';
                    break;
            }
        }
    } else if (typeof error === 'string') {
        errorMessage = error;
    }

    // Log the full error details (sanitized by logger)
    logger.error('Error handled', originalError || error, {
        correlationId,
        errorCode,
        ...context,
    });

    // Return safe error for client
    return new AppError(
        errorCode,
        errorMessage,
        correlationId,
        statusCode,
        originalError
    );
}

/**
 * React error boundary error handler
 */
export function handleReactError(
    error: Error,
    errorInfo: { componentStack: string }
): AppError {
    const appError = handleError(error, {
        source: 'React ErrorBoundary',
        componentStack: errorInfo.componentStack,
    });

    // In production, show generic message for React errors
    if (!import.meta.env.DEV) {
        return new AppError(
            appError.code,
            'Something went wrong. Please refresh the page.',
            appError.correlationId,
            appError.statusCode,
            appError.originalError
        );
    }

    return appError;
}

/**
 * Async wrapper that catches and handles errors
 */
export async function withErrorHandling<T>(
    fn: () => Promise<T>,
    context?: Record<string, unknown>
): Promise<T> {
    try {
        return await fn();
    } catch (error) {
        throw handleError(error, context);
    }
}

/**
 * Type guard for AppError
 */
export function isAppError(error: unknown): error is AppError {
    return error instanceof AppError;
}

/**
 * Extracts safe error message for display
 */
export function getErrorMessage(error: unknown): string {
    if (isAppError(error)) {
        return error.userMessage;
    }

    if (error instanceof Error) {
        // In development, show actual error message
        if (import.meta.env.DEV) {
            return error.message;
        }
    }

    return 'An unexpected error occurred';
}
