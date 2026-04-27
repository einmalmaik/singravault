// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Centralized logging service with environment-based filtering
 *
 * SECURITY: Prevents information disclosure in production by:
 * - Filtering log levels based on environment
 * - Sanitizing sensitive data before logging
 * - Providing structured logging with correlation IDs
 */

type LogLevel = 'debug' | 'info' | 'warn' | 'error';

interface LogContext {
    [key: string]: unknown;
}

class Logger {
    private readonly isDevelopment: boolean;
    private readonly isTest: boolean;
    private readonly correlationId: string;
    private readonly sensitiveKeys = new Set([
        'password',
        'masterPassword',
        'secret',
        'token',
        'key',
        'salt',
        'verifier',
        'hash',
        'encryptedKey',
        'privateKey',
        'publicKey',
        'apiKey',
        'sessionToken',
        'authToken',
        'refreshToken',
        'accessToken',
        'totpSecret',
        'backupCode',
        'encryptedData',
        'decryptedData',
    ]);

    constructor() {
        // Determine environment
        this.isDevelopment = import.meta.env.DEV || process.env.NODE_ENV === 'development';
        this.isTest = process.env.NODE_ENV === 'test';

        // Generate correlation ID for this session
        this.correlationId = this.generateCorrelationId();
    }

    private generateCorrelationId(): string {
        return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    }

    /**
     * Sanitizes sensitive data from objects before logging
     */
    private sanitize(data: unknown): unknown {
        if (data === null || data === undefined) {
            return data;
        }

        if (typeof data === 'string') {
            return data;
        }

        if (typeof data === 'object') {
            const source = data as Record<string, unknown>;
            const sanitized: Record<string, unknown> | unknown[] = Array.isArray(data) ? [] : {};

            for (const key in source) {
                if (Object.prototype.hasOwnProperty.call(source, key)) {
                    const lowerKey = key.toLowerCase();

                    // Check if key contains sensitive terms
                    const isSensitive = Array.from(this.sensitiveKeys).some(
                        sensitive => lowerKey.includes(sensitive)
                    );

                    if (isSensitive) {
                        sanitized[key] = '[REDACTED]';
                    } else if (typeof source[key] === 'object') {
                        sanitized[key] = this.sanitize(source[key]);
                    } else {
                        sanitized[key] = source[key];
                    }
                }
            }

            return sanitized;
        }

        return data;
    }

    /**
     * Formats the log message with metadata
     */
    private format(level: LogLevel, message: string, context?: LogContext): string {
        const timestamp = new Date().toISOString();
        const sanitizedContext = context ? this.sanitize(context) : undefined;

        const logData = {
            timestamp,
            level,
            correlationId: this.correlationId,
            message,
            ...(sanitizedContext && { context: sanitizedContext }),
        };

        // In production, return structured JSON
        if (!this.isDevelopment && !this.isTest) {
            return JSON.stringify(logData);
        }

        // In development, return readable format
        const prefix = `[${timestamp}] [${level.toUpperCase()}]`;
        const contextStr = sanitizedContext
            ? `\n  Context: ${JSON.stringify(sanitizedContext, null, 2)}`
            : '';

        return `${prefix} ${message}${contextStr}`;
    }

    /**
     * Determines if a log should be output based on level and environment
     */
    private shouldLog(level: LogLevel): boolean {
        // In test environment, only log errors to reduce noise
        if (this.isTest) {
            return level === 'error';
        }

        // In production, only log warnings and errors
        if (!this.isDevelopment) {
            return level === 'warn' || level === 'error';
        }

        // In development, log everything
        return true;
    }

    /**
     * Debug level - detailed information for debugging
     * Only visible in development
     */
    debug(message: string, context?: LogContext): void {
        if (this.shouldLog('debug')) {
            console.debug(this.format('debug', message, context));
        }
    }

    /**
     * Info level - general informational messages
     * Only visible in development
     */
    info(message: string, context?: LogContext): void {
        if (this.shouldLog('info')) {
            console.info(this.format('info', message, context));
        }
    }

    /**
     * Warning level - potentially harmful situations
     * Visible in production
     */
    warn(message: string, context?: LogContext): void {
        if (this.shouldLog('warn')) {
            console.warn(this.format('warn', message, context));
        }
    }

    /**
     * Error level - error events that might still allow the app to continue
     * Always visible
     */
    error(message: string, error?: Error | unknown, context?: LogContext): void {
        if (this.shouldLog('error')) {
            const errorContext: LogContext = {
                ...context,
            };

            if (error instanceof Error) {
                errorContext.errorName = error.name;
                errorContext.errorMessage = error.message;

                // Only include stack trace in development
                if (this.isDevelopment) {
                    errorContext.errorStack = error.stack;
                }
            } else if (error) {
                errorContext.error = String(error);
            }

            console.error(this.format('error', message, errorContext));
        }
    }

    /**
     * Creates a child logger with additional context
     */
    withContext(context: LogContext): LoggerWithContext {
        return new LoggerWithContext(this, context);
    }

    /**
     * Measures and logs the execution time of an async function
     */
    async measureAsync<T>(
        name: string,
        fn: () => Promise<T>,
        context?: LogContext
    ): Promise<T> {
        const start = performance.now();

        try {
            const result = await fn();
            const duration = performance.now() - start;

            this.debug(`${name} completed`, {
                ...context,
                durationMs: Math.round(duration),
            });

            return result;
        } catch (error) {
            const duration = performance.now() - start;

            this.error(`${name} failed`, error, {
                ...context,
                durationMs: Math.round(duration),
            });

            throw error;
        }
    }
}

/**
 * Logger with pre-configured context
 */
class LoggerWithContext {
    constructor(
        private readonly logger: Logger,
        private readonly context: LogContext
    ) {}

    debug(message: string, additionalContext?: LogContext): void {
        this.logger.debug(message, { ...this.context, ...additionalContext });
    }

    info(message: string, additionalContext?: LogContext): void {
        this.logger.info(message, { ...this.context, ...additionalContext });
    }

    warn(message: string, additionalContext?: LogContext): void {
        this.logger.warn(message, { ...this.context, ...additionalContext });
    }

    error(message: string, error?: Error | unknown, additionalContext?: LogContext): void {
        this.logger.error(message, error, { ...this.context, ...additionalContext });
    }
}

// Export singleton instance
export const logger = new Logger();

// Export type for use in components
export type { LogLevel, LogContext };
