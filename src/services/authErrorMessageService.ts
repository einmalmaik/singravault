import type { TFunction } from 'i18next';

export type StableAuthErrorCode =
  | 'ACCOUNT_ALREADY_EXISTS'
  | 'OPAQUE_RECORD_CONFLICT'
  | 'OPAQUE_REGISTRATION_FAILED'
  | 'AUTH_EMAIL_ALREADY_IN_USE'
  | 'AUTH_INVALID_OR_EXPIRED_CODE'
  | 'TOO_MANY_ATTEMPTS'
  | 'AUTH_REQUIRED'
  | 'FORBIDDEN'
  | 'SERVER_ERROR';

const RAW_TECHNICAL_ERROR_PATTERNS = [
  /23505/i,
  /duplicate key/i,
  /idx_user_opaque_records_identifier/i,
  /opaque failed/i,
  /opaque .*failed/i,
  /constraint/i,
];

export function getStableAuthErrorMessage(error: unknown, t: TFunction): string {
  const code = getStableAuthErrorCode(error);
  if (code) {
    return t(`auth.errorCodes.${code}`, { defaultValue: fallbackForCode(code) });
  }

  const message = error instanceof Error ? error.message : '';
  if (message && !RAW_TECHNICAL_ERROR_PATTERNS.some((pattern) => pattern.test(message))) {
    return message;
  }

  return t('auth.errorCodes.OPAQUE_REGISTRATION_FAILED', {
    defaultValue: fallbackForCode('OPAQUE_REGISTRATION_FAILED'),
  });
}

export function getStableAuthErrorCode(error: unknown): StableAuthErrorCode | null {
  const candidates: unknown[] = [];
  if (error instanceof Error) {
    candidates.push(error.name, error.message);
  }
  if (error && typeof error === 'object') {
    const record = error as Record<string, unknown>;
    candidates.push(record.code, record.error);
  }

  for (const candidate of candidates) {
    if (typeof candidate !== 'string') {
      continue;
    }
    if (isStableAuthErrorCode(candidate)) {
      return candidate;
    }
    if (/23505|duplicate key|idx_user_opaque_records_identifier/i.test(candidate)) {
      return 'OPAQUE_RECORD_CONFLICT';
    }
  }

  return null;
}

function isStableAuthErrorCode(value: string): value is StableAuthErrorCode {
  return [
    'ACCOUNT_ALREADY_EXISTS',
    'OPAQUE_RECORD_CONFLICT',
    'OPAQUE_REGISTRATION_FAILED',
    'AUTH_EMAIL_ALREADY_IN_USE',
    'AUTH_INVALID_OR_EXPIRED_CODE',
    'TOO_MANY_ATTEMPTS',
    'AUTH_REQUIRED',
    'FORBIDDEN',
    'SERVER_ERROR',
  ].includes(value);
}

function fallbackForCode(code: StableAuthErrorCode): string {
  switch (code) {
    case 'ACCOUNT_ALREADY_EXISTS':
    case 'AUTH_EMAIL_ALREADY_IN_USE':
    case 'OPAQUE_RECORD_CONFLICT':
      return 'An account with this email already exists.';
    case 'AUTH_INVALID_OR_EXPIRED_CODE':
      return 'The code is invalid or expired.';
    case 'TOO_MANY_ATTEMPTS':
      return 'Too many attempts. Please wait and try again.';
    case 'AUTH_REQUIRED':
      return 'Please sign in again.';
    case 'FORBIDDEN':
      return 'You do not have permission for this action.';
    case 'SERVER_ERROR':
      return 'Server error. Please try again.';
    case 'OPAQUE_REGISTRATION_FAILED':
    default:
      return 'Registration failed. Please try again.';
  }
}
