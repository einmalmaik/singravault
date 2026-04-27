import http from 'k6/http';
import exec from 'k6/execution';

const HTTP_TIMEOUT = __ENV.K6_HTTP_TIMEOUT || '30s';
const TOKEN_SPLIT_PATTERN = /[\r\n,;]+/;

const SUPABASE_URL = getRequiredEnv('SUPABASE_URL');
const SUPABASE_ANON_KEY = getAnyEnv(['SUPABASE_ANON_KEY', 'VITE_SUPABASE_PUBLISHABLE_KEY']);
if (!SUPABASE_ANON_KEY) {
  throw new Error('Missing SUPABASE_ANON_KEY (or VITE_SUPABASE_PUBLISHABLE_KEY)');
}

const TOKENS = loadTokenPool();
const USER_ID_BY_TOKEN = new Map();

function normalizeBaseUrl(url) {
  return String(url).replace(/\/+$/, '');
}

function getRequiredEnv(name) {
  const value = __ENV[name];
  if (!value || !String(value).trim()) {
    throw new Error(`Missing required env var ${name}`);
  }
  return String(value).trim();
}

function getAnyEnv(names) {
  for (const name of names) {
    const value = __ENV[name];
    if (value && String(value).trim()) {
      return String(value).trim();
    }
  }
  return '';
}

function parseStringList(raw) {
  return String(raw || '')
    .split(TOKEN_SPLIT_PATTERN)
    .map((value) => value.trim())
    .filter(Boolean);
}

function loadTokenPool() {
  const inline = parseStringList(__ENV.K6_TOKENS || '');
  if (inline.length > 0) return inline;

  if (__ENV.K6_TOKENS_FILE) {
    const fileContent = openWithFallback(String(__ENV.K6_TOKENS_FILE));
    return parseStringList(fileContent);
  }

  return [];
}

function openWithFallback(filePath) {
  const normalized = String(filePath).replace(/\\/g, '/');
  const candidates = [normalized];

  if (!normalized.startsWith('/') && !/^[a-zA-Z]:\//.test(normalized)) {
    candidates.push(`../${normalized}`);
    candidates.push(`../../${normalized}`);
  }

  let lastError = null;
  for (const candidate of candidates) {
    try {
      return open(candidate);
    } catch (error) {
      lastError = error;
    }
  }

  throw lastError || new Error(`Unable to open file: ${filePath}`);
}

function stringToHex(str) {
  let hex = '';
  for (let i = 0; i < str.length; i += 1) {
    hex += str.charCodeAt(i).toString(16).padStart(2, '0');
  }
  return hex;
}

export function getTokenForVu() {
  if (TOKENS.length === 0) {
    throw new Error('No bearer tokens provided. Set K6_TOKENS or K6_TOKENS_FILE.');
  }

  const vuId = Number(exec.vu.idInTest || 1);
  return TOKENS[(vuId - 1) % TOKENS.length];
}

export function getTokenPoolSize() {
  return TOKENS.length;
}

export function restUrl(pathAndQuery) {
  const path = String(pathAndQuery || '').replace(/^\/+/, '');
  return `${normalizeBaseUrl(SUPABASE_URL)}/rest/v1/${path}`;
}

export function authUrl(pathAndQuery) {
  const path = String(pathAndQuery || '').replace(/^\/+/, '');
  return `${normalizeBaseUrl(SUPABASE_URL)}/auth/v1/${path}`;
}

export function buildAuthHeaders(token, extraHeaders = {}) {
  return {
    apikey: SUPABASE_ANON_KEY,
    Authorization: `Bearer ${token}`,
    ...extraHeaders,
  };
}

export function buildRestParams(token, tags = {}, extraHeaders = {}) {
  return {
    headers: buildAuthHeaders(token, {
      Accept: 'application/json',
      ...extraHeaders,
    }),
    tags,
    timeout: HTTP_TIMEOUT,
  };
}

export function restGet(pathAndQuery, token, tags = {}) {
  return http.get(restUrl(pathAndQuery), buildRestParams(token, tags));
}

export function restPost(pathAndQuery, token, payload, { tags = {}, prefer = '' } = {}) {
  const headers = {
    'Content-Type': 'application/json',
  };
  if (prefer) {
    headers.Prefer = prefer;
  }

  return http.post(
    restUrl(pathAndQuery),
    JSON.stringify(payload),
    buildRestParams(token, tags, headers),
  );
}

export function restDelete(pathAndQuery, token, tags = {}) {
  return http.del(restUrl(pathAndQuery), null, buildRestParams(token, tags));
}

export function safeJson(response) {
  try {
    return response.json();
  } catch {
    return null;
  }
}

export function isStatusAllowed(response, allowedStatuses) {
  return Array.isArray(allowedStatuses) && allowedStatuses.includes(response.status);
}

export function authPasswordLogin(email, password, tags = {}) {
  void password;
  void tags;
  throw new Error(
    `Direct password-grant login is disabled for ${email}. Use an OPAQUE-capable login harness instead.`,
  );
}

export function fetchAuthenticatedUserId(token) {
  if (USER_ID_BY_TOKEN.has(token)) {
    return USER_ID_BY_TOKEN.get(token);
  }

  const response = http.get(authUrl('user'), {
    headers: buildAuthHeaders(token, {
      Accept: 'application/json',
    }),
    tags: { endpoint: 'auth_user' },
    timeout: HTTP_TIMEOUT,
  });

  if (response.status !== 200) {
    return null;
  }

  const payload = safeJson(response);
  const userId = payload && typeof payload.id === 'string' ? payload.id : null;
  if (userId) {
    USER_ID_BY_TOKEN.set(token, userId);
  }
  return userId;
}

export function fetchDefaultVaultId(token) {
  const response = restGet('vaults?select=id&is_default=eq.true&limit=1', token, {
    endpoint: 'vaults_default',
  });
  if (response.status !== 200) {
    return null;
  }

  const payload = safeJson(response);
  if (!Array.isArray(payload) || payload.length === 0) {
    return null;
  }

  const id = payload[0]?.id;
  return typeof id === 'string' ? id : null;
}

export function randomUuidV4(seed = '') {
  const seedHex = stringToHex(seed).padEnd(32, '0').slice(0, 32);
  let randomHex = '';
  while (randomHex.length < 32) {
    randomHex += Math.floor(Math.random() * 16).toString(16);
  }

  const hexChars = (seed ? seedHex : randomHex).split('');
  hexChars[12] = '4';
  hexChars[16] = ['8', '9', 'a', 'b'][Math.floor(Math.random() * 4)];

  const hex = hexChars.join('');
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join('-');
}

export function readCredentialsFromEnv() {
  let raw = String(__ENV.K6_LOGIN_USERS || '').trim();
  if (!raw && __ENV.K6_LOGIN_USERS_FILE) {
    raw = openWithFallback(String(__ENV.K6_LOGIN_USERS_FILE));
  }

  if (!raw.trim()) {
    return [];
  }

  const credentials = [];
  const lines = raw.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);

  for (const line of lines) {
    const commaSplit = line.split(',');
    const colonSplit = line.split(':');

    let email = '';
    let password = '';

    if (commaSplit.length >= 2) {
      email = commaSplit[0].trim();
      password = commaSplit.slice(1).join(',').trim();
    } else if (colonSplit.length >= 2) {
      email = colonSplit[0].trim();
      password = colonSplit.slice(1).join(':').trim();
    }

    if (email && password) {
      credentials.push({ email, password });
    }
  }

  return credentials;
}
