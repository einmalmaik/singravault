export function stableStringify(value: unknown): string {
  return JSON.stringify(toStableJson(value));
}

function toStableJson(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(toStableJson);
  }

  if (!value || typeof value !== 'object') {
    return value;
  }

  const record = value as Record<string, unknown>;
  return Object.keys(record)
    .sort((left, right) => left.localeCompare(right))
    .reduce<Record<string, unknown>>((result, key) => {
      const stableValue = toStableJson(record[key]);
      if (stableValue !== undefined) {
        result[key] = stableValue;
      }
      return result;
    }, {});
}

export async function sha256Base64(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return bytesToBase64(new Uint8Array(digest));
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let index = 0; index < bytes.length; index += 1) {
    binary += String.fromCharCode(bytes[index]);
  }

  return btoa(binary);
}

export function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}
