import { base64URLStringToBuffer } from "@simplewebauthn/browser";

export interface AuthenticationPrfExtensionInput {
  evalByCredential: Record<string, { first: ArrayBuffer }>;
}

/**
 * `get()` uses `prf.evalByCredential`, even when only one credential is in play.
 * `prf.eval` is only valid for credential creation.
 */
export function buildAuthenticationPrfExtension(
  prfSalts: Record<string, string>,
): AuthenticationPrfExtensionInput | undefined {
  const credentialIds = Object.keys(prfSalts);

  if (credentialIds.length === 0) {
    return undefined;
  }

  const evalByCredential: Record<string, { first: ArrayBuffer }> = {};

  for (const [credentialId, salt] of Object.entries(prfSalts)) {
    evalByCredential[credentialId] = {
      first: base64URLStringToBuffer(salt),
    };
  }

  return { evalByCredential };
}
