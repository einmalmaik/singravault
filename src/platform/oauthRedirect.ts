import { isTauriRuntime } from "./runtime";
import { TAURI_OAUTH_CALLBACK_URL } from "./tauriOAuthCallback";

export function getOAuthRedirectUrl(): string {
  if (isTauriRuntime()) {
    return TAURI_OAUTH_CALLBACK_URL;
  }

  return `${window.location.origin}/auth`;
}
