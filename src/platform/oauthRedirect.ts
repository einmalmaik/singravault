import { isTauriRuntime } from "./runtime";

export function getOAuthRedirectUrl(): string {
  if (isTauriRuntime()) {
    return "singravault://auth/callback";
  }

  return `${window.location.origin}/auth`;
}
