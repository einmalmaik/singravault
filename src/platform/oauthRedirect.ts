import { isTauriRuntime } from "./runtime";
import { runtimeConfig } from "@/config/runtimeConfig";

export function getOAuthRedirectUrl(): string {
  if (isTauriRuntime()) {
    // We use the web URL as a bounce page to ensure compatibility with 
    // OAuth providers that don't allow custom schemes (like singravault://).
    const webUrl = runtimeConfig.webUrl;
    return `${webUrl}/auth?source=tauri`;
  }

  return `${window.location.origin}/auth`;
}
