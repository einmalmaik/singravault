import { isTauriRuntime } from "./runtime";

export type AppShellMode = "web" | "desktop";

export function getAppShellMode(): AppShellMode {
  return isTauriRuntime() ? "desktop" : "web";
}

export function isDesktopAppShell(): boolean {
  return getAppShellMode() === "desktop";
}

export function shouldShowWebsiteChrome(): boolean {
  return !isDesktopAppShell();
}

export function getPrimaryAppPath(): string {
  return isDesktopAppShell() ? "/vault" : "/";
}

export function getSubscriptionEntryPath(): string {
  return "/pricing";
}
