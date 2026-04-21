export function isTauriRuntime(): boolean {
  if (typeof window === "undefined") {
    return false;
  }

  const hostname = window.location.hostname.toLowerCase();

  return (
    "__TAURI_INTERNALS__" in window ||
    window.location.protocol === "tauri:" ||
    hostname === "tauri.localhost" ||
    hostname === "asset.localhost" ||
    hostname === "ipc.localhost" ||
    window.navigator.userAgent.toLowerCase().includes(" tauri/")
  );
}

export function getAppOrigin(): string {
  if (typeof window === "undefined") {
    return "";
  }

  return window.location.origin;
}
