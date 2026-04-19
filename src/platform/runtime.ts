export function isTauriRuntime(): boolean {
  if (typeof window === "undefined") {
    return false;
  }

  return (
    "__TAURI_INTERNALS__" in window ||
    window.location.protocol === "tauri:" ||
    window.navigator.userAgent.toLowerCase().includes(" tauri/")
  );
}

export function getAppOrigin(): string {
  if (typeof window === "undefined") {
    return "";
  }

  return window.location.origin;
}
