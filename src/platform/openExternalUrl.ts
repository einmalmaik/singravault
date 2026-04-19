import { isTauriRuntime } from "./runtime";

const ALLOWED_EXTERNAL_PROTOCOLS = new Set(["http:", "https:", "mailto:"]);

export async function openExternalUrl(url: string): Promise<void> {
  const parsed = new URL(url, typeof window === "undefined" ? "https://singrapw.mauntingstudios.de" : window.location.href);

  if (!ALLOWED_EXTERNAL_PROTOCOLS.has(parsed.protocol)) {
    throw new Error(`Unsupported external URL protocol: ${parsed.protocol}`);
  }

  if (isTauriRuntime()) {
    const { openUrl } = await import("@tauri-apps/plugin-opener");
    await openUrl(parsed.toString());
    return;
  }

  window.open(parsed.toString(), "_blank", "noopener,noreferrer");
}
