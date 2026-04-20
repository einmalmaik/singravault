import { isTauriRuntime } from "./runtime";

type Unlisten = () => void;

export async function getInitialDeepLinks(): Promise<string[]> {
  if (!isTauriRuntime()) {
    return [];
  }

  try {
    const { getCurrent } = await import("@tauri-apps/plugin-deep-link");
    return (await getCurrent()) ?? [];
  } catch {
    return [];
  }
}

export async function listenForDeepLinks(handler: (urls: string[]) => void): Promise<Unlisten> {
  if (!isTauriRuntime()) {
    return () => undefined;
  }

  try {
    const { onOpenUrl } = await import("@tauri-apps/plugin-deep-link");
    return await onOpenUrl(handler);
  } catch (err) {
    console.error("[DeepLink] Failed to register listeners:", err);
    return () => undefined;
  }
}
