import { isTauriRuntime } from "./runtime";

type Unlisten = () => void;
const SINGLE_INSTANCE_DEEP_LINK_EVENT = "singra://deep-link";

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

  const unlistenCallbacks: Unlisten[] = [];

  try {
    const { onOpenUrl } = await import("@tauri-apps/plugin-deep-link");
    unlistenCallbacks.push(await onOpenUrl(handler));
  } catch (err) {
    console.error("[DeepLink] Failed to register listeners:", err);
  }

  try {
    const { listen } = await import("@tauri-apps/api/event");
    const unlisten = await listen<string[]>(SINGLE_INSTANCE_DEEP_LINK_EVENT, (event) => {
      if (Array.isArray(event.payload) && event.payload.length > 0) {
        handler(event.payload);
      }
    });
    unlistenCallbacks.push(unlisten);
  } catch (err) {
    console.error("[DeepLink] Failed to register single-instance listener:", err);
  }

  return () => {
    unlistenCallbacks.forEach((unlisten) => unlisten());
  };
}
