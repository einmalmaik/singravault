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

  const unlistens: Unlisten[] = [];

  try {
    // 1. Standard Tauri v2 Deep Link Plugin
    const { onOpenUrl } = await import("@tauri-apps/plugin-deep-link");
    const stdUnlisten = await onOpenUrl(handler);
    unlistens.push(stdUnlisten);

    // 2. Custom Fallback for Windows single-instance args
    const { listen } = await import("@tauri-apps/api/event");
    const customUnlisten = await listen<string[]>("singra://deep-link", (event) => {
      // Filter out the executable path itself, only return valid URIs
      const urls = event.payload.filter(arg => arg.startsWith('singravault://'));
      if (urls.length > 0) {
        handler(urls);
      }
    });
    unlistens.push(customUnlisten);

  } catch (err) {
    console.error("[DeepLink] Failed to register listeners:", err);
  }

  return () => {
    unlistens.forEach(fn => fn());
  };
}
