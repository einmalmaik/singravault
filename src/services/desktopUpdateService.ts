import { isTauriRuntime } from "@/platform/runtime";

export async function checkForDesktopUpdates(): Promise<void> {
  if (!isTauriRuntime()) {
    return;
  }

  try {
    const [{ check }, { relaunch }] = await Promise.all([
      import("@tauri-apps/plugin-updater"),
      import("@tauri-apps/plugin-process"),
    ]);

    const update = await check();
    if (!update) {
      return;
    }

    const shouldInstall = window.confirm(
      `Singra Vault ${update.version} ist verfuegbar. Jetzt installieren und neu starten?`,
    );

    if (!shouldInstall) {
      await update.close();
      return;
    }

    await update.downloadAndInstall();
    await relaunch();
  } catch (error) {
    console.warn("[desktopUpdateService] Update check failed:", error);
  }
}
