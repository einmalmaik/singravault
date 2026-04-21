import { isTauriRuntime } from "@/platform/runtime";
import {
  resetDesktopUpdateState,
  setDesktopUpdateState,
} from "@/services/desktopUpdateStore";

const SUCCESS_DISMISS_DELAY_MS = 900;
const ERROR_DISMISS_DELAY_MS = 1800;

let pendingCheck: Promise<void> | null = null;

export async function checkForDesktopUpdates(): Promise<void> {
  if (!isTauriRuntime() || import.meta.env.DEV) {
    return;
  }

  if (pendingCheck) {
    return pendingCheck;
  }

  pendingCheck = runDesktopUpdateCheck().finally(() => {
    pendingCheck = null;
  });

  return pendingCheck;
}

async function runDesktopUpdateCheck(): Promise<void> {
  setDesktopUpdateState({
    visible: true,
    stage: "checking",
    title: "Prüfe auf Updates",
    message:
      "Singra Vault gleicht diese Desktop-Installation mit dem neuesten Release ab.",
    detail: "Bitte einen Moment warten",
    progress: null,
    version: null,
  });

  let updateHandle:
    | {
        version: string;
        close: () => Promise<void>;
        downloadAndInstall: (
          onEvent?: (event: {
            event: "Started" | "Progress" | "Finished";
            data?: { contentLength?: number; chunkLength?: number };
          }) => void,
        ) => Promise<void>;
      }
    | null = null;

  try {
    const [{ check }, { relaunch }] = await Promise.all([
      import("@tauri-apps/plugin-updater"),
      import("@tauri-apps/plugin-process"),
    ]);

    updateHandle = await check();

    if (!updateHandle) {
      setDesktopUpdateState({
        stage: "upToDate",
        title: "Aktueller Stand",
        message: "Diese Installation ist bereits auf dem neuesten Stand.",
        detail: "Die App wird jetzt geöffnet",
        progress: 100,
        version: null,
      });
      await wait(SUCCESS_DISMISS_DELAY_MS);
      resetDesktopUpdateState();
      return;
    }

    setDesktopUpdateState({
      stage: "downloading",
      title: `Update ${updateHandle.version} wird vorbereitet`,
      message:
        "Das Update wird geladen und anschließend automatisch installiert.",
      detail: "Download wird gestartet",
      progress: 0,
      version: updateHandle.version,
    });

    let totalBytes: number | null = null;
    let downloadedBytes = 0;

    await updateHandle.downloadAndInstall((event) => {
      switch (event.event) {
        case "Started":
          totalBytes = event.data?.contentLength ?? null;
          downloadedBytes = 0;
          setDesktopUpdateState({
            stage: "downloading",
            detail: totalBytes
              ? "Download läuft"
              : "Downloadgröße wird vorbereitet",
            progress: 8,
          });
          break;
        case "Progress": {
          downloadedBytes += event.data?.chunkLength ?? 0;
          const progress = totalBytes
            ? Math.min(100, Math.round((downloadedBytes / totalBytes) * 100))
            : null;
          setDesktopUpdateState({
            stage: "downloading",
            detail: progress ? `${progress}% geladen` : "Download läuft",
            progress,
          });
          break;
        }
        case "Finished":
          setDesktopUpdateState({
            stage: "installing",
            title: `Update ${updateHandle?.version ?? ""} wird installiert`,
            message:
              "Die neue Version wird eingebunden. Danach startet Singra Vault neu.",
            detail: "Installation wird abgeschlossen",
            progress: 100,
          });
          break;
      }
    });

    setDesktopUpdateState({
      stage: "restarting",
      title: "Neustart",
      message:
        "Die neue Version ist installiert. Singra Vault startet jetzt neu.",
      detail: "Desktop-App wird neu gestartet",
      progress: 100,
    });
    await relaunch();
  } catch (error) {
    console.warn("[desktopUpdateService] Update check failed:", error);
    setDesktopUpdateState({
      visible: true,
      stage: "error",
      title: "Updateprüfung fehlgeschlagen",
      message:
        "Die App startet normal weiter. Beim nächsten Start wird erneut geprüft.",
      detail: error instanceof Error ? error.message : "Unbekannter Fehler",
      progress: 100,
    });
    await wait(ERROR_DISMISS_DELAY_MS);
    resetDesktopUpdateState();
  } finally {
    if (updateHandle) {
      await updateHandle.close().catch(() => undefined);
    }
  }
}

function wait(durationMs: number): Promise<void> {
  return new Promise((resolve) => {
    window.setTimeout(resolve, durationMs);
  });
}
