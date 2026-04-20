import { isTauriRuntime } from "./runtime";

export type TauriInvoke = <T>(command: string, args?: Record<string, unknown>) => Promise<T>;

export async function getTauriInvoke(): Promise<TauriInvoke | null> {
  if (!isTauriRuntime()) {
    return null;
  }

  try {
    const api = await import("@tauri-apps/api/core");
    return api.invoke as TauriInvoke;
  } catch {
    return null;
  }
}
