import { useSyncExternalStore } from "react";

export type DesktopUpdateStage =
  | "idle"
  | "checking"
  | "upToDate"
  | "downloading"
  | "installing"
  | "restarting"
  | "error";

export interface DesktopUpdateState {
  visible: boolean;
  stage: DesktopUpdateStage;
  title: string;
  message: string;
  detail: string | null;
  progress: number | null;
  version: string | null;
}

const DEFAULT_STATE: DesktopUpdateState = {
  visible: false,
  stage: "idle",
  title: "",
  message: "",
  detail: null,
  progress: null,
  version: null,
};

let snapshot: DesktopUpdateState = DEFAULT_STATE;
const listeners = new Set<() => void>();

function emitChange() {
  listeners.forEach((listener) => listener());
}

export function setDesktopUpdateState(
  nextState: Partial<DesktopUpdateState>,
) {
  snapshot = {
    ...snapshot,
    ...nextState,
  };
  emitChange();
}

export function resetDesktopUpdateState() {
  snapshot = DEFAULT_STATE;
  emitChange();
}

export function getDesktopUpdateState(): DesktopUpdateState {
  return snapshot;
}

export function subscribeToDesktopUpdateState(listener: () => void) {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

export function useDesktopUpdateState(): DesktopUpdateState {
  return useSyncExternalStore(
    subscribeToDesktopUpdateState,
    getDesktopUpdateState,
    getDesktopUpdateState,
  );
}
