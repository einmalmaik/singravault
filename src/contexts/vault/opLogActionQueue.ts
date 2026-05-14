// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

export type SerializedOpLogAction<T> = () => Promise<T>;

export interface OpLogActionQueue {
  run<T>(action: SerializedOpLogAction<T>): Promise<T>;
}

export function createOpLogActionQueue(): OpLogActionQueue {
  let tail: Promise<void> = Promise.resolve();

  return {
    run<T>(action: SerializedOpLogAction<T>): Promise<T> {
      const run = tail.then(action, action);
      tail = run.then(
        () => undefined,
        () => undefined,
      );
      return run;
    },
  };
}
