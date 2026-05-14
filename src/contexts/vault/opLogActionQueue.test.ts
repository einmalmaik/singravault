import { describe, expect, it } from 'vitest';

import { createOpLogActionQueue } from './opLogActionQueue';

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });

  return { promise, resolve, reject };
}

describe('createOpLogActionQueue', () => {
  it('runs signed vault actions sequentially even when callers fire in parallel', async () => {
    const queue = createOpLogActionQueue();
    const firstGate = deferred<string>();
    const events: string[] = [];

    const first = queue.run(async () => {
      events.push('first:start');
      const value = await firstGate.promise;
      events.push('first:end');
      return value;
    });
    const second = queue.run(async () => {
      events.push('second:start');
      return 'second-result';
    });

    await Promise.resolve();
    expect(events).toEqual(['first:start']);

    firstGate.resolve('first-result');

    await expect(first).resolves.toBe('first-result');
    await expect(second).resolves.toBe('second-result');
    expect(events).toEqual(['first:start', 'first:end', 'second:start']);
  });

  it('continues with the next action after a failed action', async () => {
    const queue = createOpLogActionQueue();
    const events: string[] = [];

    const first = queue.run(async () => {
      events.push('first:start');
      throw new Error('first-failed');
    });
    const second = queue.run(async () => {
      events.push('second:start');
      return 'second-result';
    });

    await expect(first).rejects.toThrow('first-failed');
    await expect(second).resolves.toBe('second-result');
    expect(events).toEqual(['first:start', 'second:start']);
  });
});
