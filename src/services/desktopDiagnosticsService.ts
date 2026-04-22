import { isTauriRuntime } from '@/platform/runtime';

const DESKTOP_LOG_PREFIX = 'desktop-runtime';
const DESKTOP_LOG_BUFFER_KEY = 'singra-desktop-diagnostics-buffer';
const MAX_BUFFERED_LINES = 200;
const MAX_SERIALIZED_ARG_LENGTH = 4000;

let consoleMirroringInstalled = false;
let writeQueue: Promise<void> = Promise.resolve();
let resolvedDesktopLogPath: Promise<string | null> | null = null;
let ensuredDesktopLogDirectory = false;

export function installDesktopConsoleMirroring(): void {
  if (consoleMirroringInstalled || !isTauriRuntime()) {
    return;
  }

  consoleMirroringInstalled = true;

  const originalConsole = {
    debug: console.debug.bind(console),
    info: console.info.bind(console),
    warn: console.warn.bind(console),
    error: console.error.bind(console),
  };

  for (const level of ['debug', 'info', 'warn', 'error'] as const) {
    console[level] = (...args: unknown[]) => {
      originalConsole[level](...args);
      void appendDesktopDiagnosticLine(level, args);
    };
  }

  void getDesktopDiagnosticLogPath().then((logPath) => {
    void appendDesktopDiagnosticLine('info', [
      '[Diagnostics] Desktop console mirroring initialized.',
      {
        fileName: getDesktopDiagnosticLogFileName(),
        logPath,
      },
    ]);
  });
}

export function getDesktopDiagnosticLogFileName(date: Date = new Date()): string {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${DESKTOP_LOG_PREFIX}-${year}-${month}-${day}.log`;
}

export async function getDesktopDiagnosticLogPath(): Promise<string | null> {
  if (!isTauriRuntime()) {
    return null;
  }

  if (!resolvedDesktopLogPath) {
    resolvedDesktopLogPath = (async () => {
      try {
        const [{ appLogDir, join }] = await Promise.all([
          import('@tauri-apps/api/path'),
        ]);
        const logDir = await appLogDir();
        return await join(logDir, getDesktopDiagnosticLogFileName());
      } catch {
        return null;
      }
    })();
  }

  return resolvedDesktopLogPath;
}

async function appendDesktopDiagnosticLine(
  level: 'debug' | 'info' | 'warn' | 'error',
  args: unknown[],
): Promise<void> {
  if (!isTauriRuntime()) {
    return;
  }

  const line = formatDiagnosticLine(level, args);

  writeQueue = writeQueue
    .catch(() => undefined)
    .then(async () => {
      const { BaseDirectory, writeTextFile } = await import('@tauri-apps/plugin-fs');
      await ensureDesktopLogDirectoryExists(BaseDirectory.AppLog);
      await writeTextFile(
        getDesktopDiagnosticLogFileName(),
        line,
        {
          append: true,
          create: true,
          baseDir: BaseDirectory.AppLog,
        },
      );
    })
    .catch(() => {
      persistDiagnosticLineFallback(line);
    });

  await writeQueue;
}

function formatDiagnosticLine(level: string, args: unknown[]): string {
  const timestamp = new Date().toISOString();
  const message = args.map(serializeDiagnosticArgument).join(' ');
  return `[${timestamp}] [${level.toUpperCase()}] ${message}\n`;
}

function serializeDiagnosticArgument(value: unknown): string {
  if (value instanceof Error) {
    return truncateSerializedValue(
      JSON.stringify({
        name: value.name,
        message: value.message,
        stack: value.stack,
      }),
    );
  }

  if (typeof value === 'string') {
    return truncateSerializedValue(value);
  }

  if (typeof value === 'number' || typeof value === 'boolean' || value === null || value === undefined) {
    return String(value);
  }

  try {
    return truncateSerializedValue(JSON.stringify(value));
  } catch {
    return truncateSerializedValue(String(value));
  }
}

function truncateSerializedValue(value: string): string {
  if (value.length <= MAX_SERIALIZED_ARG_LENGTH) {
    return value;
  }

  return `${value.slice(0, MAX_SERIALIZED_ARG_LENGTH)}...[truncated]`;
}

function persistDiagnosticLineFallback(line: string): void {
  if (typeof window === 'undefined') {
    return;
  }

  try {
    const existing = window.localStorage.getItem(DESKTOP_LOG_BUFFER_KEY);
    const nextLines = existing ? JSON.parse(existing) as string[] : [];
    nextLines.push(line);

    if (nextLines.length > MAX_BUFFERED_LINES) {
      nextLines.splice(0, nextLines.length - MAX_BUFFERED_LINES);
    }

    window.localStorage.setItem(DESKTOP_LOG_BUFFER_KEY, JSON.stringify(nextLines));
  } catch {
    // Best-effort diagnostics only.
  }
}

async function ensureDesktopLogDirectoryExists(baseDir: number): Promise<void> {
  if (ensuredDesktopLogDirectory) {
    return;
  }

  const { mkdir } = await import('@tauri-apps/plugin-fs');
  await mkdir('.', {
    baseDir,
    recursive: true,
  });
  ensuredDesktopLogDirectory = true;
}
