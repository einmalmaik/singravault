#!/usr/bin/env node
// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';

const repoRoot = process.cwd();
const findings = [];

const forbiddenTrackedPathPatterns = [
  /^\.env(?:\..*)?$/i,
  /^loadtest\/(?:tokens|users)\.txt$/i,
  /^src-tauri\/singra-vault-(?:safe-mode-)?export-\d{4}-\d{2}-\d{2}\.json$/i,
  /^src-tauri\/.*(?:backup-codes|recovery|rettung).*\.txt$/i,
  /^public\/.*(?:backup|recovery|rettung|secret|private|key).*$/i,
  /\.(?:pem|p12|pfx)$/i,
];

const forbiddenWorkspacePathPatterns = [
  /^src-tauri\/singra-vault-(?:safe-mode-)?export-.*\.json$/i,
  /^src-tauri\/.*(?:backup-codes|recovery|rettung).*\.txt$/i,
  /^public\/.*(?:backup|recovery|rettung|secret|private|key).*$/i,
];

const ignoredDirs = new Set([
  '.git',
  '.codex-artifacts',
  '.codex-logs',
  'node_modules',
  'dist',
  'build',
  'src-tauri/target',
  'src-tauri/gen',
]);

for (const trackedPath of getTrackedFiles()) {
  const normalized = normalizePath(trackedPath);
  if (forbiddenTrackedPathPatterns.some((pattern) => pattern.test(normalized))) {
    findings.push(`${normalized} is a tracked private/secret-bearing path`);
  }
}

scanWorkspace('.');

if (findings.length > 0) {
  console.error('Repository secret guardrails failed:');
  for (const finding of findings) {
    console.error(`- ${finding}`);
  }
  process.exit(1);
}

console.log('Repository secret guardrails passed.');

function getTrackedFiles() {
  const output = execFileSync('git', ['ls-files'], {
    cwd: repoRoot,
    encoding: 'utf8',
  });
  return output.split(/\r?\n/).filter(Boolean);
}

function scanWorkspace(relativeDir) {
  const absoluteDir = path.join(repoRoot, relativeDir);
  if (!existsSync(absoluteDir)) return;

  const normalizedDir = normalizePath(relativeDir);
  if (ignoredDirs.has(normalizedDir)) return;

  for (const entry of readdirSync(absoluteDir, { withFileTypes: true })) {
    const relativePath = relativeDir === '.'
      ? entry.name
      : path.join(relativeDir, entry.name);
    const normalized = normalizePath(relativePath);

    if (entry.isDirectory()) {
      if ([...ignoredDirs].some((ignored) => normalized === ignored || normalized.startsWith(`${ignored}/`))) {
        continue;
      }
      scanWorkspace(relativePath);
      continue;
    }

    if (!entry.isFile()) continue;

    const size = statSync(path.join(repoRoot, relativePath)).size;
    if (size === 0) continue;

    if (forbiddenWorkspacePathPatterns.some((pattern) => pattern.test(normalized))) {
      findings.push(`${normalized} exists in the workspace and must not be shipped or committed`);
    }
  }
}

function normalizePath(filePath) {
  return filePath.split(path.sep).join('/');
}
