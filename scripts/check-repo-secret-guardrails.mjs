#!/usr/bin/env node
// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';

const repoRoot = process.cwd();
const findings = [];

const forbiddenTrackedPathPatterns = [
  /^\.env(?:\..*)?$/i,
  /^loadtest\/(?:tokens|users)\.txt(?:\.failed\.txt)?$/i,
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
  const absolutePath = path.join(repoRoot, trackedPath);
  if (
    existsSync(absolutePath)
    && forbiddenTrackedPathPatterns.some((pattern) => pattern.test(normalized))
  ) {
    findings.push(`${normalized} is a tracked private/secret-bearing path`);
  }

  if (existsSync(absolutePath)) {
    scanTrackedFileContent(normalized, absolutePath);
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

function scanTrackedFileContent(normalizedPath, absolutePath) {
  if (statSync(absolutePath).size > 1024 * 1024) return;

  let content = "";
  try {
    content = readFileSync(absolutePath, 'utf8');
  } catch {
    return;
  }
  for (const line of content.split(/\r?\n/)) {
    const match = line.match(/^\s*(VITE_(?:E2E_TEST|DEV_TEST).*PASSWORD|SINGRA_DEV_TEST_(?:PASSWORD|MASTER_PASSWORD)|SUPABASE_SERVICE_ROLE_KEY)\s*=\s*(.*)$/i);
    if (!match) continue;
    if (normalizedPath === 'env.example') continue;

    const value = normalizeEnvAssignmentValue(match[2]);
    if (!value || isPlaceholderEnvValue(value)) continue;

    findings.push(`${normalizedPath} contains a forbidden committed dev-test secret assignment`);
  }

  if (/import\.meta\.env\.VITE_(?:E2E_TEST|DEV_TEST).*PASSWORD/.test(content)) {
    findings.push(`${normalizedPath} reads a dev-test password from the client environment`);
  }
}

function normalizeEnvAssignmentValue(rawValue) {
  return rawValue
    .replace(/\s+#.*$/, '')
    .trim()
    .replace(/^["']|["']$/g, '')
    .trim();
}

function isPlaceholderEnvValue(value) {
  return /^(?:your-|example|placeholder|change-me|local-only|test-|dev-test|xxx|todo)/i.test(value);
}

function normalizePath(filePath) {
  return filePath.split(path.sep).join('/');
}
