#!/usr/bin/env node
// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { existsSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';

const repoRoot = process.cwd();
const scannedDirs = ['public', 'dist', 'build', 'assets', 'src-tauri'];
const ignoredDirs = new Set([
  path.join('src-tauri', 'target'),
  path.join('src-tauri', 'gen'),
]);
const privateNamePattern = /(RETTUNG|RECOVERY|BACKUP|SECRET|PRIVATE|BACKUP-CODES)/i;
const publicTextAllowlist = new Set(['robots.txt']);
const binaryReleaseArtifactPattern = /\.(exe|msi|zip|7z|rar)$/i;
const findings = [];

function shouldScanDir(relativeDir) {
  return scannedDirs.some((root) => relativeDir === root || relativeDir.startsWith(`${root}${path.sep}`));
}

function scanDir(relativeDir) {
  const absoluteDir = path.join(repoRoot, relativeDir);
  if (!existsSync(absoluteDir) || !shouldScanDir(relativeDir)) return;

  for (const entry of readdirSync(absoluteDir, { withFileTypes: true })) {
    const relativePath = path.join(relativeDir, entry.name);
    const normalized = relativePath.split(path.sep).join('/');

    if (entry.isDirectory()) {
      if ([...ignoredDirs].some((ignored) => relativePath === ignored || relativePath.startsWith(`${ignored}${path.sep}`))) {
        continue;
      }
      scanDir(relativePath);
      continue;
    }

    if (!entry.isFile()) continue;

    const lowerDir = relativeDir.split(path.sep).join('/').toLowerCase();
    const extension = path.extname(entry.name).toLowerCase();
    const size = statSync(path.join(repoRoot, relativePath)).size;

    if (privateNamePattern.test(entry.name)) {
      findings.push(`${normalized} matches private/recovery naming rules`);
    }

    if (['public', 'dist', 'build', 'assets'].some((dir) => lowerDir === dir || lowerDir.startsWith(`${dir}/`))) {
      if (binaryReleaseArtifactPattern.test(entry.name)) {
        findings.push(`${normalized} is an installer/archive in a shipped asset directory`);
      }

      if (extension === '.txt' && lowerDir === 'public' && !publicTextAllowlist.has(entry.name)) {
        findings.push(`${normalized} is a non-allowlisted text file in public/`);
      }
    }

    if (lowerDir === 'src-tauri' && /backup|recovery|rettung/i.test(entry.name)) {
      findings.push(`${normalized} is a backup/recovery file in src-tauri/`);
    }

    if (size > 50 * 1024 * 1024 && ['public', 'dist', 'build', 'assets'].some((dir) => lowerDir === dir || lowerDir.startsWith(`${dir}/`))) {
      findings.push(`${normalized} is larger than 50 MB in a shipped asset directory`);
    }
  }
}

for (const dir of scannedDirs) {
  scanDir(dir);
}

if (findings.length > 0) {
  console.error('Release artifact check failed:');
  for (const finding of findings) {
    console.error(`- ${finding}`);
  }
  process.exit(1);
}

console.log('Release artifact check passed.');
