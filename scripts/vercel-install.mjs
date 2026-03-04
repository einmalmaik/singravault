import { readFileSync, writeFileSync, existsSync, unlinkSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { resolve } from 'node:path';

const pat = process.env.GITHUB_PAT;

if (!pat) {
    console.warn('Warning: GITHUB_PAT environment variable is not set.');
} else {
    console.log('Injecting GITHUB_PAT into package.json...');

    const packageJsonPath = resolve(process.cwd(), 'package.json');
    const lockfilePath = resolve(process.cwd(), 'package-lock.json');

    try {
        // 1. Rewrite package.json — replace all GitHub/SSH refs with HTTPS+token
        let pkgContent = readFileSync(packageJsonPath, 'utf8');
        const httpsUrl = `"git+https://x-oauth-basic:${pat}@github.com/einmalmaik/singra-premium.git"`;

        pkgContent = pkgContent.replace(/"github:einmalmaik\/singra-premium"/g, httpsUrl);
        pkgContent = pkgContent.replace(/"(git\+)?ssh:\/\/git@github\.com\/einmalmaik\/singra-premium\.git"/g, httpsUrl);
        writeFileSync(packageJsonPath, pkgContent);
        console.log('Successfully updated package.json');

        // 2. Delete package-lock.json so npm won't use cached SSH URLs from it
        if (existsSync(lockfilePath)) {
            unlinkSync(lockfilePath);
            console.log('Deleted package-lock.json to force fresh resolution');
        }
    } catch (error) {
        console.error('Failed to rewrite package files', error);
    }
}

console.log('Running npm install...');
try {
    execSync('npm install', { stdio: 'inherit' });
} catch (installError) {
    console.error('npm install failed with error:', installError);
    process.exit(1);
}
