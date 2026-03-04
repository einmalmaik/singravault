import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { resolve } from 'node:path';

const pat = process.env.GITHUB_PAT;

if (!pat) {
    console.warn('Warning: GITHUB_PAT environment variable is not set.');
} else {
    console.log('Injecting GITHUB_PAT into package.json and optionally package-lock.json...');

    const packageJsonPath = resolve(process.cwd(), 'package.json');
    const lockfilePath = resolve(process.cwd(), 'package-lock.json');

    try {
        // 1. Rewrite package.json
        let pkgContent = readFileSync(packageJsonPath, 'utf8');
        const githubPattern = /"github:einmalmaik\/singra-premium"/g;
        const httpsUrl = `"git+https://x-oauth-basic:${pat}@github.com/einmalmaik/singra-premium.git"`;

        // Also try to catch any existing ssh URLs if they were left over
        const sshPattern = /"(git\+)?ssh:\/\/git@github\.com\/einmalmaik\/singra-premium\.git"/g;

        pkgContent = pkgContent.replace(githubPattern, httpsUrl);
        pkgContent = pkgContent.replace(sshPattern, httpsUrl);
        writeFileSync(packageJsonPath, pkgContent);
        console.log('Successfully updated package.json');

        // 2. Rewrite package-lock.json if it exists
        if (existsSync(lockfilePath)) {
            let lockContent = readFileSync(lockfilePath, 'utf8');

            // Replace all SSH variations in the lockfile
            const lockSshPattern1 = /git\+ssh:\/\/git@github\.com\/einmalmaik\/singra-premium\.git/g;
            const lockSshPattern2 = /ssh:\/\/git@github\.com\/einmalmaik\/singra-premium\.git/g;
            const lockSshPattern3 = /github:einmalmaik\/singra-premium/g;
            const httpsUrlNoQuotes = `git+https://x-oauth-basic:${pat}@github.com/einmalmaik/singra-premium.git`;

            lockContent = lockContent.replace(lockSshPattern1, httpsUrlNoQuotes);
            lockContent = lockContent.replace(lockSshPattern2, httpsUrlNoQuotes);
            lockContent = lockContent.replace(lockSshPattern3, httpsUrlNoQuotes);

            writeFileSync(lockfilePath, lockContent);
            console.log('Successfully updated package-lock.json');
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
