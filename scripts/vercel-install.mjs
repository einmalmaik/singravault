import { existsSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { resolve } from 'node:path';

const pat = process.env.GITHUB_PAT;

console.log('=== Vercel Install Script ===');
console.log('GITHUB_PAT is set:', !!pat);
console.log('GITHUB_PAT length:', pat ? pat.length : 0);
console.log('GITHUB_PAT starts with:', pat ? pat.substring(0, 6) + '...' : 'N/A');

function configureGitRewrite(baseUrl) {
    const normalizedBaseUrl = baseUrl.endsWith('/') ? baseUrl : `${baseUrl}/`;
    const rewriteSources = [
        'ssh://git@github.com/',
        'git@github.com:',
        'https://github.com/',
        'git+https://github.com/',
    ];

    for (const source of rewriteSources) {
        try {
            execSync(`git config --global url."${normalizedBaseUrl}".insteadOf "${source}"`, { stdio: 'ignore' });
        } catch (error) {
            console.warn(`Failed to configure git rewrite for ${source}:`, error instanceof Error ? error.message : error);
        }
    }
}

if (!pat) {
    console.error('ERROR: GITHUB_PAT environment variable is NOT set!');
    console.error('Please add GITHUB_PAT to your Vercel environment variables.');
    configureGitRewrite('https://github.com/');
    // Continue anyway - npm install may still work if repository access is public
} else {
    const packageJsonPath = resolve(process.cwd(), 'package.json');
    const lockfilePath = resolve(process.cwd(), 'package-lock.json');
    const httpsBaseUrl = `git+https://x-oauth-basic:${pat}@github.com/einmalmaik/singra-premium.git`;

    configureGitRewrite(`https://x-oauth-basic:${pat}@github.com/`);

    try {
        // 1. Read package.json
        let pkgContent = readFileSync(packageJsonPath, 'utf8');

        // Debug: show what we're looking for
        const hasSingra = pkgContent.includes('singra-premium');
        const hasGithubShorthand = pkgContent.includes('github:einmalmaik/singra-premium');
        const hasSshUrl = pkgContent.includes('ssh://git@github.com/einmalmaik/singra-premium');
        const hasHttpsUrl = pkgContent.includes('https://github.com/einmalmaik/singra-premium.git');
        console.log('package.json contains singra-premium:', hasSingra);
        console.log('package.json has github: shorthand:', hasGithubShorthand);
        console.log('package.json has ssh:// URL:', hasSshUrl);
        console.log('package.json has https:// URL:', hasHttpsUrl);

        // 2. Replace ALL possible URL formats with authenticated HTTPS
        // Replace github shorthand and preserve pinned refs (#commit, #tag)
        pkgContent = pkgContent.replace(
            /"github:einmalmaik\/singra-premium(?:#([^"]+))?"/g,
            (_match, ref) => `"${httpsBaseUrl}${ref ? `#${ref}` : ''}"`,
        );

        // Replace SSH URLs and preserve pinned refs (#commit, #tag)
        pkgContent = pkgContent.replace(
            /"(?:git\+)?ssh:\/\/git@github\.com\/einmalmaik\/singra-premium\.git(?:#([^"]+))?"/g,
            (_match, ref) => `"${httpsBaseUrl}${ref ? `#${ref}` : ''}"`,
        );

        // Replace SCP-like git URLs just in case (git@github.com:owner/repo.git#ref)
        pkgContent = pkgContent.replace(
            /"git@github\.com:einmalmaik\/singra-premium\.git(?:#([^"]+))?"/g,
            (_match, ref) => `"${httpsBaseUrl}${ref ? `#${ref}` : ''}"`,
        );

        // Replace plain HTTPS URLs (with/without token) and preserve pinned refs (#commit, #tag)
        pkgContent = pkgContent.replace(
            /"(?:git\+)?https:\/\/(?:x-oauth-basic:[^@"]+@)?github\.com\/einmalmaik\/singra-premium\.git(?:#([^"]+))?"/g,
            (_match, ref) => `"${httpsBaseUrl}${ref ? `#${ref}` : ''}"`,
        );

        writeFileSync(packageJsonPath, pkgContent);

        // 3. Verify the replacement worked
        const verifyContent = readFileSync(packageJsonPath, 'utf8');
        const stillHasGithub = verifyContent.includes('github:einmalmaik/singra-premium');
        const stillHasSsh = verifyContent.includes('ssh://git@github.com/einmalmaik/singra-premium');
        const stillHasPlainHttps = verifyContent.includes('https://github.com/einmalmaik/singra-premium.git');
        const hasHttpsWithToken = verifyContent.includes('x-oauth-basic');
        console.log('AFTER replacement:');
        console.log('  Still has github: shorthand:', stillHasGithub);
        console.log('  Still has ssh:// URL:', stillHasSsh);
        console.log('  Still has plain https URL:', stillHasPlainHttps);
        console.log('  Has https with token:', hasHttpsWithToken);

        if (stillHasGithub || stillHasSsh || stillHasPlainHttps) {
            console.error('WARNING: Replacement may have failed!');
            const lines = verifyContent.split('\n');
            const premiumLine = lines.find((line) => line.includes('singra-premium'));
            console.log('  Premium line:', premiumLine?.trim());
        }

        // 4. Delete package-lock.json
        if (existsSync(lockfilePath)) {
            unlinkSync(lockfilePath);
            console.log('Deleted package-lock.json');
        } else {
            console.log('No package-lock.json found');
        }
    } catch (error) {
        console.error('Failed to rewrite package files:', error);
    }
}

console.log('Running npm install...');
try {
    execSync('npm install', { stdio: 'inherit' });
    console.log('npm install completed successfully!');
} catch {
    console.error('npm install failed');
    process.exit(1);
}