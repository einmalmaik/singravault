import { afterEach, describe, expect, it, vi } from 'vitest';

describe('core edge function CORS config', () => {
    afterEach(() => {
        vi.resetModules();
        vi.unstubAllGlobals();
    });

    it('allows explicitly configured preview origins', async () => {
        vi.stubGlobal('Deno', {
            env: {
                get(key: string) {
                    switch (key) {
                        case 'ALLOWED_ORIGIN':
                            return 'https://singravault.mauntingstudios.de';
                        case 'ALLOW_PREVIEW_ORIGINS':
                            return 'true';
                        case 'ALLOWED_PREVIEW_ORIGINS':
                            return 'https://preview.example.test';
                        default:
                            return '';
                    }
                },
            },
        });

        const { getCorsHeaders } = await import('./cors.ts');
        const headers = getCorsHeaders(new Request('https://example.test', {
            headers: { Origin: 'https://preview.example.test' },
        }));

        expect(headers['Access-Control-Allow-Origin']).toBe('https://preview.example.test');
    });

    it('allows owned vercel preview hosts by suffix', async () => {
        vi.stubGlobal('Deno', {
            env: {
                get(key: string) {
                    switch (key) {
                        case 'ALLOWED_ORIGIN':
                            return 'https://singravault.mauntingstudios.de';
                        case 'ALLOW_PREVIEW_ORIGINS':
                            return 'true';
                        case 'ALLOWED_PREVIEW_ORIGIN_SUFFIXES':
                            return 'einmalmaik-5474s-projects.vercel.app';
                        default:
                            return '';
                    }
                },
            },
        });

        const { getCorsHeaders } = await import('./cors.ts');
        const headers = getCorsHeaders(new Request('https://example.test', {
            headers: {
                Origin: 'https://singravault-fbr8-git-codex-aut-20d874-einmalmaik-5474s-projects.vercel.app',
            },
        }));

        expect(headers['Access-Control-Allow-Origin']).toBe(
            'https://singravault-fbr8-git-codex-aut-20d874-einmalmaik-5474s-projects.vercel.app',
        );
    });

    it('rejects unrelated vercel preview hosts', async () => {
        vi.stubGlobal('Deno', {
            env: {
                get(key: string) {
                    switch (key) {
                        case 'ALLOWED_ORIGIN':
                            return 'https://singravault.mauntingstudios.de';
                        case 'ALLOW_PREVIEW_ORIGINS':
                            return 'true';
                        case 'ALLOWED_PREVIEW_ORIGIN_SUFFIXES':
                            return 'einmalmaik-5474s-projects.vercel.app';
                        default:
                            return '';
                    }
                },
            },
        });

        const { getCorsHeaders } = await import('./cors.ts');
        const headers = getCorsHeaders(new Request('https://example.test', {
            headers: { Origin: 'https://attacker-preview.vercel.app' },
        }));

        expect(headers['Access-Control-Allow-Origin']).toBeUndefined();
        expect(headers['Vary']).toBe('Origin');
    });

    it('rejects localhost unless local development origins are explicitly enabled', async () => {
        vi.stubGlobal('Deno', {
            env: {
                get(key: string) {
                    switch (key) {
                        case 'ALLOWED_ORIGIN':
                            return 'https://singravault.mauntingstudios.de';
                        default:
                            return '';
                    }
                },
            },
        });

        const { getCorsHeaders } = await import('./cors.ts');
        const headers = getCorsHeaders(new Request('https://example.test', {
            headers: { Origin: 'http://localhost:8080' },
        }));

        expect(headers['Access-Control-Allow-Origin']).toBeUndefined();
        expect(headers['Vary']).toBe('Origin');
    });

    it('allows localhost only through the local development opt-in', async () => {
        vi.stubGlobal('Deno', {
            env: {
                get(key: string) {
                    switch (key) {
                        case 'ALLOWED_ORIGIN':
                            return 'https://singravault.mauntingstudios.de';
                        case 'ALLOW_LOCAL_DEV_ORIGINS':
                            return 'true';
                        default:
                            return '';
                    }
                },
            },
        });

        const { getCorsHeaders } = await import('./cors.ts');
        const headers = getCorsHeaders(new Request('https://example.test', {
            headers: { Origin: 'http://localhost:8080' },
        }));

        expect(headers['Access-Control-Allow-Origin']).toBe('http://localhost:8080');
        expect(headers['Vary']).toBe('Origin');
    });

    it('allows both documented local web dev origins through the local development opt-in', async () => {
        vi.stubGlobal('Deno', {
            env: {
                get(key: string) {
                    switch (key) {
                        case 'ALLOWED_ORIGIN':
                            return 'https://singravault.mauntingstudios.de';
                        case 'ALLOW_LOCAL_DEV_ORIGINS':
                            return 'true';
                        default:
                            return '';
                    }
                },
            },
        });

        const { getCorsHeaders } = await import('./cors.ts');
        const localhostHeaders = getCorsHeaders(new Request('https://example.test', {
            headers: { Origin: 'http://localhost:8080' },
        }));
        const loopbackHeaders = getCorsHeaders(new Request('https://example.test', {
            headers: { Origin: 'http://127.0.0.1:8080' },
        }));

        expect(localhostHeaders['Access-Control-Allow-Origin']).toBe('http://localhost:8080');
        expect(loopbackHeaders['Access-Control-Allow-Origin']).toBe('http://127.0.0.1:8080');
    });

    it('allows explicitly configured local development origins', async () => {
        vi.stubGlobal('Deno', {
            env: {
                get(key: string) {
                    switch (key) {
                        case 'ALLOWED_ORIGIN':
                            return 'https://singravault.mauntingstudios.de';
                        case 'ALLOWED_DEV_ORIGINS':
                            return 'http://localhost:5173';
                        default:
                            return '';
                    }
                },
            },
        });

        const { getCorsHeaders } = await import('./cors.ts');
        const headers = getCorsHeaders(new Request('https://example.test', {
            headers: { Origin: 'http://localhost:5173' },
        }));

        expect(headers['Access-Control-Allow-Origin']).toBe('http://localhost:5173');
    });

    it('allows configured Tauri desktop origins', async () => {
        vi.stubGlobal('Deno', {
            env: {
                get(key: string) {
                    switch (key) {
                        case 'ALLOWED_ORIGIN':
                            return 'https://singravault.mauntingstudios.de';
                        case 'ALLOWED_DESKTOP_ORIGINS':
                            return 'tauri://localhost,http://tauri.localhost,https://tauri.localhost,https://asset.localhost,https://ipc.localhost';
                        default:
                            return '';
                    }
                },
            },
        });

        const { getCorsHeaders } = await import('./cors.ts');
        const tauriHeaders = getCorsHeaders(new Request('https://example.test', {
            headers: { Origin: 'tauri://localhost' },
        }));
        const devHeaders = getCorsHeaders(new Request('https://example.test', {
            headers: { Origin: 'http://tauri.localhost' },
        }));
        const releaseHeaders = getCorsHeaders(new Request('https://example.test', {
            headers: { Origin: 'https://tauri.localhost' },
        }));
        const assetHeaders = getCorsHeaders(new Request('https://example.test', {
            headers: { Origin: 'https://asset.localhost' },
        }));

        expect(tauriHeaders['Access-Control-Allow-Origin']).toBe('tauri://localhost');
        expect(devHeaders['Access-Control-Allow-Origin']).toBe('http://tauri.localhost');
        expect(releaseHeaders['Access-Control-Allow-Origin']).toBe('https://tauri.localhost');
        expect(assetHeaders['Access-Control-Allow-Origin']).toBe('https://asset.localhost');
    });

    it('supports function-specific allowed method narrowing', async () => {
        vi.stubGlobal('Deno', {
            env: {
                get(key: string) {
                    switch (key) {
                        case 'ALLOWED_ORIGIN':
                            return 'https://singravault.mauntingstudios.de';
                        case 'ALLOW_LOCAL_DEV_ORIGINS':
                            return 'true';
                        default:
                            return '';
                    }
                },
            },
        });

        const { getCorsHeaders } = await import('./cors.ts');
        const headers = getCorsHeaders(new Request('https://example.test', {
            headers: { Origin: 'http://localhost:8080' },
        }), { allowedMethods: 'POST, OPTIONS' });

        expect(headers['Access-Control-Allow-Origin']).toBe('http://localhost:8080');
        expect(headers['Access-Control-Allow-Methods']).toBe('POST, OPTIONS');
    });
});
