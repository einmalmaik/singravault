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

        expect(headers['Access-Control-Allow-Origin']).toBe('null');
    });

    it('allows configured Tauri desktop origins', async () => {
        vi.stubGlobal('Deno', {
            env: {
                get(key: string) {
                    switch (key) {
                        case 'ALLOWED_ORIGIN':
                            return 'https://singravault.mauntingstudios.de';
                        case 'ALLOWED_DESKTOP_ORIGINS':
                            return 'tauri://localhost,http://tauri.localhost';
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

        expect(tauriHeaders['Access-Control-Allow-Origin']).toBe('tauri://localhost');
        expect(devHeaders['Access-Control-Allow-Origin']).toBe('http://tauri.localhost');
    });
});
