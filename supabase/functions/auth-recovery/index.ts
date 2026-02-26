import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.49.1";
import { getCorsHeaders } from "../_shared/cors.ts";

const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const resendApiKey = Deno.env.get("RESEND_API_KEY")!;
const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey);

/**
 * Generates a cryptographically secure 8-digit numeric code.
 */
function generateCode(): string {
    const bytes = new Uint8Array(4);
    crypto.getRandomValues(bytes);
    const num = ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
    return String(num % 100_000_000).padStart(8, "0");
}

/**
 * SHA-256 hash of a string, returned as hex.
 */
async function hashCode(code: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(code);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Reads the reset-password email HTML template and replaces the code placeholder.
 */
function buildEmailHtml(code: string): string {
    // Inline template based on src/email-templates/reset-password.html
    return `<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Passwort zurücksetzen - Singra Vault</title>
<style>
body,table,td{margin:0;padding:0}
img{border:0;display:block}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;line-height:1.6;color:#1a1a2e;background-color:#f4f4f8}
.wrapper{max-width:600px;margin:0 auto;padding:40px 20px}
.card{background:#ffffff;border-radius:16px;box-shadow:0 4px 24px rgba(0,0,0,0.08);overflow:hidden}
.header{background:linear-gradient(135deg,#6366f1 0%,#8b5cf6 100%);padding:32px;text-align:center}
.logo{display:inline-flex;align-items:center;gap:12px;color:#ffffff;font-size:24px;font-weight:700;text-decoration:none}
.content{padding:40px 32px}
h1{margin:0 0 16px;font-size:24px;font-weight:700;color:#1a1a2e}
p{margin:0 0 16px;color:#4a4a68}
.warning-box{background:#fef3c7;border:1px solid #f59e0b;border-radius:8px;padding:16px;margin:16px 0}
.warning-box p{color:#92400e;margin:0}
.divider{height:1px;background:#e2e2ea;margin:24px 0}
.note{font-size:14px;color:#6b6b80}
.footer{padding:24px 32px;background:#f8f8fc;text-align:center;font-size:12px;color:#6b6b80}
.footer a{color:#6366f1;text-decoration:none}
@media(prefers-color-scheme:dark){body{background-color:#0f0f1a;color:#e4e4e7}.card{background:#1a1a2e}h1{color:#ffffff}p{color:#a1a1aa}.footer{background:#0f0f1a}}
</style>
</head>
<body>
<div class="wrapper">
<div class="card">
<div class="header">
<a href="https://singra.de" class="logo">
<svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
<span>Singra Vault</span>
</a>
</div>
<div class="content">
<h1>Passwort zurücksetzen 🔐</h1>
<p>Du hast eine Anfrage zum Zurücksetzen deines Passworts gestellt. Verwende den folgenden 8-stelligen Code in der App, um ein neues Passwort zu vergeben:</p>
<div style="text-align:center;margin:32px 0;">
<div style="display:inline-block;background:#f4f4f8;padding:16px 32px;border-radius:12px;border:2px dashed #6366f1;letter-spacing:4px;font-size:32px;font-weight:700;color:#1a1a2e;font-family:monospace;">
${code}
</div>
</div>
<div class="warning-box">
<p><strong>⚠️ Wichtig:</strong> Das Zurücksetzen des Kontopassworts ändert NICHT dein Master-Passwort. Deine verschlüsselten Vault-Daten bleiben sicher.</p>
</div>
<div class="divider"></div>
<p class="note">Wenn du diese Anfrage nicht gestellt hast, ignoriere diese E-Mail. Dein Konto bleibt sicher.</p>
<p class="note">Dieser Code ist 1 Stunde gültig.</p>
</div>
<div class="footer">
<p>&copy; 2026 Singra Vault. Alle Rechte vorbehalten.</p>
<p><a href="https://singra.de/privacy">Datenschutz</a> | <a href="https://singra.de/terms">AGB</a> | <a href="https://singra.de/support">Support</a></p>
<p class="note">Diese E-Mail wurde automatisch gesendet von noreply@mauntingstudios.de</p>
</div>
</div>
</div>
</body>
</html>`;
}

serve(async (req) => {
    const corsHeaders = getCorsHeaders(req);
    if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

    try {
        const body = await req.json();
        const { email, action, code: verifyCode } = body;

        // === ACTION: verify — Nutzer gibt 8-stelligen Code ein ===
        if (action === "verify") {
            if (!email || !verifyCode) {
                return new Response(JSON.stringify({ error: "Missing email or code" }), {
                    status: 400,
                    headers: { ...corsHeaders, "Content-Type": "application/json" },
                });
            }

            const codeHash = await hashCode(verifyCode);

            // Prüfe Token in DB
            const { data: tokens, error: tokenError } = await supabaseAdmin
                .from("recovery_tokens")
                .select("*")
                .eq("email", email.toLowerCase().trim())
                .eq("token_hash", codeHash)
                .gt("expires_at", new Date().toISOString())
                .limit(1);

            if (tokenError || !tokens || tokens.length === 0) {
                // Konstante Antwortzeit
                await new Promise(r => setTimeout(r, 300));
                return new Response(JSON.stringify({ error: "Invalid or expired code" }), {
                    status: 400,
                    headers: { ...corsHeaders, "Content-Type": "application/json" },
                });
            }

            // Token ist gültig → lösche ihn (single use)
            await supabaseAdmin
                .from("recovery_tokens")
                .delete()
                .eq("id", tokens[0].id);

            // Erstelle eine Session via generateLink + verifyOtp (wie beim Login)
            const { data: linkData, error: linkError } = await supabaseAdmin.auth.admin.generateLink({
                type: "magiclink",
                email: email.toLowerCase().trim(),
            });

            if (linkError || !linkData) {
                console.error("generateLink failed:", linkError);
                return new Response(JSON.stringify({ error: "Session creation failed" }), {
                    status: 500,
                    headers: { ...corsHeaders, "Content-Type": "application/json" },
                });
            }

            const tokenHash = linkData.properties?.hashed_token;
            if (!tokenHash) {
                return new Response(JSON.stringify({ error: "No hashed_token" }), {
                    status: 500,
                    headers: { ...corsHeaders, "Content-Type": "application/json" },
                });
            }

            const { data: sessionData, error: verifyError } = await supabaseAdmin.auth.verifyOtp({
                token_hash: tokenHash,
                type: "magiclink",
            });

            if (verifyError || !sessionData?.session) {
                console.error("verifyOtp failed:", verifyError);
                return new Response(JSON.stringify({ error: "Session verification failed" }), {
                    status: 500,
                    headers: { ...corsHeaders, "Content-Type": "application/json" },
                });
            }

            return new Response(JSON.stringify({
                success: true,
                session: {
                    access_token: sessionData.session.access_token,
                    refresh_token: sessionData.session.refresh_token,
                },
            }), {
                status: 200,
                headers: { ...corsHeaders, "Content-Type": "application/json" },
            });
        }

        // === ACTION: default — Passwort-Reset anfordern ===
        if (!email) {
            return new Response(JSON.stringify({ error: "Invalid email" }), {
                status: 400,
                headers: { ...corsHeaders, "Content-Type": "application/json" },
            });
        }

        const startTime = Date.now();
        const normalizedEmail = email.toLowerCase().trim();

        // Prüfe ob User existiert
        const { data: users, error: rpcError } = await supabaseAdmin.rpc("get_user_id_by_email", {
            p_email: normalizedEmail,
        });
        const userExists = !rpcError && users && users.length > 0;

        if (userExists) {
            // Eigenen Rate Limit: max 1 Token pro 60s pro E-Mail
            const { data: recentTokens } = await supabaseAdmin
                .from("recovery_tokens")
                .select("created_at")
                .eq("email", normalizedEmail)
                .gt("created_at", new Date(Date.now() - 60_000).toISOString())
                .limit(1);

            if (recentTokens && recentTokens.length > 0) {
                // Bereits ein Token in den letzten 60s gesendet — still succeed (anti-enumeration)
                console.log("Rate limited: recovery token already sent recently for", normalizedEmail);
            } else {
                // Alte abgelaufene Tokens löschen
                await supabaseAdmin
                    .from("recovery_tokens")
                    .delete()
                    .eq("email", normalizedEmail);

                // 8-stelligen Code generieren und hashen
                const code = generateCode();
                const codeHash = await hashCode(code);
                const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 Stunde

                // Token in DB speichern
                const { error: insertError } = await supabaseAdmin
                    .from("recovery_tokens")
                    .insert({
                        email: normalizedEmail,
                        token_hash: codeHash,
                        expires_at: expiresAt,
                    });

                if (insertError) {
                    console.error("Failed to insert recovery token:", insertError);
                } else {
                    // E-Mail via Resend senden
                    const emailHtml = buildEmailHtml(code);
                    const resendRes = await fetch("https://api.resend.com/emails", {
                        method: "POST",
                        headers: {
                            "Authorization": `Bearer ${resendApiKey}`,
                            "Content-Type": "application/json",
                        },
                        body: JSON.stringify({
                            from: "Singra Vault <noreply@mauntingstudios.de>",
                            to: [normalizedEmail],
                            subject: "Passwort zurücksetzen – Singra Vault 🔐",
                            html: emailHtml,
                        }),
                    });

                    if (!resendRes.ok) {
                        const errText = await resendRes.text();
                        console.error("Resend API error:", errText);
                    } else {
                        console.log("Recovery email sent via Resend to:", normalizedEmail);
                    }
                }
            }
        }

        // Konstante Antwortzeit (anti-timing-attack)
        const elapsed = Date.now() - startTime;
        if (elapsed < 500) await new Promise(r => setTimeout(r, 500 - elapsed));

        // IMMER Erfolg, um User-Enumeration auszuschließen
        return new Response(JSON.stringify({ success: true }), {
            status: 200,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
    } catch (err: any) {
        console.error("Auth Recovery Error:", err);
        return new Response(JSON.stringify({ error: "Internal Server Error" }), {
            status: 500,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
    }
});
