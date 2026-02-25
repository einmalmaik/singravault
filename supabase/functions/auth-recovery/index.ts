import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.49.1";
import { getCorsHeaders } from "../_shared/cors.ts";

const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey);

serve(async (req) => {
    const corsHeaders = getCorsHeaders(req);
    if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

    try {
        const { email } = await req.json();
        if (!email) {
            return new Response(JSON.stringify({ error: "Invalid email" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        const startTime = Date.now();

        // 4. Check if user actually exists before proceeding with DB and Mail
        const { data: users, error: rpcError } = await supabaseAdmin.rpc("get_user_id_by_email", { p_email: email });
        const userExists = !rpcError && users && users.length > 0;

        if (userExists) {
            // Rufen wir GoTrue's resetPasswordForEmail auf.
            // Dies sendet die Email mit dem konfigurierten Template aus dem Supabase Dashboard.
            const siteUrl = Deno.env.get("SITE_URL") || "https://singravault.mauntingstudios.de";
            const { error: resetError } = await supabaseAdmin.auth.resetPasswordForEmail(email, {
                redirectTo: `${siteUrl}/vault`,
            });

            if (resetError) {
                console.error("Failed to trigger reset password:", resetError);
            } else {
                console.log("Recovery email triggered via GoTrue for:", email);
            }
        }

        // Konstante Antwortzeit simulieren
        const elapsed = Date.now() - startTime;
        if (elapsed < 500) await new Promise(r => setTimeout(r, 500 - elapsed));

        // IMMER Erfolg, um Enumeration auszuschließen
        return new Response(JSON.stringify({ success: true }), {
            status: 200,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
    } catch (err: any) {
        console.error("Auth Recovery Error:", err);
        return new Response(JSON.stringify({ error: "Internal Server Error" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
});
