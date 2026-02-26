import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import Stripe from "npm:stripe@17.7.0";
import { createClient } from "npm:@supabase/supabase-js@2";
import { getCorsHeaders } from "../_shared/cors.ts";

Deno.serve(async (req: Request) => {
    const cors = getCorsHeaders(req);

    if (req.method === "OPTIONS") {
        return new Response(null, { status: 204, headers: cors });
    }

    if (req.method !== "POST") {
        return new Response(JSON.stringify({ error: "Method not allowed" }), {
            status: 405,
            headers: { ...cors, "Content-Type": "application/json" },
        });
    }

    try {
        // 1. Authenticate user
        const authHeader = req.headers.get("Authorization");
        if (!authHeader) {
            return new Response(JSON.stringify({ error: "Missing authorization" }), {
                status: 401,
                headers: { ...cors, "Content-Type": "application/json" },
            });
        }

        const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
        const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
        const stripeApiKey = Deno.env.get("STRIPE_SECRET_KEY")!;

        const supabaseClient = createClient(supabaseUrl, Deno.env.get("SUPABASE_ANON_KEY")!, {
            global: { headers: { Authorization: authHeader } },
        });

        const { data: { user }, error: authError } = await supabaseClient.auth.getUser();
        if (authError || !user) {
            return new Response(JSON.stringify({ error: "Unauthorized" }), {
                status: 401,
                headers: { ...cors, "Content-Type": "application/json" },
            });
        }

        // 2. Get Stripe customer ID
        const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey);
        const { data: subscription } = await supabaseAdmin
            .from("subscriptions")
            .select("stripe_customer_id")
            .eq("user_id", user.id)
            .single();

        if (!subscription?.stripe_customer_id) {
            return new Response(JSON.stringify({ error: "No active subscription found" }), {
                status: 404,
                headers: { ...cors, "Content-Type": "application/json" },
            });
        }

        // 3. Create Stripe Customer Portal session
        const stripe = new Stripe(stripeApiKey, { apiVersion: "2024-12-18.acacia" });
        const portalSession = await stripe.billingPortal.sessions.create({
            customer: subscription.stripe_customer_id,
            return_url: `${req.headers.get("origin") || Deno.env.get("SITE_URL") || "https://singrapw.mauntingstudios.de"}/settings`,
        });

        return new Response(
            JSON.stringify({ url: portalSession.url }),
            {
                status: 200,
                headers: { ...cors, "Content-Type": "application/json" },
            }
        );
    } catch (err) {
        console.error("Error creating portal session:", err);
        return new Response(JSON.stringify({ error: "Internal server error" }), {
            status: 500,
            headers: { ...getCorsHeaders(req), "Content-Type": "application/json" },
        });
    }
});
