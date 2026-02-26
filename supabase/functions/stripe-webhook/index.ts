import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import Stripe from "npm:stripe@17.7.0";
import { createClient } from "npm:@supabase/supabase-js@2";

// Server-side price → tier mapping
const PRICE_TO_TIER: Record<string, string> = {
    "price_1Sz4ydPOxkvnea3yiUS9yZsV": "premium",  // Premium Monthly
    "price_1Sz4ydPOxkvnea3yjs4Tfnzt": "premium",  // Premium Yearly
    "price_1Sz4yePOxkvnea3ywl0Ggaqj": "families", // Families Monthly
    "price_1Sz4ygPOxkvnea3yy7lrqSmP": "families", // Families Yearly
};

const INTRO_COUPON_ID = "K3tViKjk";

Deno.serve(async (req: Request) => {
    if (req.method !== "POST") {
        return new Response("Method not allowed", { status: 405 });
    }

    try {
        const stripeApiKey = Deno.env.get("STRIPE_SECRET_KEY")!;
        const webhookSecret = Deno.env.get("STRIPE_WEBHOOK_SECRET")!;
        const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
        const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

        const stripe = new Stripe(stripeApiKey, { apiVersion: "2024-12-18.acacia" });
        const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey);

        // 1. Verify webhook signature
        const body = await req.text();
        const signature = req.headers.get("stripe-signature");

        if (!signature) {
            console.error("Missing stripe-signature header");
            return new Response("Missing signature", { status: 400 });
        }

        let event: Stripe.Event;
        try {
            event = await stripe.webhooks.constructEventAsync(body, signature, webhookSecret);
        } catch (err) {
            console.error("Webhook signature verification failed:", err);
            return new Response("Invalid signature", { status: 400 });
        }

        console.log(`Processing event: ${event.type} (${event.id})`);

        // 2. Handle events
        switch (event.type) {
            case "checkout.session.completed": {
                const session = event.data.object as Stripe.Checkout.Session;
                if (session.mode !== "subscription") break;

                const userId = session.metadata?.supabase_user_id;
                const tier = session.metadata?.tier;
                const planKey = session.metadata?.plan_key;
                const subscriptionId = session.subscription as string;
                const customerId = session.customer as string;

                if (!userId || !tier) {
                    console.error("Missing metadata in checkout session:", session.id);
                    break;
                }

                // Retrieve the subscription to get price info
                const stripeSubscription = await stripe.subscriptions.retrieve(subscriptionId);
                const priceId = stripeSubscription.items.data[0]?.price?.id || null;

                // Check if coupon was applied (intro discount)
                const hasDiscount = stripeSubscription.discount?.coupon?.id === INTRO_COUPON_ID;

                // Update subscription in DB
                const { error: upsertError } = await supabaseAdmin
                    .from("subscriptions")
                    .update({
                        stripe_customer_id: customerId,
                        stripe_subscription_id: subscriptionId,
                        stripe_price_id: priceId,
                        status: stripeSubscription.status,
                        tier,
                        current_period_end: new Date(stripeSubscription.current_period_end * 1000).toISOString(),
                        cancel_at_period_end: stripeSubscription.cancel_at_period_end,
                        has_used_intro_discount: hasDiscount ? true : undefined,
                    })
                    .eq("user_id", userId);

                if (upsertError) {
                    console.error("Error updating subscription:", upsertError);
                }

                // If discount was applied, ensure flag is set even if update above didn't include it
                if (hasDiscount) {
                    await supabaseAdmin
                        .from("subscriptions")
                        .update({ has_used_intro_discount: true })
                        .eq("user_id", userId);
                }

                console.log(`Checkout completed: user=${userId}, tier=${tier}, subscription=${subscriptionId}`);
                break;
            }

            case "invoice.payment_succeeded": {
                const invoice = event.data.object as Stripe.Invoice;
                const subscriptionId = invoice.subscription as string;
                if (!subscriptionId) break;

                // Get subscription to find user
                const { data: subData } = await supabaseAdmin
                    .from("subscriptions")
                    .select("user_id")
                    .eq("stripe_subscription_id", subscriptionId)
                    .single();

                if (subData) {
                    const stripeSubscription = await stripe.subscriptions.retrieve(subscriptionId);
                    await supabaseAdmin
                        .from("subscriptions")
                        .update({
                            status: stripeSubscription.status,
                            current_period_end: new Date(stripeSubscription.current_period_end * 1000).toISOString(),
                        })
                        .eq("stripe_subscription_id", subscriptionId);

                    console.log(`Payment succeeded for subscription: ${subscriptionId}`);
                }
                break;
            }

            case "customer.subscription.updated": {
                const subscription = event.data.object as Stripe.Subscription;
                const subscriptionId = subscription.id;
                const priceId = subscription.items.data[0]?.price?.id;
                const tier = priceId ? (PRICE_TO_TIER[priceId] || null) : null;

                const updateData: Record<string, unknown> = {
                    status: subscription.status,
                    cancel_at_period_end: subscription.cancel_at_period_end,
                    current_period_end: new Date(subscription.current_period_end * 1000).toISOString(),
                    stripe_price_id: priceId || null,
                };

                if (tier) {
                    updateData.tier = tier;
                }

                const { error } = await supabaseAdmin
                    .from("subscriptions")
                    .update(updateData)
                    .eq("stripe_subscription_id", subscriptionId);

                if (error) {
                    console.error("Error updating subscription:", error);
                }

                console.log(`Subscription updated: ${subscriptionId}, status=${subscription.status}`);
                break;
            }

            case "customer.subscription.deleted": {
                const subscription = event.data.object as Stripe.Subscription;
                const subscriptionId = subscription.id;

                const { error } = await supabaseAdmin
                    .from("subscriptions")
                    .update({
                        status: "canceled",
                        tier: "free",
                        cancel_at_period_end: false,
                        stripe_price_id: null,
                    })
                    .eq("stripe_subscription_id", subscriptionId);

                if (error) {
                    console.error("Error canceling subscription:", error);
                }

                console.log(`Subscription deleted (canceled): ${subscriptionId}`);
                break;
            }

            default:
                console.log(`Unhandled event type: ${event.type}`);
        }

        return new Response(JSON.stringify({ received: true }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
        });
    } catch (err) {
        console.error("Webhook handler error:", err);
        return new Response(JSON.stringify({ error: "Internal server error" }), {
            status: 500,
            headers: { "Content-Type": "application/json" },
        });
    }
});
