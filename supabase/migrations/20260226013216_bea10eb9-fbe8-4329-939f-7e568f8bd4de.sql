-- Ephemeral OPAQUE login states (server-side, never exposed to client)
CREATE TABLE public.opaque_login_states (
    id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID NOT NULL,
    server_login_state TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- RLS: service_role only (edge function uses service role)
ALTER TABLE public.opaque_login_states ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Service role only for opaque login states"
ON public.opaque_login_states
FOR ALL
USING (auth.role() = 'service_role')
WITH CHECK (auth.role() = 'service_role');

-- Index for cleanup
CREATE INDEX idx_opaque_login_states_expires ON public.opaque_login_states (expires_at);

-- Cleanup function for expired states
CREATE OR REPLACE FUNCTION public.cleanup_expired_opaque_login_states()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $$
BEGIN
    DELETE FROM public.opaque_login_states WHERE expires_at < now();
END;
$$;