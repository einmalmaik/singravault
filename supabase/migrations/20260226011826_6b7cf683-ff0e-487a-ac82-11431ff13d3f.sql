
-- OPAQUE Protocol: Speichert die OPAQUE Registration Records (Server-seitig)
CREATE TABLE public.user_opaque_records (
    id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID NOT NULL UNIQUE,
    registration_record TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- RLS: Nur Service-Role darf zugreifen (kein Client-Zugriff)
ALTER TABLE public.user_opaque_records ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Service role only for opaque records"
    ON public.user_opaque_records
    FOR ALL
    USING (auth.role() = 'service_role')
    WITH CHECK (auth.role() = 'service_role');

-- Trigger für updated_at
CREATE TRIGGER update_user_opaque_records_updated_at
    BEFORE UPDATE ON public.user_opaque_records
    FOR EACH ROW
    EXECUTE FUNCTION public.update_updated_at_column();

-- Auth-Protokoll-Feld in profiles (legacy = Argon2id über TLS, opaque = OPAQUE PAKE)
ALTER TABLE public.profiles
    ADD COLUMN auth_protocol TEXT NOT NULL DEFAULT 'legacy';
