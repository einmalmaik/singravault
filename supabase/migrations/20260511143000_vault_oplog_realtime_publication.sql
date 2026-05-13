-- Enable near-real-time client refresh for vault operation-log changes.
-- Clients still re-load and locally verify the OpLog; realtime only acts as
-- a low-latency wake-up signal after add/revoke/recovery operations.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime') THEN
        IF NOT EXISTS (
            SELECT 1
            FROM pg_publication_tables
            WHERE pubname = 'supabase_realtime'
              AND schemaname = 'public'
              AND tablename = 'vault_operations'
        ) THEN
            ALTER PUBLICATION supabase_realtime ADD TABLE public.vault_operations;
        END IF;

        IF NOT EXISTS (
            SELECT 1
            FROM pg_publication_tables
            WHERE pubname = 'supabase_realtime'
              AND schemaname = 'public'
              AND tablename = 'vault_device_trust_records'
        ) THEN
            ALTER PUBLICATION supabase_realtime ADD TABLE public.vault_device_trust_records;
        END IF;
    END IF;
END $$;
