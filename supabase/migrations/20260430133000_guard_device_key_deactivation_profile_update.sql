-- Device-Key deactivation must pass the server-side confirmation and VaultFA
-- checks in auth-2fa. Authenticated clients may still update many profile
-- fields for existing zero-knowledge flows, but they must not directly switch
-- a Device-Key-protected vault back to master-only protection.

CREATE OR REPLACE FUNCTION public.prevent_direct_device_key_deactivation()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF auth.role() <> 'service_role'
     AND OLD.vault_protection_mode = 'device_key_required'
     AND NEW.vault_protection_mode = 'master_only' THEN
    RAISE EXCEPTION 'device_key_deactivation_requires_server_validation'
      USING ERRCODE = '42501';
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS prevent_direct_device_key_deactivation_trigger ON public.profiles;
CREATE TRIGGER prevent_direct_device_key_deactivation_trigger
  BEFORE UPDATE ON public.profiles
  FOR EACH ROW
  EXECUTE FUNCTION public.prevent_direct_device_key_deactivation();

REVOKE ALL ON FUNCTION public.prevent_direct_device_key_deactivation() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.prevent_direct_device_key_deactivation() FROM anon;
REVOKE ALL ON FUNCTION public.prevent_direct_device_key_deactivation() FROM authenticated;
