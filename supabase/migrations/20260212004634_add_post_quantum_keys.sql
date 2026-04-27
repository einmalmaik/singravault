-- ============================================================
-- Migration: Add Post-Quantum Key Storage
-- Date: 2026-02-12
-- Description: Adds columns for ML-KEM-768 post-quantum keys
--              to support hybrid key wrapping (PQ + RSA-4096)
-- ============================================================

-- 1. Add PQ keys to profiles table (for user's own PQ key pair)
-- The pq_public_key is shared with trustees/collection members
-- The pq_encrypted_private_key is encrypted with the master password
ALTER TABLE profiles
ADD COLUMN IF NOT EXISTS pq_public_key TEXT,
ADD COLUMN IF NOT EXISTS pq_encrypted_private_key TEXT,
ADD COLUMN IF NOT EXISTS pq_key_version INTEGER DEFAULT NULL;

COMMENT ON COLUMN profiles.pq_public_key IS 'Base64-encoded ML-KEM-768 public key (1184 bytes)';
COMMENT ON COLUMN profiles.pq_encrypted_private_key IS 'ML-KEM-768 private key encrypted with master password (format: salt:ciphertext)';
COMMENT ON COLUMN profiles.pq_key_version IS 'Version of PQ key format (NULL = no PQ keys, 1 = ML-KEM-768)';

-- 2. Add PQ public key to emergency_access table (trustee's PQ key)
-- This stores the trustee's PQ public key alongside their RSA public key
ALTER TABLE emergency_access
ADD COLUMN IF NOT EXISTS trustee_pq_public_key TEXT,
ADD COLUMN IF NOT EXISTS pq_encrypted_master_key TEXT;

COMMENT ON COLUMN emergency_access.trustee_pq_public_key IS 'Trustee ML-KEM-768 public key for hybrid key wrapping';
COMMENT ON COLUMN emergency_access.pq_encrypted_master_key IS 'Emergency-access key wrapped with hybrid PQ+RSA (version byte prefix)';

-- 3. Add PQ wrapped key to collection_keys table
-- This stores the hybrid-wrapped collection key for each member
ALTER TABLE collection_keys
ADD COLUMN IF NOT EXISTS pq_wrapped_key TEXT;

COMMENT ON COLUMN collection_keys.pq_wrapped_key IS 'Collection key wrapped with hybrid PQ+RSA key wrapping';

-- 4. Create index for efficient PQ key lookups
CREATE INDEX IF NOT EXISTS idx_profiles_pq_key_version 
ON profiles(pq_key_version) 
WHERE pq_key_version IS NOT NULL;

-- 5. Add trigger to update updated_at when PQ keys change
CREATE OR REPLACE FUNCTION update_profile_pq_keys_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.pq_public_key IS DISTINCT FROM NEW.pq_public_key OR
       OLD.pq_encrypted_private_key IS DISTINCT FROM NEW.pq_encrypted_private_key THEN
        NEW.updated_at = NOW();
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_update_profile_pq_keys_timestamp ON profiles;
CREATE TRIGGER trigger_update_profile_pq_keys_timestamp
BEFORE UPDATE ON profiles
FOR EACH ROW
EXECUTE FUNCTION update_profile_pq_keys_timestamp();
