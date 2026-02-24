-- RPC for safely looking up a user's ID and Email by Email without exposing the entire auth.users table.
CREATE OR REPLACE FUNCTION get_user_id_by_email(p_email TEXT)
RETURNS TABLE (id UUID, email TEXT) 
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  RETURN QUERY
  SELECT u.id, u.email::TEXT
  FROM auth.users u
  WHERE u.email = p_email
  LIMIT 1;
END;
$$;
