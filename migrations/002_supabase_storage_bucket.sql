-- Run in Supabase SQL Editor once.
-- Requires the Supabase Storage extension/schema already enabled.
-- Keep this bucket private. The backend should use a Supabase secret/service-role key.

INSERT INTO storage.buckets (id, name, public, file_size_limit)
VALUES ('cipherfault', 'cipherfault', false, 104857600)
ON CONFLICT (id) DO UPDATE
SET
    name = EXCLUDED.name,
    public = EXCLUDED.public,
    file_size_limit = EXCLUDED.file_size_limit;

SELECT id, name, public, file_size_limit
FROM storage.buckets
WHERE id = 'cipherfault';
