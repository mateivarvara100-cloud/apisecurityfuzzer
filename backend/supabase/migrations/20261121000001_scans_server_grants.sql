-- The backend's own access to the scans table. Newer Supabase projects don't give the API roles
-- privileges on new tables automatically, and bypassing row level security (which the secret
-- key's service role does) is not the same as having table privileges.
--
-- Only what the backend uses: read (history and the daily-limit counts), add (a finished scan)
-- and delete (scans past the retention period). No update. The browser roles still get nothing.

grant select, insert, delete on table public.scans to service_role;
