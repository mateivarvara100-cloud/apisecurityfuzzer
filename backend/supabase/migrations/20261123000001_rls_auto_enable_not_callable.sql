-- public.rls_auto_enable() is Supabase's "turn on RLS for new tables" event-trigger function. It is
-- SECURITY DEFINER and sits in the exposed schema, so anyone could call it at /rest/v1/rpc/.
-- Postgres refuses to run a trigger function called directly, but no browser needs it at all.
-- The event trigger keeps working: firing it doesn't check EXECUTE.
revoke execute on function public.rls_auto_enable() from public, anon, authenticated;
