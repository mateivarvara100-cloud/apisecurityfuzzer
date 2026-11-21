-- Accounts created with Google never get a password here. Without this, "Forgot your password?"
-- would let a Google account set one, and that password would then sign in too: a second way into
-- the account that its owner may not know about.
--
-- The rule: a password can't be set on an account that has no e-mail sign-in ("email" identity).
-- E-mail accounts are unaffected, and so is signing in with Google. It is enforced in the database,
-- so it holds however the change is attempted (the site, Supabase's API, or the dashboard).

create schema if not exists private;
revoke all on schema private from public, anon, authenticated;

create or replace function private.refuse_password_without_email_identity()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if coalesce(new.encrypted_password, '') <> ''
     and new.encrypted_password is distinct from old.encrypted_password
     and not exists (
       select 1 from auth.identities i where i.user_id = new.id and i.provider = 'email'
     ) then
    raise exception 'This account signs in with Google, so it has no password here.'
      using errcode = 'check_violation';
  end if;
  return new;
end;
$$;

revoke all on function private.refuse_password_without_email_identity() from public, anon, authenticated;

drop trigger if exists refuse_password_without_email_identity on auth.users;
create trigger refuse_password_without_email_identity
  before update on auth.users
  for each row execute function private.refuse_password_without_email_identity();
