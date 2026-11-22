-- Users' own APIs, second milestone: self-service proof of control, and uploaded specs.
--
-- Proof: each API gets a random token. The user publishes the line `apifuzz-verify=<token>` at
-- https://<their API>/.well-known/apifuzz-verify.txt, and the backend approves the API when it
-- finds it there (setting verified_at). It checks the file again before every scan, so taking it
-- down withdraws the permission. Approving or rejecting by hand in the table editor still works:
-- an API approved by hand has no verified_at and its file is never checked; a rejected one can't
-- be approved by the backend, because its update only matches status = 'pending'.
--
-- Upload: instead of a spec_url, an API may carry the spec itself (spec_text, at most 1 MB, and
-- the file's name in spec_name). The backend lists targets without spec_text and reads it only
-- when a scan needs it.
--
-- Apply this BEFORE deploying the backend that uses it: that backend selects the new columns.
-- Still locked down like before: row level security on, no policies, no browser grants.

alter table public.targets
  add column if not exists verify_token text not null default replace(gen_random_uuid()::text, '-', '')
    check (char_length(verify_token) between 16 and 64),
  add column if not exists verified_at timestamptz,
  add column if not exists spec_name text check (spec_name is null or char_length(spec_name) <= 100),
  add column if not exists spec_text text check (spec_text is null or octet_length(spec_text) <= 1000000);

-- A spec is linked or uploaded: one or the other, and a name exactly when there is a file.
alter table public.targets alter column spec_url drop not null;
alter table public.targets drop constraint if exists targets_has_one_spec;
alter table public.targets add constraint targets_has_one_spec
  check ((spec_url is null) <> (spec_text is null) and (spec_name is null) = (spec_text is null));

-- The backend may now change these columns of a user's own row, and nothing else: not the
-- owner, the address, the token, or the admin's note. It never sets status to 'rejected'.
grant update (status, verified_at, spec_url, spec_name, spec_text) on table public.targets to service_role;

-- Still nothing for the browser roles.
revoke all on table public.targets from anon, authenticated;
