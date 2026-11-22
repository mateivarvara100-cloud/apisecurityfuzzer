-- Users' own APIs for the hosted demo. A user asks for one to be added (status 'pending'); an
-- admin approves or rejects it by changing `status` here, in the Supabase table editor, and may
-- leave a short `note` the user sees. Only approved targets can be scanned.
--
-- Locked down like public.scans: row level security ON with NO policies, and no grants for the
-- browser roles, so only the backend (the secret key's service role) can read or write rows.
-- Ownership and the per-user limit are enforced by the backend.
--
-- The test-account tokens a scan uses are never stored, here or anywhere else.

create table if not exists public.targets (
  id          uuid primary key,
  user_id     uuid not null references auth.users (id) on delete cascade,
  user_email  text not null,
  label       text not null check (char_length(label) between 1 and 60),
  base_url    text not null check (base_url like 'https://%' and char_length(base_url) <= 300),
  spec_url    text not null check (spec_url like 'https://%' and char_length(spec_url) <= 2048),
  status      text not null default 'pending' check (status in ('pending', 'approved', 'rejected')),
  note        text check (char_length(note) <= 300),
  created_at  timestamptz not null,
  unique (user_id, base_url)
);

create index if not exists targets_user on public.targets (user_id, created_at desc);
-- What an admin looks at: the requests waiting for a decision.
create index if not exists targets_pending on public.targets (created_at) where status = 'pending';

alter table public.targets enable row level security;
revoke all on table public.targets from anon, authenticated;

-- The backend lists, adds and deletes a user's targets. It never changes one: approving is the
-- admin's job, done here in the dashboard.
grant select, insert, delete on table public.targets to service_role;
