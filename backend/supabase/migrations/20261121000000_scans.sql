-- Scan history for the hosted demo. Only the backend reads and writes this table, with the
-- project's secret key (which acts as the service role and bypasses row level security).
--
-- Row level security is ON with NO policies, and the browser roles have no grants: a signed-in
-- user holding the publishable key can't read, add, change or delete a single row, not even their
-- own. Ownership is enforced by the backend (a user sees their scans, an admin everyone's).

create table if not exists public.scans (
  id            uuid primary key,
  user_id       uuid not null references auth.users (id) on delete cascade,
  user_email    text not null,
  target        text not null,
  spec_url      text not null,
  checks        text[] not null,
  status        text not null check (status in ('done', 'failed')),
  requests_sent integer not null default 0 check (requests_sent >= 0),
  created_at    timestamptz not null,
  report        jsonb,
  error         text
);

-- History lists and the daily-limit counts both filter by owner and time.
create index if not exists scans_user_created on public.scans (user_id, created_at desc);
create index if not exists scans_created on public.scans (created_at);

alter table public.scans enable row level security;
revoke all on table public.scans from anon, authenticated;
