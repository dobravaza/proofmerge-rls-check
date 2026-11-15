-- Same table, same grants. Only the policy changes, in the next migration.

create table if not exists public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  body text not null
);

alter table public.notes enable row level security;

grant select, insert on public.notes to authenticated;
grant select on public.notes to anon;

create policy notes_select on public.notes
  for select to authenticated using (true);
