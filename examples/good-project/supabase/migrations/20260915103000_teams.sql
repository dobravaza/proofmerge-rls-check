-- Team workspaces: access goes through a membership helper.

create table public.teams (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  created_by uuid not null references auth.users (id)
);

create table public.team_members (
  team_id uuid not null references public.teams (id) on delete cascade,
  user_id uuid not null references auth.users (id),
  primary key (team_id, user_id)
);

create function public.is_team_member(p_team uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.team_members m
    where m.team_id = p_team and m.user_id = (select auth.uid())
  );
$$;

alter table public.teams enable row level security;
alter table public.team_members enable row level security;

create policy "Members read their teams" on public.teams
  for select to authenticated using (public.is_team_member(id));
create policy "Creator manages team" on public.teams
  for all to authenticated
  using ((select auth.uid()) = created_by)
  with check ((select auth.uid()) = created_by);

create policy "Members read memberships" on public.team_members
  for select to authenticated using (public.is_team_member(team_id));
create policy "Members leave teams" on public.team_members
  for delete to authenticated using ((select auth.uid()) = user_id);

-- Idempotent policy creation inside a DO block, as AI tools often generate it.
do $$
begin
  if not exists (
    select 1 from pg_policies where tablename = 'team_members' and policyname = 'Members join via invite'
  ) then
    create policy "Members join via invite" on public.team_members
      for insert to authenticated
      with check ((select auth.uid()) = user_id);
  end if;
end
$$;
