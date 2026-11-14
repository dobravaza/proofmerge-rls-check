-- Initial schema, generated with an AI app builder. Intentionally insecure sample.

create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  full_name text,
  email text,
  stripe_customer_id text
);
-- (no row level security on profiles)

create table public.todos (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users (id),
  title text not null,
  done boolean default false
);
alter table public.todos enable row level security;
create policy "Enable all access for all users" on public.todos
  for all using (true) with check (true);

create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id),
  body text
);
alter table public.notes enable row level security;
-- (no policy on notes: the app gets empty results)

create table public.payments (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id),
  amount_cents integer not null,
  status text not null
);
alter table public.payments enable row level security;
create policy "Authenticated users can read payments" on public.payments
  for select to authenticated using (auth.role() = 'authenticated');
create policy "Users can update payments" on public.payments
  for update to authenticated using (status <> 'refunded');
grant all on table public.profiles to anon;

create table public.messages (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id),
  body text not null
);
alter table public.messages enable row level security;
create policy "Users manage own messages" on public.messages
  for all to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

create function public.get_user_emails()
returns table (id uuid, email text)
language sql
security definer
as $$
  select id, email from auth.users;
$$;

create view public.payment_summary as
  select user_id, sum(amount_cents) as total_cents
  from public.payments
  group by user_id;

insert into storage.buckets (id, name, public)
values ('avatars', 'avatars', true), ('user-documents', 'user-documents', true);
