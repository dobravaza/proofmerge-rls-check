-- Initial schema with row level security done properly.

create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  full_name text,
  avatar_path text
);
alter table public.profiles enable row level security;
create policy "Users read own profile" on public.profiles
  for select to authenticated using ((select auth.uid()) = id);
create policy "Users update own profile" on public.profiles
  for update to authenticated
  using ((select auth.uid()) = id)
  with check ((select auth.uid()) = id);

create table public.todos (
  id bigint generated always as identity primary key,
  user_id uuid not null default auth.uid() references auth.users (id),
  title text not null,   -- e.g. 'buy milk; call bank'
  done boolean default false
);
alter table public.todos enable row level security;
create policy "Users manage own todos" on public.todos
  for all to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

create table public.posts (
  id uuid primary key default gen_random_uuid(),
  author_id uuid not null references auth.users (id),
  title text not null,
  body text,
  published boolean not null default false
);
alter table public.posts enable row level security;
create policy "Published posts are public" on public.posts
  for select to anon, authenticated using (published = true);
create policy "Authors manage own posts" on public.posts
  for all to authenticated
  using ((select auth.uid()) = author_id)
  with check ((select auth.uid()) = author_id);

create table public.payments (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id),
  amount_cents integer not null,
  status text not null
);
alter table public.payments enable row level security;
create policy "Users read own payments" on public.payments
  for select to authenticated using ((select auth.uid()) = user_id);
-- Writes to payments happen only from the server with the service role.

create view public.payment_summary
  with (security_invoker = true) as
  select user_id, sum(amount_cents) as total_cents
  from public.payments
  group by user_id;

insert into storage.buckets (id, name, public)
values ('user-documents', 'user-documents', false);
