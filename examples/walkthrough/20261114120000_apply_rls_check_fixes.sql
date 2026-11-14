-- Walkthrough: the fixes rls_check suggested for examples/bad-project, reviewed by a person first.
-- Copy into supabase/migrations/ after the existing files. Read every statement before you run it.

-- RLS005: protection was switched off "to fix" an empty list. The real cause was a missing login, not RLS.
alter table public.messages enable row level security;

-- RLS001 + GRANT001: profiles had no RLS and an explicit grant to anon.
alter table public.profiles enable row level security;
create policy "profiles_owner_all" on public.profiles for all to authenticated
  using ((select auth.uid()) = id) with check ((select auth.uid()) = id);
revoke all on public.profiles from anon;

-- RLS003: always-true policy on todos.
drop policy if exists "Enable all access for all users" on public.todos;
create policy "todos_owner_all" on public.todos for all to authenticated
  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);

-- RLS002: RLS on notes but no policy.
create policy "notes_owner_all" on public.notes for all to authenticated
  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);

-- RLS004 (x2): payments policies only checked "logged in", not "my row".
drop policy if exists "Authenticated users can read payments" on public.payments;
create policy "payments_owner_read" on public.payments for select to authenticated
  using ((select auth.uid()) = user_id);
-- Users should not edit payment rows at all; status changes come from the server (webhook) with the service role.
drop policy if exists "Users can update payments" on public.payments;

-- VIEW001: the view now respects the RLS of public.payments.
alter view public.payment_summary set (security_invoker = true);

-- FUNC001: pin search_path (the body already uses schema-qualified auth.users).
alter function public.get_user_emails() set search_path = '';
-- Not reported by rls_check (see "What the tool did not catch"): this function returns every
-- user's email and, like any new function in public, can be called through the API by anyone.
revoke execute on function public.get_user_emails() from public, anon, authenticated;

-- STOR001: private documents bucket. Avatars stay public on purpose (accepted, still reported as MEDIUM).
update storage.buckets set public = false where id = 'user-documents';
