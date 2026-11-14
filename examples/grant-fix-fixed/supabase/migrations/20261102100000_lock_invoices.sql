-- The fix for examples/grant-fix: undo the schema-wide grant, turn on RLS,
-- let each signed-in user read only their own invoices, and grant only what the app uses.
revoke all on all tables in schema public from anon, authenticated;
alter table public.invoices enable row level security;
create policy "invoices_owner_select" on public.invoices
  for select to authenticated
  using ((select auth.uid()) = user_id);
grant select on public.invoices to authenticated;
