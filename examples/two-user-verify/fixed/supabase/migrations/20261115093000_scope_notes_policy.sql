-- The fix: scope the read to the caller, and match it with a write check so
-- the same gap cannot be reopened through INSERT (a read-only scoping with
-- no WITH CHECK on writes is the second half of this bug).

drop policy if exists notes_select on public.notes;

create policy notes_select on public.notes
  for select to authenticated using (auth.uid() = user_id);

create policy notes_insert on public.notes
  for insert to authenticated with check (auth.uid() = user_id);
