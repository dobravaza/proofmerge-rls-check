-- Since 30 Oct 2026 Supabase no longer grants new tables in public to the API roles automatically.
-- Grant each table only what the app needs; RLS policies still decide which rows each user reaches.
grant select, insert, update, delete on public.profiles, public.todos, public.posts to authenticated;
grant select on public.payments, public.payment_summary to authenticated;
grant select, insert, update, delete on public.teams, public.team_members to authenticated;
-- Published posts are readable without logging in (the posts policy limits anon to published rows).
grant select on public.posts to anon;
