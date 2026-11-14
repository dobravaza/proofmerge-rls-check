-- "Fix": the messages list came back empty in the app, so RLS was turned off.
alter table public.messages disable row level security;
