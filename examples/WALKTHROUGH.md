# Walkthrough: from 15 findings to a reviewed pass

`examples/bad-project` is a small Next.js + Supabase app written to look like what AI app builders often produce. It is a sample we wrote for this repository, not a customer's application. Its migrations date from September 2026, before Supabase stopped granting new tables to the API roles automatically (30 Oct 2026 for existing projects), so its tables carry the old default grants to `anon` and `authenticated`. Everything below is the tool's real output (version 0.1.0, run with `--no-color`); the regression test `test_walkthrough_fix_migration_clears_database_findings` keeps step 2 true.

## Step 1: first run

```bash
python3 rls_check.py examples/bad-project
```

```
Summary: 7 critical, 5 high, 2 medium, 1 low  ->  FAIL (fail-on: high)
```

The finding that tells the story is on `public.messages`:

```
table public.messages
  [CRITICAL] RLS005  Row level security was switched off in a later migration
      where: supabase/migrations/20260915103000_fix_empty_messages.sql:2
      why:   The table was protected, then a later migration removed the protection. Any API role with privileges on it can now read and change every row; in Supabase projects created before 30 May 2026, anon held those privileges on every table made before 30 Oct 2026.
      fix:   alter table public.messages enable row level security;
```

The second migration says why it exists: the messages list came back empty in the app, so RLS was turned off. An empty list under RLS usually means the request had no logged-in user, or the rows belong to someone else. Turning RLS off makes the list appear for the developer and for everyone else holding the public anon key.

## Step 2: one reviewed fix migration

[`walkthrough/20261114120000_apply_rls_check_fixes.sql`](walkthrough/20261114120000_apply_rls_check_fixes.sql) applies the tool's suggestions, with three changes a person made after reading them:

1. **Avatars stay public.** Profile pictures are meant to be seen. The finding is accepted and stays in the report as MEDIUM.
2. **The payments update policy is dropped, not rewritten.** The tool suggested an owner-only update policy. Users should not edit payment rows at all; status changes come from the server.
3. **`get_user_emails()` loses its execute grant.** The tool reported only the missing `search_path`. See "What the tool did not catch" below.

Copied into `supabase/migrations/` and run again:

```
Supabase RLS pre-launch check v0.1.0 - my-app
Read 3 SQL file(s) and 4 app source file(s); 5 table(s) in exposed schema(s): public

app code .env.example
  [CRITICAL] KEY001  Service-role key in a browser-exposed env var (NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY)
app code src/components/AdminPanel.tsx
  [CRITICAL] KEY002  Service-role key referenced in a file marked "use client" (SUPABASE_SERVICE_ROLE_KEY)
app code src/lib/legacy.js
  [CRITICAL] KEY003  Hardcoded service-role key in source (value redacted)
app code src/lib/supabaseAdmin.ts
  [CRITICAL] KEY001  Service-role key in a browser-exposed env var (NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY)
storage bucket avatars
  [MEDIUM] STOR001  Storage bucket is public
Summary: 4 critical, 0 high, 1 medium, 0 low  ->  FAIL (fail-on: high)
```

(`where` / `why` / `fix` lines removed above for length.) Every database finding is gone except the accepted bucket. The four that remain are in the app code, and SQL cannot fix them.

## Step 3: keep the service-role key on the server

- `.env.example`: `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=` renamed to `SUPABASE_SERVICE_ROLE_KEY=`. In a real project the key would also be rotated in Supabase, because it has already shipped to browsers.
- `src/lib/supabaseAdmin.ts`: reads `SUPABASE_SERVICE_ROLE_KEY` and starts with `import "server-only";`, so the Next.js build fails if a client component ever imports it.
- `src/lib/legacy.js`: deleted (hardcoded key).
- `src/components/AdminPanel.tsx`: no Supabase client any more; the button calls `fetch("/api/admin/payments")`.

```
Supabase RLS pre-launch check v0.1.0 - my-app
Read 3 SQL file(s) and 3 app source file(s); 5 table(s) in exposed schema(s): public

storage bucket avatars
  [MEDIUM] STOR001  Storage bucket is public
      where: supabase/migrations/20260901090000_init.sql:66
      why:   Every file in a public bucket can be downloaded by anyone who has or guesses the URL, with no login and no policy check.
      fix:   update storage.buckets set public = false where id = 'avatars';  -- then serve files with signed URLs

Summary: 0 critical, 0 high, 1 medium, 0 low  ->  PASS (fail-on: high)
Limits: Static reading of migration files only: changes made in the Supabase dashboard are invisible to this tool, and it does not test policies against a live database or replace a human review.
```

## What the tool did not catch

A pass means none of the known patterns matched. In this sample, three things still needed a person:

1. **`public.get_user_emails()` returned every user's email to anyone.** It is `SECURITY DEFINER`, so it reads `auth.users` with its owner's rights, and PostgreSQL lets every role execute a new function unless that is revoked. Through the Supabase API that means any visitor could call it. The tool flagged only the missing `search_path`; the fix migration also runs `revoke execute ... from public, anon, authenticated`.
2. **`/api/admin/payments` must check that the caller is an admin.** Moving the key to the server only helps if the route refuses everyone else. API-route authorization is outside what this tool reads.
3. **Policies and buckets changed in the Supabase dashboard** and never pulled into a migration are invisible to it. Run `supabase db pull` before trusting a clean result.

If you want a person to check those parts before launch, that is what [Proofmerge](https://proofmerge.com) does: a fixed-price Launch Security Check with a written report.
