# two-user-verify: the read the checker cannot make

The checker reads files. This example adds the missing half — the same
migration set applied to a real database and read the way two users would.
One pair of states: `insecure/` is the always-true SELECT policy, `fixed/`
is the same schema after the policy is scoped to the caller.

## Run the checker (the floor)

```bash
python3 rls_check.py examples/two-user-verify/insecure   # 1 high, FAIL
python3 rls_check.py examples/two-user-verify/fixed      # 0 findings, PASS
```

The insecure run reports the finding with its `file:line`, one sentence on
why it matters, and the fix SQL. The fixed run prints the line this repo is
right to print: *no findings means none of the known patterns matched, not
that the app is secure.*

## Run the read (the verdict)

```bash
cd examples/two-user-verify
npm install
node verify.mjs
```

This applies each migration set to a fresh database, seeds two rows, and
reads them as `anon`, as user A and as user B. On `insecure/` the honest
output is three passes and one leak: user B sees user A's row. On `fixed/`
every check passes — each user reads only their own rows, a write as another
user is denied, a write as yourself succeeds.

Exit code is 0 only when every check matches its state.

## What the example shows

| | static pass | two-user read |
|---|---|---|
| `insecure/` | `[HIGH] RLS004` — policy does not tie the row to the caller | user B reads user A's rows |
| `fixed/` | clean | clean |

Two things the pair demonstrates that neither half shows alone:

1. **A policy can be scoped in shape and open in effect.** `using (true)`
   with an owner column in the table is RLS004 today. A policy that compares
   `auth.uid()` with the wrong column, or one whose predicate is a shared
   setting, passes the static pass entirely — the file reader cannot know
   what the setting resolves to or which column was meant. The read is the
   only thing that catches those, and this script is the cheapest version of
   that read: two claims, one `count`, no Supabase project, no credentials.
2. **Read scoping without write scoping is half a fix.** The fixed set
   carries a `with check` alongside the scoped `using`, and the script
   asserts the cross-tenant INSERT raises instead of succeeding.

## Notes

- `auth.uid()` is created by the script, not by the migrations: PGlite ships
  no `auth` schema. It is built exactly the way Supabase defines it — a
  reader of the claim PostgREST sets per transaction — which is also why the
  script sets both `request.jwt.claims` and `request.jwt.claim.sub`:
  PostgREST sets both and `auth.uid()` reads the singular one.
- The script is `verify.mjs` + `package.json`, i.e. the only addition that
  carries a dependency. The checker itself stays one file with none, and the
  SQL alone is enough to reproduce the read on any PostgreSQL 16 by hand.
- Seed rows use fixed UUIDs so output is diffable.