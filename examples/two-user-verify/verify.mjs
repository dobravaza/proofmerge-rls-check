/**
 * verify.mjs — proves the two-user read, at runtime, on the migrations beside this file.
 *
 * Two fresh databases, one per migration set:
 *   insecure/  ->  the always-true SELECT policy
 *   fixed/     ->  the same state after the scoping migration
 * Each database gets two seed rows (user A and user B). Then the same reads
 * are run as anon, as user A and as user B, and the results are asserted
 * against what the migration set promises.
 *
 * Run: npm install && node verify.mjs
 *
 * PGlite has no auth schema, so auth.uid() is created here the way Supabase
 * defines it: a reader of the claim PostgREST sets per transaction. Both GUCs
 * are set (request.jwt.claims and request.jwt.claim.sub) because PostgREST
 * sets both and auth.uid() reads the singular one.
 */
import { PGlite } from "@electric-sql/pglite";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const USER_A = "11111111-1111-1111-1111-111111111111";
const USER_B = "22222222-2222-2222-2222-222222222222";

async function openDatabase(setName) {
  const db = new PGlite();
  db.exec(
    "create schema auth;\n" +
      "create role authenticated nologin;\n" +
      "create role anon nologin;\n" +
      "create or replace function auth.uid() returns uuid language sql stable\n" +
      "  as $$ select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $$;"
  );
  const dir = join(HERE, setName, "supabase", "migrations");
  for (const file of readdirSync(dir).sort()) {
    await db.exec(readFileSync(join(dir, file), "utf8"));
  }
  await db.exec(
    "insert into public.notes (user_id, body) values\n" +
      `  ('${USER_A}', 'user A private note'),\n` +
      `  ('${USER_B}', 'user B private note');`
  );
  return db;
}

async function asRole(db, role, uuid, sql) {
  const claims = JSON.stringify({ sub: uuid, role }).replace(/'/g, "''");
  try {
    const res = await db.exec(
      `begin;\n set local role ${role};\n select set_config('request.jwt.claims', '${claims}', true);\n select set_config('request.jwt.claim.sub', '${String(uuid).replace(/'/g, "''")}', true);\n ${sql}\n rollback;`
    );
    return res[res.length - 2].rows;
  } catch (e) {
    await db.exec("rollback").catch(() => {});
    throw e;
  }
}

let failures = 0;
async function check(name, fn) {
  try {
    await fn();
    console.log(`  PASS  ${name}`);
  } catch (e) {
    failures++;
    console.log(`  FAIL  ${name}\n        ${e.message.split("\n")[0]}`);
  }
}

{
  const db = await openDatabase("insecure");
  console.log("\ninsecure/ — RLS on, SELECT policy exists, anon reads nothing");

  await check("anon reads nothing (the half every outside check sees)", async () => {
    const rows = await asRole(db, "anon", null, "select count(*)::int as n from public.notes;");
    assert.equal(rows[0].n, 0);
  });

  await check("user B reads user A's rows — the leak the scanner cannot see", async () => {
    const rows = await asRole(
      db,
      "authenticated",
      USER_B,
      "select user_id::text, body from public.notes order by body;"
    );
    assert.equal(rows.length, 2, `user B saw ${rows.length} rows`);
    assert.ok(
      rows.some((r) => r.user_id === USER_A),
      "user A's row visible to user B"
    );
  });

  await check("a write as another user is still denied (no INSERT policy)", async () => {
    await assert.rejects(
      asRole(
        db,
        "authenticated",
        USER_A,
        `insert into public.notes (user_id, body) values ('${USER_B}', 'planted by A');`
      ),
      /row-level security|violates/i
    );
  });
  await db.close();
}

{
  const db = await openDatabase("fixed");
  console.log("\nfixed/ — same grants, policy scoped to the caller");

  await check("anon reads nothing", async () => {
    const rows = await asRole(db, "anon", null, "select count(*)::int as n from public.notes;");
    assert.equal(rows[0].n, 0);
  });

  await check("user A reads only own rows", async () => {
    const rows = await asRole(db, "authenticated", USER_A, "select user_id::text from public.notes;");
    assert.equal(rows.length, 1);
    assert.equal(rows[0].user_id, USER_A);
  });

  await check("user B reads only own rows", async () => {
    const rows = await asRole(db, "authenticated", USER_B, "select user_id::text from public.notes;");
    assert.equal(rows.length, 1);
    assert.equal(rows[0].user_id, USER_B);
  });

  await check("a write as another user is denied (WITH CHECK on INSERT)", async () => {
    await assert.rejects(
      asRole(
        db,
        "authenticated",
        USER_A,
        `insert into public.notes (user_id, body) values ('${USER_B}', 'planted by A');`
      ),
      /row-level security|violates/i
    );
  });

  await check("a write as yourself succeeds", async () => {
    const rows = await asRole(
      db,
      "authenticated",
      USER_A,
      `insert into public.notes (user_id, body) values ('${USER_A}', 'own note') returning id;`
    );
    assert.equal(rows.length, 1);
  });
  await db.close();
}

console.log(
  failures === 0
    ? "\nALL CHECKS PASS — the two-user read is the verdict; the static pass is only the floor.\n"
    : `\n${failures} CHECK(S) FAILED\n`
);
process.exit(failures === 0 ? 0 : 1);