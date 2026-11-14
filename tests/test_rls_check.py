"""Tests for rls_check.py. Run: python3 -m unittest discover -s tests -v"""
import base64
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
KIT = os.path.dirname(HERE)
sys.path.insert(0, KIT)
import rls_check  # noqa: E402

BAD = os.path.join(KIT, "examples", "bad-project")
GOOD = os.path.join(KIT, "examples", "good-project")
MIG = "supabase/migrations/"
OWN = "(select auth.uid()) = user_id"


def fake_service_jwt():
    def enc(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")
    return "%s.%s.%s" % (enc({"alg": "HS256", "typ": "JWT"}),
                         enc({"iss": "unit-test", "role": "service_role"}), "UNIT_TEST_FAKE_SIGNATURE")


def fake_anon_jwt():
    def enc(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")
    return "%s.%s.%s" % (enc({"alg": "HS256", "typ": "JWT"}),
                         enc({"iss": "unit-test", "role": "anon"}), "UNIT_TEST_FAKE_SIGNATURE")


class Base(unittest.TestCase):
    def scan(self, files):
        """files: {relative path: content} (a bare SQL string means one migration)."""
        if isinstance(files, str):
            files = {MIG + "0001_init.sql": files}
        with tempfile.TemporaryDirectory() as root:
            for rel, content in files.items():
                path = os.path.join(root, rel)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(content)
            return rls_check.scan_project(root)

    def rules(self, files):
        return sorted(f.rule for f in self.scan(files)["findings"])

    def one(self, files, rule):
        hits = [f for f in self.scan(files)["findings"] if f.rule == rule]
        self.assertEqual(len(hits), 1, "expected exactly one %s, got %r" % (rule, [h.title for h in hits]))
        return hits[0]


TODOS = "create table public.todos (id bigint primary key, user_id uuid references auth.users(id), title text);\n"
ITEMS = "create table public.items (id bigint primary key, name text);\n"
RLS_ON = "alter table public.%s enable row level security;\n"
GOOD_POLICY = ('create policy "own" on public.todos for all to authenticated using (%s) with check (%s);\n' % (OWN, OWN))


class TestRls001NoRls(Base):
    def test_positive(self):
        f = self.one(TODOS, "RLS001")
        self.assertEqual(f.severity, "critical")
        self.assertEqual((f.file, f.line), (MIG + "0001_init.sql", 1))
        self.assertIn("alter table public.todos enable row level security;", f.fix)

    def test_positive_unqualified_and_quoted_names(self):
        self.assertEqual(self.rules('create table "Orders" (id int);\ncreate table if not exists things (id int);'),
                         ["RLS001", "RLS001"])

    def test_positive_policy_without_enable(self):
        f = self.one(TODOS + GOOD_POLICY, "RLS001")
        self.assertIn("Policies exist", f.title)

    def test_negative(self):
        self.assertEqual(self.rules(TODOS + RLS_ON % "todos" + GOOD_POLICY), [])

    def test_negative_other_schema_temp_and_dropped(self):
        sql = ("create table private.audit (id int);\ncreate temp table scratch (id int);\n"
               "create table public.old (id int);\ndrop table if exists public.old cascade;\n")
        self.assertEqual(self.rules(sql), [])

    def test_negative_commented_out_and_string_content(self):
        sql = ("-- create table public.ghost (id int);\n/* create table public.ghost2 (id int); */\n"
               "create table private.t (note text default 'x; create table public.fake (id int)');\n")
        self.assertEqual(self.rules(sql), [])

    def test_negative_dynamic_enable_loop(self):
        sql = TODOS + GOOD_POLICY + """do $$ declare r record; begin
          for r in select tablename from pg_tables where schemaname = 'public' loop
            execute format('alter table public.%I enable row level security', r.tablename);
          end loop; end $$;"""
        self.assertEqual(self.rules(sql), [])


class TestRls002NoPolicy(Base):
    def test_positive(self):
        f = self.one(TODOS + RLS_ON % "todos", "RLS002")
        self.assertEqual(f.severity, "low")

    def test_positive_after_drop_policy(self):
        sql = TODOS + RLS_ON % "todos" + GOOD_POLICY + 'drop policy if exists "own" on public.todos;'
        self.assertEqual(self.rules(sql), ["RLS002"])

    def test_negative(self):
        self.assertEqual(self.rules(TODOS + RLS_ON % "todos" + GOOD_POLICY), [])

    def test_negative_policy_created_inside_do_block(self):
        sql = TODOS + RLS_ON % "todos" + """do $$ begin
          if not exists (select 1 from pg_policies where policyname = 'own') then
            create policy "own" on public.todos for all to authenticated
              using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
          end if; end $$;"""
        self.assertEqual(self.rules(sql), [])


class TestRls003AlwaysTrue(Base):
    def test_positive_all_true_default_role_is_critical(self):
        f = self.one(TODOS + RLS_ON % "todos" + 'create policy "open" on public.todos for all using (true) with check (true);', "RLS003")
        self.assertEqual(f.severity, "critical")
        self.assertEqual(f.line, 3)

    def test_positive_insert_true_authenticated_is_high(self):
        f = self.one(ITEMS + RLS_ON % "items" + "create policy ins on items for insert to authenticated with check (true);", "RLS003")
        self.assertEqual(f.severity, "high")

    def test_positive_update_check_true(self):
        sql = TODOS + RLS_ON % "todos" + 'create policy "u" on public.todos for update to authenticated using (%s) with check ( TRUE );' % OWN
        self.assertEqual(self.rules(sql), ["RLS003"])

    def test_positive_anon_read_of_user_table_is_medium(self):
        f = self.one(TODOS + RLS_ON % "todos" + 'create policy "r" on public.todos for select to anon using (true);', "RLS003")
        self.assertEqual(f.severity, "medium")

    def test_positive_anon_read_of_plain_table_is_low(self):
        f = self.one(ITEMS + RLS_ON % "items" + 'create policy "r" on public.items for select using (true);', "RLS003")
        self.assertEqual(f.severity, "low")

    def test_positive_alter_policy_makes_it_open(self):
        sql = TODOS + RLS_ON % "todos" + GOOD_POLICY + 'alter policy "own" on public.todos using (true) with check (true);'
        self.assertEqual(self.rules(sql), ["RLS003"])

    def test_negative_scoped_policies(self):
        sql = (TODOS + RLS_ON % "todos" + GOOD_POLICY + ITEMS + RLS_ON % "items"
               + "create policy r on public.items for select to anon using (name is not null);")
        self.assertEqual(self.rules(sql), [])

    def test_negative_service_role_only_and_later_fixed(self):
        sql = (TODOS + RLS_ON % "todos" + GOOD_POLICY
               + 'create policy "svc" on public.todos for all to service_role using (true) with check (true);\n'
               + 'create policy "open" on public.todos for all using (true);\n'
               + 'drop policy "open" on public.todos;')
        self.assertEqual(self.rules(sql), [])


class TestRls004NoOwnerCheck(Base):
    def test_positive_role_check_only(self):
        sql = TODOS + RLS_ON % "todos" + "create policy r on public.todos for select to authenticated using (auth.role() = 'authenticated');"
        f = self.one(sql, "RLS004")
        self.assertEqual(f.severity, "high")
        self.assertIn("user_id", f.fix)

    def test_positive_true_for_authenticated_read(self):
        sql = TODOS + RLS_ON % "todos" + "create policy r on public.todos for select to authenticated using (true);"
        self.assertEqual(self.rules(sql), ["RLS004"])

    def test_positive_write_without_identity(self):
        sql = TODOS + RLS_ON % "todos" + "create policy u on public.todos for update to authenticated using (title <> '');"
        self.assertEqual(self.rules(sql), ["RLS004"])

    def test_positive_uid_is_not_null(self):
        sql = TODOS + RLS_ON % "todos" + "create policy u on public.todos for delete to authenticated using (auth.uid() is not null);"
        self.assertEqual(self.rules(sql), ["RLS004"])

    def test_negative_owner_check(self):
        sql = TODOS + RLS_ON % "todos" + "create policy u on public.todos for update to authenticated using (auth.uid() = user_id);"
        self.assertEqual(self.rules(sql), [])

    def test_negative_helper_function_with_auth_uid(self):
        sql = (TODOS + RLS_ON % "todos"
               + "create function public.owns(p uuid) returns boolean language sql stable as $$ select p = auth.uid() $$;\n"
               + "create policy u on public.todos for update to authenticated using (public.owns(user_id));")
        self.assertEqual(self.rules(sql), [])

    def test_negative_table_without_owner_column(self):
        sql = ITEMS + RLS_ON % "items" + "create policy u on public.items for update to authenticated using (name <> '');"
        self.assertEqual(self.rules(sql), [])


class TestRls005DisabledLater(Base):
    def test_positive_across_files(self):
        f = self.one({
            MIG + "0001_init.sql": TODOS + RLS_ON % "todos" + GOOD_POLICY,
            MIG + "0002_hotfix.sql": "-- quick fix\nalter table public.todos disable row level security;\n",
        }, "RLS005")
        self.assertEqual(f.severity, "critical")
        self.assertEqual((f.file, f.line), (MIG + "0002_hotfix.sql", 2))

    def test_negative_reenabled_later(self):
        self.assertEqual(self.rules({
            MIG + "0001_init.sql": TODOS + RLS_ON % "todos" + GOOD_POLICY,
            MIG + "0002_off.sql": "alter table public.todos disable row level security;",
            MIG + "0003_on.sql": "ALTER TABLE ONLY public.todos ENABLE ROW LEVEL SECURITY;",
        }), [])

    def test_order_is_by_file_name_not_creation(self):
        self.assertEqual(self.rules({
            MIG + "0003_on.sql": "alter table todos enable row level security;",
            MIG + "0001_init.sql": TODOS + GOOD_POLICY,
            MIG + "0002_off.sql": "alter table todos disable row level security;",
        }), [])


class TestFunc001SecurityDefiner(Base):
    FN = "create or replace function public.f() returns int language sql security definer %s as $$ select 1 $$;"

    def test_positive(self):
        f = self.one(self.FN % "", "FUNC001")
        self.assertEqual(f.severity, "medium")

    def test_negative_search_path_inline(self):
        self.assertEqual(self.rules(self.FN % "set search_path = ''"), [])

    def test_negative_search_path_altered_later(self):
        self.assertEqual(self.rules(self.FN % "" + "\nalter function public.f() set search_path = public, pg_temp;"), [])

    def test_negative_invoker_and_body_text(self):
        sql = "create function public.g() returns text language sql as $$ select 'security definer' $$;"
        self.assertEqual(self.rules(sql), [])


class TestView001SecurityInvoker(Base):
    def test_positive(self):
        f = self.one(ITEMS + RLS_ON % "items" + "create policy r on items for select to authenticated using (name <> '');\n"
                     "create or replace view public.v as select * from public.items;", "VIEW001")
        self.assertEqual(f.severity, "high")
        self.assertEqual(f.line, 4)

    def test_positive_explicit_false(self):
        self.assertEqual(self.rules("create view v with (security_invoker = false) as select 1;"), ["VIEW001"])

    def test_negative_inline_and_altered(self):
        sql = ("create view public.v1 with (security_invoker = true) as select 1 as x;\n"
               "create view public.v2 with (security_invoker=on) as select 1 as x;\n"
               "create view public.v3 as select 1 as x;\nalter view public.v3 set (security_invoker = true);\n"
               "create view private.v4 as select 1 as x;\n"
               "create view public.v5 as select 1 as x;\ndrop view public.v5;\n")
        self.assertEqual(self.rules(sql), [])


class TestStor001PublicBucket(Base):
    def test_positive(self):
        res = self.scan("insert into storage.buckets (id, name, public) values ('avatars','avatars', true), ('invoices','invoices',true), ('tmp','tmp',false);")
        got = {f.target: f.severity for f in res["findings"]}
        self.assertEqual(got, {"storage bucket avatars": "medium", "storage bucket invoices": "high"})

    def test_positive_update_to_public(self):
        sql = ("insert into storage.buckets (id, name) values ('files', 'files');\n"
               "update storage.buckets set public = true where id = 'files';")
        self.assertEqual(self.one(sql, "STOR001").line, 2)

    def test_negative_private_and_made_private_later(self):
        sql = ("insert into storage.buckets (id, name, public) values ('a','a', false);\n"
               "insert into storage.buckets (id, name, public) values ('b','b', true);\n"
               "update storage.buckets set public = false where id = 'b';")
        self.assertEqual(self.rules(sql), [])


class TestGrant001AnonGrant(Base):
    PAY = "create table public.payments (id int primary key, amount int);\n"

    def test_positive_write_grant_is_high(self):
        res = self.scan(self.PAY + "grant select, insert on table public.payments to anon;")
        got = {f.rule: f.severity for f in res["findings"]}
        self.assertEqual(got, {"RLS001": "critical", "GRANT001": "high"})

    def test_positive_low_when_rls_and_policy_exist(self):
        sql = (self.PAY + RLS_ON % "payments"
               + "create policy r on public.payments for select to authenticated using (amount > 0);\n"
               + "GRANT ALL ON TABLE public.payments TO anon, authenticated;")
        self.assertEqual(self.one(sql, "GRANT001").severity, "low")

    def test_negative_non_sensitive_other_role_and_revoked(self):
        sql = (self.PAY + RLS_ON % "payments"
               + "create policy r on public.payments for select to authenticated using (amount > 0);\n"
               + ITEMS + RLS_ON % "items" + "create policy r on public.items for select to authenticated using (name <> '');\n"
               + "grant select on public.items to anon;\n"
               + "grant all on public.payments to authenticated;\n"
               + "grant select on public.payments to anon;\nrevoke all on public.payments from anon;\n"
               + "grant usage on schema public to anon;\ngrant execute on function public.f() to anon;\n")
        self.assertEqual(self.rules(sql), [])


class TestGrant002WideGrants(Base):
    T = "create table public.a (id int primary key, user_id uuid references auth.users(id));\n"
    R = ("alter table public.a enable row level security;\n"
         'create policy "own" on public.a for all to authenticated using ((select auth.uid()) = user_id) '
         "with check ((select auth.uid()) = user_id);\n")

    def wide(self, files):
        return [(f.severity, f.title) for f in self.scan(files)["findings"] if f.rule == "GRANT002"]

    def test_positive_schema_grant_to_anon_over_table_without_rls_is_high(self):
        f = self.one(self.T + "grant all on all tables in schema public to anon, authenticated;\n", "GRANT002")
        self.assertEqual((f.severity, f.target, f.line), ("high", "schema public", 2))
        self.assertIn("public.a", f.why)
        self.assertIn("revoke all on all tables in schema public", f.fix)

    def test_positive_authenticated_only_is_medium_and_rls_tables_low(self):
        self.assertEqual(self.wide(self.T + "grant all on all tables in schema public to authenticated;\n"),
                         [("medium", "Schema-wide grant to authenticated on all tables")])
        self.assertEqual(self.wide(self.T + self.R + "grant select, insert, update, delete on all tables in schema "
                                   "public to anon, authenticated, service_role;\n"),
                         [("low", "Schema-wide grant to anon, authenticated on all tables")])

    def test_positive_default_privileges_cover_later_tables(self):
        sql = "alter default privileges for role postgres in schema public grant all on tables to anon;\n" + self.T
        self.assertEqual(self.wide(sql), [("high", "Default privileges hand new tables to anon")])
        dump = ('ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "anon";\n'
                + self.T + self.R)
        self.assertEqual(self.wide({"supabase/schema.sql": dump}), [("low", "Default privileges hand new tables to anon")])

    def test_negative_revoked_sequences_and_tables_created_later(self):
        self.assertEqual(self.wide({MIG + "0001_a.sql": self.T + self.R + "grant all on all tables in schema public to anon;\n",
                                    MIG + "0002_b.sql": "revoke all on all tables in schema public from anon;\n"}), [])
        self.assertEqual(self.wide("alter default privileges for role postgres in schema public grant all on tables to anon;\n"
                                   "alter default privileges for role postgres in schema public revoke select, insert, "
                                   "update, delete on tables from anon;\n" + self.T + self.R), [])
        self.assertEqual(self.wide("alter default privileges in schema public grant usage on sequences to anon;\n"
                                   + self.T), [])
        # ON ALL TABLES covers only tables that exist at that moment: public.a is created afterwards.
        late = ("create table public.b (id int);\nalter table public.b enable row level security;\n"
                "grant all on all tables in schema public to anon;\n" + self.T)
        self.assertEqual(self.wide(late), [("low", "Schema-wide grant to anon on all tables")])


class TestKeyRules(Base):
    def test_key001_positive_source_and_env(self):
        res = self.scan({
            "src/lib/admin.ts": "const k = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;\n",
            "web/main.ts": "const k = import.meta.env.VITE_SUPABASE_SERVICE_KEY;\n",
            ".env.local": "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=abc\n",
        })
        self.assertEqual([f.rule for f in res["findings"]], ["KEY001"] * 3)
        self.assertTrue(all(f.severity == "critical" for f in res["findings"]))

    def test_key001_negative(self):
        self.assertEqual(self.rules({
            "src/lib/client.ts": "createClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY)\n",
            ".env": "SUPABASE_SERVICE_ROLE_KEY=abc\nVITE_SUPABASE_ANON_KEY=def\n",
        }), [])

    def test_key002_positive_use_client_is_critical(self):
        f = self.one({"app/admin/page.tsx": '"use client";\nconst k = process.env.SUPABASE_SERVICE_ROLE_KEY;\n'}, "KEY002")
        self.assertEqual((f.severity, f.line), ("critical", 2))

    def test_key002_positive_components_and_src(self):
        res = self.scan({
            "components/Panel.jsx": "const k = process.env.SUPABASE_SERVICE_ROLE_KEY;\n",
            "src/utils/db.ts": "const k = process.env.SUPABASE_SERVICE_ROLE_KEY;\n",
        })
        self.assertEqual({f.target: f.severity for f in res["findings"]},
                         {"app code components/Panel.jsx": "high", "app code src/utils/db.ts": "medium"})

    def test_key002_negative_server_side_files(self):
        line = "const k = process.env.SUPABASE_SERVICE_ROLE_KEY;\n"
        self.assertEqual(self.rules({
            "src/lib/supabase/server.ts": line,
            "app/api/admin/route.ts": line,
            "src/app/actions.ts": '"use server";\n' + line,
            "supabase/functions/sync/index.ts": "const k = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');\n",
            "scripts/seed.mjs": line,
            "src/components/List.tsx": '"use client";\nconst a = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;\n',
            "node_modules/pkg/src/x.js": line,
        }), [])

    def test_key002_negative_server_only_import(self):
        line = "const k = process.env.SUPABASE_SERVICE_ROLE_KEY;\n"
        self.assertEqual(self.rules({"src/lib/supabaseAdmin.ts": 'import "server-only";\n' + line}), [])

    def test_key002_positive_use_client_wins_over_server_only(self):
        f = self.one({"src/lib/admin.ts": '"use client";\nimport "server-only";\nconst k = process.env.SUPABASE_SERVICE_ROLE_KEY;\n'},
                     "KEY002")
        self.assertEqual(f.severity, "critical")

    def test_key003_positive_and_value_never_printed(self):
        token = fake_service_jwt()
        files = {"lib/admin.js": 'const k = "%s";\n' % token}
        f = self.one(files, "KEY003")
        self.assertEqual(f.severity, "critical")
        res = self.scan(files)
        for rendered in (rls_check.render_text(res, ".", "high"), rls_check.render_json(res, "high"),
                         rls_check.render_html(res, ".", "high")):
            self.assertNotIn(token, rendered)
            self.assertNotIn(token.split(".")[2], rendered)

    def test_key003_negative_anon_jwt_and_env_file(self):
        self.assertEqual(self.rules({
            "lib/client.js": 'const k = "%s";\n' % fake_anon_jwt(),
            ".env.local": "SUPABASE_SERVICE_ROLE_KEY=%s\n" % fake_service_jwt(),
        }), [])


DUMP = """
CREATE OR REPLACE FUNCTION "public"."handle_new_user"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO ''
    AS $$ begin insert into public.profiles (id) values (new.id); return new; end; $$;
CREATE TABLE IF NOT EXISTS "public"."profiles" (
    "id" "uuid" NOT NULL,
    "username" "text",
    CONSTRAINT "username_length" CHECK (("char_length"("username") >= 3))
);
ALTER TABLE "public"."profiles" OWNER TO "postgres";
ALTER TABLE ONLY "public"."profiles"
    ADD CONSTRAINT "profiles_id_fkey" FOREIGN KEY ("id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;
CREATE OR REPLACE VIEW "public"."names" WITH ("security_invoker"='on') AS SELECT "username" FROM "public"."profiles";
CREATE POLICY "Users can update own profile." ON "public"."profiles" FOR UPDATE USING ((( SELECT "auth"."uid"() AS "uid") = "id"));
CREATE POLICY "Users can read own profile." ON "public"."profiles" FOR SELECT TO "authenticated" USING (("auth"."uid"() = "id"));
ALTER TABLE "public"."profiles" ENABLE ROW LEVEL SECURITY;
GRANT ALL ON TABLE "public"."profiles" TO "authenticated";
GRANT ALL ON TABLE "public"."profiles" TO "service_role";
"""


class TestDumpStyleSql(Base):
    """`supabase db dump` / pg_dump output quotes every identifier."""

    def test_negative_clean_dump_has_no_findings(self):
        self.assertEqual(self.rules({"supabase/schema.sql": DUMP}), [])

    def test_positive_dump_with_role_only_policy(self):
        bad = DUMP.replace('USING (("auth"."uid"() = "id"))', """USING (("auth"."role"() = 'authenticated'::"text"))""")
        f = self.one({"supabase/schema.sql": bad}, "RLS004")
        self.assertIn("= id", f.fix)  # owner column learned from the ALTER TABLE ... FOREIGN KEY

    def test_positive_dump_view_invoker_off(self):
        bad = DUMP.replace("""("security_invoker"='on')""", """("security_invoker"='false')""")
        self.assertEqual(self.rules({"supabase/schema.sql": bad}), ["VIEW001"])


class TestOutputAndCli(Base):
    def run_cli(self, *args):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = rls_check.main(list(args))
        return code, buf.getvalue()

    def test_html_is_escaped_and_self_contained(self):
        sql = (ITEMS + RLS_ON % "items"
               + 'create policy "<script>alert(1)</script>" on public.items for all using (true);')
        page = rls_check.render_html(self.scan(sql), "proj", "high")
        self.assertNotIn("<script>", page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertNotIn("<link", page)
        self.assertNotIn("src=", page)

    def test_json_shape(self):
        code, out = self.run_cli(BAD, "--json")
        data = json.loads(out)
        self.assertEqual(code, 1)
        self.assertFalse(data["passed"])
        self.assertEqual(set(data["findings"][0]), {"rule", "severity", "target", "title", "file", "line", "why", "fix"})
        self.assertEqual(sum(data["summary"].values()), len(data["findings"]))

    def test_exit_codes_and_fail_on(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "supabase", "migrations"))
            with open(os.path.join(root, "supabase", "migrations", "1.sql"), "w") as fh:
                fh.write(TODOS + RLS_ON % "todos")  # only a low finding (RLS002)
            self.assertEqual(self.run_cli(root)[0], 0)
            self.assertEqual(self.run_cli(root, "--fail-on", "low")[0], 1)
            report = os.path.join(root, "r.html")
            code, out = self.run_cli(root, "--html", report)
            self.assertTrue(os.path.getsize(report) > 500)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(rls_check.main([os.path.join(HERE, "does-not-exist")]), 2)

    def test_empty_project_says_nothing_was_checked(self):
        with tempfile.TemporaryDirectory() as root:
            code, out = self.run_cli(root)
        self.assertEqual(code, 0)
        self.assertIn("no .sql files found", out)


class TestExampleProjects(Base):
    def test_bad_project_end_to_end(self):
        res = rls_check.scan_project(BAD)
        got = sorted((f.rule, f.severity, f.target) for f in res["findings"])
        expected = sorted([
            ("RLS001", "critical", "table public.profiles"),
            ("RLS002", "low", "table public.notes"),
            ("RLS003", "critical", "table public.todos"),
            ("RLS004", "high", "table public.payments"),
            ("RLS004", "high", "table public.payments"),
            ("RLS005", "critical", "table public.messages"),
            ("FUNC001", "medium", "function public.get_user_emails"),
            ("VIEW001", "high", "view public.payment_summary"),
            ("STOR001", "medium", "storage bucket avatars"),
            ("STOR001", "high", "storage bucket user-documents"),
            ("GRANT001", "high", "table public.profiles"),
            ("KEY001", "critical", "app code .env.example"),
            ("KEY001", "critical", "app code src/lib/supabaseAdmin.ts"),
            ("KEY002", "critical", "app code src/components/AdminPanel.tsx"),
            ("KEY003", "critical", "app code src/lib/legacy.js"),
        ])
        self.assertEqual(got, expected)
        self.assertEqual(rls_check.exit_code(res), 1)
        for f in res["findings"]:
            self.assertTrue(os.path.isfile(os.path.join(BAD, f.file)), f.file)
            self.assertGreaterEqual(f.line, 1)
            self.assertTrue(f.why and f.fix)

    def test_walkthrough_fix_migration_clears_database_findings(self):
        """examples/WALKTHROUGH.md: after the reviewed fix migration only the accepted public avatars bucket remains."""
        import shutil
        fix = os.path.join(KIT, "examples", "walkthrough", "20261114120000_apply_rls_check_fixes.sql")
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "app")
            shutil.copytree(BAD, root)
            shutil.copy(fix, os.path.join(root, "supabase", "migrations"))
            res = rls_check.scan_project(root)
        db = sorted((f.rule, f.severity, f.target) for f in res["findings"] if not f.rule.startswith("KEY"))
        self.assertEqual(db, [("STOR001", "medium", "storage bucket avatars")])

    def test_grant_fix_example(self):
        res = rls_check.scan_project(os.path.join(KIT, "examples", "grant-fix"))
        got = sorted((f.rule, f.severity, f.target) for f in res["findings"])
        self.assertEqual(got, [("GRANT002", "high", "schema public"), ("RLS001", "critical", "table public.invoices")])

    def test_good_project_has_zero_findings(self):
        res = rls_check.scan_project(GOOD)
        self.assertEqual([(f.rule, f.target, f.title) for f in res["findings"]], [])
        self.assertEqual(res["scanned"]["tables"], 6)
        self.assertEqual(rls_check.exit_code(res, "low"), 0)

    def test_good_project_was_actually_parsed(self):
        schema = rls_check.Schema()
        mig = os.path.join(GOOD, "supabase", "migrations")
        for name in sorted(os.listdir(mig)):
            with open(os.path.join(mig, name), encoding="utf-8") as fh:
                schema.apply_file(fh.read(), name)
        members = schema.tables[("public", "team_members")]
        self.assertTrue(members.rls)
        self.assertIn("Members join via invite", members.policies)  # created inside a DO block
        self.assertEqual(sum(len(t.policies) for t in schema.tables.values()), 11)
        self.assertTrue(schema.functions[("public", "is_team_member")]["definer"])
        self.assertTrue(schema.views[("public", "payment_summary")]["invoker"])
        self.assertFalse(schema.buckets["user-documents"]["public"])


if __name__ == "__main__":
    unittest.main()
