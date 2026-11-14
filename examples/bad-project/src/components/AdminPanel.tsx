"use client";

import { createClient } from "@supabase/supabase-js";

// Intentionally wrong: service-role key used in a client component.
const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);

export function AdminPanel() {
  return <button onClick={() => admin.from("payments").select("*")}>Load payments</button>;
}
