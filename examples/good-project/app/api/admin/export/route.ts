import { createAdminClient } from "@/lib/supabase/server";

export async function GET() {
  const admin = createAdminClient();
  const { count } = await admin.from("payments").select("*", { count: "exact", head: true });
  return Response.json({ payments: count });
}
