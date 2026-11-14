import "server-only";
import { createClient } from "@supabase/supabase-js";

// Server-only admin client. Never import this from a client component.
export function createAdminClient() {
  return createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);
}
