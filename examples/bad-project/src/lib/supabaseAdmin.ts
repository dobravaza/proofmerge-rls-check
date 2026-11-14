import { createClient } from "@supabase/supabase-js";

// Intentionally wrong: a NEXT_PUBLIC_ variable is shipped to every browser.
export const supabaseAdmin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!
);
