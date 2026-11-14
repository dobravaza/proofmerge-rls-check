create table public.invoices (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id),
  amount_cents integer not null,
  pdf_path text
);
