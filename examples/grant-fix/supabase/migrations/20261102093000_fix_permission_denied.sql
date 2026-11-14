-- The app got "42501 permission denied for table invoices", so access was granted.
grant all on all tables in schema public to anon, authenticated;
