-- Supabase migration — VULNERABLE. This is the CVE-2025-48757 pattern: tables
-- exposed via Supabase's auto REST API with RLS off (profiles) or an
-- authorize-everyone `using (true)` policy (documents). The rls gate must BLOCK.

create table public.profiles (
  id uuid primary key default gen_random_uuid(),
  email text,
  ssn text,
  created_at timestamptz default now()
);
-- ❌ VULN 3a — no `enable row level security`: Supabase exposes every row to the world.

create table public.documents (
  id uuid primary key default gen_random_uuid(),
  owner uuid references public.profiles(id),
  body text
);
alter table public.documents enable row level security;
-- ❌ VULN 3b — `using (true)` authorizes every caller: RLS on, but it leaks all rows.
create policy "all_documents" on public.documents
  for select using (true);
