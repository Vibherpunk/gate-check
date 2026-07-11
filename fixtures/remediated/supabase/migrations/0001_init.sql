-- Supabase migration — REMEDIATED. RLS enabled on every table with a
-- caller-scoped policy (no `using (true)`).

create table public.profiles (
  id uuid primary key default gen_random_uuid(),
  email text,
  ssn text,
  created_at timestamptz default now()
);
-- ✅ FIX 3a — RLS enabled; each caller sees only their own row.
alter table public.profiles enable row level security;
create policy "own_profile" on public.profiles
  for select using (auth.uid() = id);

create table public.documents (
  id uuid primary key default gen_random_uuid(),
  owner uuid references public.profiles(id),
  body text
);
alter table public.documents enable row level security;
-- ✅ FIX 3b — policy scoped to the owner, not everyone.
create policy "own_documents" on public.documents
  for select using (auth.uid() = owner);
