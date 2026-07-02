-- Phase 5 clean fixture: RLS policy evidence satisfying AUTH-03 + STORAGE-02.
alter table profiles enable row level security;

create policy "Users can view own profile"
  on profiles for select
  using (auth.uid() = id);

create policy "Users can manage own avatar objects"
  on storage.objects for all
  using (bucket_id = 'avatars' and auth.uid()::text = (storage.foldername(name))[1]);
