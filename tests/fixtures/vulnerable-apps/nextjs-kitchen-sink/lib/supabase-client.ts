// AUTH-03 + STORAGE-02: Supabase anon-client query and a public bucket
// creation, with NO RLS policy migration anywhere in this repo.
import { createClient } from "@supabase/supabase-js";

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL ?? "",
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ?? "",
);

export async function listAllProfiles() {
  // AUTH-03: anon-client table query, no corresponding RLS policy file.
  const { data } = await supabase.from("profiles").select("*");
  return data;
}

export async function createPublicAvatarsBucket() {
  // STORAGE-02: public bucket, no storage policy evidence anywhere.
  await supabase.storage.createBucket("avatars", { public: true });
}
