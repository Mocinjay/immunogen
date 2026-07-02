// AUTH-03 + STORAGE-02 must NOT fire: a policy migration exists under
// supabase/migrations/ (see 0001_policies.sql), so the absence-evidence
// check finds corroborating evidence and stays clean.
//
// BUNDLE-01 must NOT fire: this anon credential is named *_PUBLISHABLE (not
// *_ANON_KEY) to match clientExposureDetector's PUBLISHABLE exclusion —
// Supabase's anon key, like Stripe's publishable key, is safe-by-design to
// expose to the client.
import { createClient } from "@supabase/supabase-js";

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL ?? "",
  process.env.NEXT_PUBLIC_SUPABASE_ANON_PUBLISHABLE ?? "",
);

export async function listOwnProfile(userId: string) {
  const { data } = await supabase.from("profiles").select("*").eq("id", userId);
  return data;
}

export async function createPrivateAvatarsBucket() {
  await supabase.storage.createBucket("avatars", { public: false });
}
