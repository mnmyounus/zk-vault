// lib/supabase-browser.ts
// Public, browser-safe Supabase client. Uses the anon/publishable key only
// — this key is designed to be exposed in the bundle; it carries no
// special privilege on its own. It exists solely so the browser can call
// uploadToSignedUrl(), which Supabase Storage's SDK requires for direct
// browser uploads. The actual one-time permission for each upload comes
// from the signed token minted server-side in lib/server.ts using the
// service-role key — not from this client's own access level.

import { createClient } from '@supabase/supabase-js';

export const supabasePublic = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
);
