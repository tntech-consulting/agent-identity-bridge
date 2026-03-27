import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-api-key",
};

function jsonResponse(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

async function hashKey(key: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function authenticate(req: Request) {
  const apiKey = req.headers.get("x-api-key");
  if (apiKey) {
    const keyHash = await hashKey(apiKey);
    const { data } = await supabaseAdmin.from("api_keys").select("org_id, organizations(slug, plan)").eq("key_hash", keyHash).eq("status", "active").single();
    if (data) { const org = (data as any).organizations; return { org_id: data.org_id, plan: org?.plan || "community" }; }
  }
  const authHeader = req.headers.get("authorization");
  if (authHeader?.startsWith("Bearer ")) {
    const token = authHeader.replace("Bearer ", "");
    const ANON = Deno.env.get("SUPABASE_ANON_KEY")!;
    const userClient = createClient(SUPABASE_URL, ANON, { global: { headers: { Authorization: `Bearer ${token}` } } });
    const { data: { user } } = await userClient.auth.getUser();
    if (user) {
      const { data: m } = await supabaseAdmin.from("org_members").select("org_id, organizations(slug, plan)").eq("user_id", user.id).limit(1).single();
      if (m) { const org = (m as any).organizations; return { org_id: m.org_id, plan: org?.plan || "community" }; }
    }
  }
  return null;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
  const auth = await authenticate(req);
  if (!auth) return jsonResponse({ error: "Unauthorized", code: "AIB-101" }, 401);

  const url = new URL(req.url);
  const status = url.searchParams.get("status") || undefined;
  const limit = Math.min(parseInt(url.searchParams.get("limit") || "50"), 200);
  const offset = parseInt(url.searchParams.get("offset") || "0");

  let query = supabaseAdmin.from("passports")
    .select("passport_id, display_name, issuer, capabilities, protocols, tier, status, version, issued_at, expires_at, revoked_at, created_at", { count: "exact" })
    .eq("org_id", auth.org_id)
    .order("created_at", { ascending: false })
    .range(offset, offset + limit - 1);

  if (status) query = query.eq("status", status);

  const { data: passports, count, error } = await query;
  if (error) return jsonResponse({ error: error.message, code: "AIB-501" }, 500);

  await supabaseAdmin.rpc("increment_usage", { p_org_id: auth.org_id, p_field: "transactions" });

  return jsonResponse({ count: count || 0, limit, offset, passports: passports || [] });
});
