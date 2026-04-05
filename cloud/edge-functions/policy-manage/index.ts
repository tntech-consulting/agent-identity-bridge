import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-api-key",
};

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: CORS });

  const supabase = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
  );

  // Auth via API key
  const apiKey = req.headers.get("x-api-key");
  if (!apiKey) {
    return new Response(JSON.stringify({ error: "Unauthorized", code: "AIB-101" }), {
      status: 401, headers: { ...CORS, "Content-Type": "application/json" }
    });
  }

  // Hasher la clé et chercher l'org
  const keyHash = await crypto.subtle.digest(
    "SHA-256", new TextEncoder().encode(apiKey)
  );
  const hashHex = Array.from(new Uint8Array(keyHash)).map(b => b.toString(16).padStart(2, "0")).join("");

  const { data: keyData } = await supabase
    .from("api_keys")
    .select("org_id")
    .eq("key_hash", hashHex)
    .single();

  if (!keyData) {
    return new Response(JSON.stringify({ error: "Unauthorized", code: "AIB-101" }), {
      status: 401, headers: { ...CORS, "Content-Type": "application/json" }
    });
  }
  const orgId = keyData.org_id;

  const url = new URL(req.url);
  const method = req.method;
  let body: Record<string, unknown> = {};
  if (method === "POST") {
    try { body = await req.json(); } catch { /* empty body */ }
  }

  const action = (body.action as string) || (method === "GET" ? "list" : "create");

  // ── LIST ──
  if (action === "list") {
    // Filtre optionnel par passport_id
    const passportId = url.searchParams.get("passport_id") || (body.passport_id as string);
    let query = supabase
      .from("policy_rules")
      .select("rule_id,rule_type,config,severity,active,hits,passport_id,created_at")
      .eq("org_id", orgId)
      .eq("active", true)
      .order("created_at", { ascending: false });

    if (passportId) {
      // Rules de ce passport spécifique + rules globales de l'org
      query = query.or(`passport_id.eq.${passportId},passport_id.is.null`);
    }

    const { data, error } = await query;
    if (error) return new Response(JSON.stringify({ error: error.message }), {
      status: 500, headers: { ...CORS, "Content-Type": "application/json" }
    });

    return new Response(JSON.stringify({ rules: data, count: data?.length ?? 0 }), {
      headers: { ...CORS, "Content-Type": "application/json" }
    });
  }

  // ── CREATE ──
  if (action === "create") {
    const { rule_type, config, severity = "block", description = "", passport_id } = body as {
      rule_type: string; config: Record<string, unknown>;
      severity?: string; description?: string; passport_id?: string;
    };

    if (!rule_type || !config) {
      return new Response(JSON.stringify({ error: "rule_type and config required", code: "AIB-400" }), {
        status: 400, headers: { ...CORS, "Content-Type": "application/json" }
      });
    }

    const VALID_TYPES = [
      "deliverable_gate", "capability_required", "separation_of_duties",
      "protocol_restrict", "domain_block", "domain_allow", "tier_restrict",
      "time_restrict", "action_block", "rate_limit", "attestation_required", "capability_limit"
    ];
    if (!VALID_TYPES.includes(rule_type)) {
      return new Response(JSON.stringify({ error: `Invalid rule_type: ${rule_type}`, code: "AIB-400" }), {
        status: 400, headers: { ...CORS, "Content-Type": "application/json" }
      });
    }

    // Si passport_id fourni, vérifier qu'il appartient à cette org
    if (passport_id) {
      const { data: pData } = await supabase
        .from("passports")
        .select("passport_id, status")
        .eq("passport_id", passport_id)
        .eq("org_id", orgId)
        .single();

      if (!pData) {
        return new Response(JSON.stringify({ error: "Passport not found or not in your org", code: "AIB-404" }), {
          status: 404, headers: { ...CORS, "Content-Type": "application/json" }
        });
      }
      if (pData.status !== "active") {
        return new Response(JSON.stringify({ error: "Passport is not active", code: "AIB-409" }), {
          status: 409, headers: { ...CORS, "Content-Type": "application/json" }
        });
      }
    }

    const ruleId = `rule_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
    const row: Record<string, unknown> = {
      org_id: orgId,
      rule_id: ruleId,
      rule_type,
      config,
      severity,
      description,
      active: true,
    };
    if (passport_id) row.passport_id = passport_id;

    const { data: created, error } = await supabase
      .from("policy_rules")
      .insert(row)
      .select("rule_id, rule_type, config, severity, passport_id, active, created_at")
      .single();

    if (error) return new Response(JSON.stringify({ error: error.message }), {
      status: 500, headers: { ...CORS, "Content-Type": "application/json" }
    });

    return new Response(JSON.stringify({
      ...created,
      scope: passport_id ? `passport:${passport_id}` : "org-global",
      portable: !!passport_id,
    }), {
      status: 201, headers: { ...CORS, "Content-Type": "application/json" }
    });
  }

  // ── DELETE ──
  if (action === "delete") {
    const ruleId = body.rule_id as string;
    if (!ruleId) return new Response(JSON.stringify({ error: "rule_id required" }), {
      status: 400, headers: { ...CORS, "Content-Type": "application/json" }
    });

    const { error } = await supabase
      .from("policy_rules")
      .delete()
      .eq("rule_id", ruleId)
      .eq("org_id", orgId);

    if (error) return new Response(JSON.stringify({ error: error.message }), {
      status: 500, headers: { ...CORS, "Content-Type": "application/json" }
    });

    return new Response(JSON.stringify({ deleted: ruleId }), {
      headers: { ...CORS, "Content-Type": "application/json" }
    });
  }

  return new Response(JSON.stringify({ error: "Unknown action", code: "AIB-400" }), {
    status: 400, headers: { ...CORS, "Content-Type": "application/json" }
  });
});
