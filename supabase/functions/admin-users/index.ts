// HEND DRINKS — operações administrativas de usuários
// Deploy somente após aplicar a migração Auth/RLS e atualizar o frontend.
// SUPABASE_SERVICE_ROLE_KEY deve existir apenas nos secrets da Edge Function.

import { createClient } from "npm:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Método não permitido." }, 405);

  const url = Deno.env.get("SUPABASE_URL");
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !anonKey || !serviceKey) {
    return json({ error: "Secrets do Supabase não configurados." }, 500);
  }

  const authorization = req.headers.get("Authorization") || "";
  const token = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
  if (!token) return json({ error: "Autenticação obrigatória." }, 401);

  const caller = createClient(url, anonKey, {
    global: { headers: { Authorization: `Bearer ${token}` } },
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const admin = createClient(url, serviceKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  const { data: authData, error: authError } = await caller.auth.getUser(token);
  if (authError || !authData.user) return json({ error: "Sessão inválida." }, 401);

  const { data: actor, error: actorError } = await admin
    .from("perfis_usuarios")
    .select("id,cargo,status,is_owner")
    .eq("auth_user_id", authData.user.id)
    .maybeSingle();

  if (actorError || !actor || actor.status !== "ativo" || actor.cargo !== "ADM") {
    return json({ error: "Somente um ADM ativo pode executar esta operação." }, 403);
  }

  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return json({ error: "JSON inválido." }, 400);
  }

  const action = String(body.action || "");
  const profileId = String(body.profile_id || "");

  try {
    if (action === "invite") {
      const email = String(body.email || "").trim().toLowerCase();
      const nome = String(body.nome || "").trim();
      const cargo = String(body.cargo || "Vendedor");
      if (!email || !nome || !email.includes("@")) return json({ error: "Nome e e-mail válidos são obrigatórios." }, 400);
      if (!["Vendedor", "ADM"].includes(cargo)) return json({ error: "Cargo inválido." }, 400);

      const { data, error } = await admin.auth.admin.inviteUserByEmail(email, {
        data: { nome },
      });
      if (error) return json({ error: error.message }, 400);

      // O trigger sync_auth_profile cria ou vincula o perfil. Cargo e status
      // são definidos aqui no servidor, nunca por metadata controlada pelo cliente.
      const { data: profile, error: profileError } = await admin
        .from("perfis_usuarios")
        .update({ nome, cargo, status: "ativo" })
        .ilike("email", email)
        .select("id,nome,email,cargo,status")
        .maybeSingle();
      if (profileError || !profile) {
        return json({ error: "Conta Auth criada, mas não foi possível atualizar o perfil. Revise o perfil no painel." }, 500);
      }
      return json({ user_id: data.user?.id, profile });
    }

    if (action === "update_profile" || action === "reset_password" || action === "delete_user") {
      if (!profileId) return json({ error: "profile_id obrigatório." }, 400);
      const { data: target, error: targetError } = await admin
        .from("perfis_usuarios")
        .select("id,auth_user_id,email,cargo,status,is_owner")
        .eq("id", profileId)
        .maybeSingle();
      if (targetError || !target) return json({ error: "Perfil não encontrado." }, 404);
      if (target.is_owner) return json({ error: "A conta proprietária não pode ser alterada por este fluxo." }, 403);

      if (action === "update_profile") {
        const cargo = body.cargo === undefined ? target.cargo : String(body.cargo);
        const status = body.status === undefined ? target.status : String(body.status);
        if (!["ADM", "Vendedor"].includes(cargo)) return json({ error: "Cargo inválido." }, 400);
        if (!["ativo", "pendente", "bloqueado"].includes(status)) return json({ error: "Status inválido." }, 400);

        if (target.cargo === "ADM" && target.status === "ativo" && (cargo !== "ADM" || status !== "ativo")) {
          const { count, error } = await admin
            .from("perfis_usuarios")
            .select("id", { count: "exact", head: true })
            .eq("cargo", "ADM")
            .eq("status", "ativo");
          if (error) return json({ error: "Não foi possível validar os administradores ativos." }, 500);
          if ((count || 0) <= 1) return json({ error: "Não é permitido remover ou bloquear o último ADM ativo." }, 409);
        }

        const { data, error } = await admin
          .from("perfis_usuarios")
          .update({ cargo, status })
          .eq("id", profileId)
          .select("id,nome,email,cargo,status,is_owner")
          .single();
        if (error) return json({ error: error.message }, 400);
        return json({ profile: data });
      }

      if (action === "reset_password") {
        const password = String(body.password || "");
        if (!target.auth_user_id) return json({ error: "Perfil ainda não está vinculado ao Supabase Auth." }, 409);
        if (password.length < 12) return json({ error: "A nova senha deve ter pelo menos 12 caracteres." }, 400);
        const { error } = await admin.auth.admin.updateUserById(target.auth_user_id, { password });
        if (error) return json({ error: error.message }, 400);
        return json({ success: true });
      }

      if (action === "delete_user") {
        if (target.auth_user_id) {
          const { error } = await admin.auth.admin.deleteUser(target.auth_user_id);
          if (error) return json({ error: error.message }, 400);
        }
        const { error } = await admin.from("perfis_usuarios").delete().eq("id", profileId);
        if (error) return json({ error: "Conta Auth removida; o perfil não foi removido. Revise o cadastro no painel." }, 500);
        return json({ success: true });
      }
    }

    return json({ error: "Ação desconhecida." }, 400);
  } catch (error) {
    console.error("admin-users failure", error);
    return json({ error: "Falha interna ao processar a operação." }, 500);
  }
});
