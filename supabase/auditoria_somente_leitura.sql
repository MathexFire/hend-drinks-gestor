-- HEND DRINKS — AUDITORIA SOMENTE LEITURA
-- Este arquivo NÃO altera tabelas, dados, políticas ou permissões.
-- Não habilite RLS isoladamente: o sistema atual usa login próprio e ainda
-- não possui Supabase Auth. Ativar RLS sem políticas compatíveis pode bloquear
-- o aplicativo. Faça a migração de autenticação e revise as políticas antes.

-- 1) Tabelas públicas e estado do RLS
select
  n.nspname as schema_name,
  c.relname as table_name,
  c.relrowsecurity as rls_enabled,
  c.relforcerowsecurity as rls_forced
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public'
  and c.relkind in ('r', 'p')
order by c.relname;

-- 2) Políticas atualmente configuradas
select
  schemaname,
  tablename,
  policyname,
  permissive,
  roles,
  cmd,
  qual,
  with_check
from pg_policies
where schemaname = 'public'
order by tablename, policyname;

-- 3) Funções SECURITY DEFINER expostas no schema public
select
  n.nspname as schema_name,
  p.proname as function_name,
  pg_get_userbyid(p.proowner) as function_owner,
  p.prosecdef as security_definer,
  pg_get_function_identity_arguments(p.oid) as arguments
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
where n.nspname = 'public'
  and p.prosecdef = true
order by p.proname;

-- 4) Resumo do estoque atual (custo de aquisição × quantidade)
select
  count(*) as produtos_cadastrados,
  coalesce(sum(estoque), 0) as unidades_em_estoque,
  round(coalesce(sum(greatest(custo, 0) * greatest(estoque, 0)), 0), 2)
    as valor_atual_do_estoque
from public.produtos;

-- 5) Resumo das vendas
select
  count(*) as quantidade_vendas,
  round(coalesce(sum(total), 0), 2) as faturamento_registrado,
  min(created_at) as primeira_venda,
  max(created_at) as venda_mais_recente
from public.vendas;