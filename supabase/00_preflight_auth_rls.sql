-- HEND DRINKS | PRÉ-VALIDAÇÃO DE SEGURANÇA
-- Somente leitura. Pode ser executado antes da migração.
-- Não retorna e-mails, senhas, imagens nem dados pessoais.

select
  c.relname as tabela,
  c.relrowsecurity as rls_ativo,
  c.relforcerowsecurity as force_rls
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public'
  and c.relkind = 'r'
  and c.relname in (
    'perfis_usuarios',
    'produtos',
    'vendas',
    'despesas_extras',
    'solicitacoes_exclusao'
  )
order by c.relname;

select
  tablename,
  policyname,
  roles,
  cmd,
  coalesce(qual, '') as using_expression,
  coalesce(with_check, '') as check_expression
from pg_policies
where schemaname = 'public'
order by tablename, policyname;

select
  (select count(*) from public.perfis_usuarios) as perfis_existentes,
  (select count(*) from public.perfis_usuarios where status = 'ativo') as perfis_ativos,
  (select count(*) from public.perfis_usuarios where status = 'pendente') as perfis_pendentes,
  (select count(*) from public.perfis_usuarios where status = 'bloqueado') as perfis_bloqueados,
  (select count(*) from auth.users) as contas_supabase_auth;

select
  p.proname as funcao,
  p.prosecdef as security_definer,
  has_function_privilege('anon', p.oid, 'EXECUTE') as anon_pode_executar,
  has_function_privilege('authenticated', p.oid, 'EXECUTE') as autenticado_pode_executar
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
where n.nspname = 'public'
  and p.proname = 'rls_auto_enable';

select
  grantee,
  table_name,
  privilege_type
from information_schema.role_table_grants
where table_schema = 'public'
  and grantee in ('anon', 'authenticated')
  and table_name in (
    'perfis_usuarios',
    'produtos',
    'vendas',
    'despesas_extras',
    'solicitacoes_exclusao'
  )
order by table_name, grantee, privilege_type;
