-- HEND DRINKS | MIGRAÇÃO DE AUTENTICAÇÃO + RLS
-- ESTADO: PREPARADA, NÃO EXECUTAR AINDA.
--
-- PRÉ-REQUISITOS OBRIGATÓRIOS:
-- 1) Publicar primeiro a versão do frontend que usa Supabase Auth.
-- 2) Criar/CONVIDAR no Supabase Auth cada usuário legado existente.
-- 3) Confirmar que todos os perfis de public.perfis_usuarios estão ligados
--    a uma conta em auth.users com o mesmo e-mail.
-- 4) Atualizar as consultas do frontend para selecionar colunas explícitas.
--    A coluna senha NÃO deve mais ser consultada.
-- 5) Implementar as Edge Functions administrativas descritas no plano.
--
-- Esta migração aborta se encontrar qualquer perfil sem conta Auth correspondente.
-- Ela preserva perfis.id (usado no histórico de vendas) e não apaga vendas.
-- Execute somente após backup e revisão do plano docs/PLANO_SEGURANCA_AUTH.md.

begin;

-- 1. Vincular os perfis atuais às identidades oficiais do Supabase Auth.
alter table public.perfis_usuarios
  add column if not exists auth_user_id uuid;

update public.perfis_usuarios p
set auth_user_id = u.id
from auth.users u
where lower(p.email) = lower(u.email)
  and p.auth_user_id is null;

do $$
declare
  v_total bigint;
  v_sem_vinculo bigint;
begin
  select count(*) into v_total from public.perfis_usuarios;
  select count(*) into v_sem_vinculo
  from public.perfis_usuarios
  where auth_user_id is null;

  if v_total = 0 then
    raise exception 'Migração cancelada: nenhum perfil foi encontrado.';
  end if;

  if v_sem_vinculo > 0 then
    raise exception
      'Migração cancelada: % perfil(is) ainda sem conta Supabase Auth. Convide os usuários e tente novamente.',
      v_sem_vinculo;
  end if;
end;
$$;

create unique index if not exists perfis_usuarios_auth_user_id_uidx
  on public.perfis_usuarios (auth_user_id)
  where auth_user_id is not null;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'perfis_usuarios_auth_user_id_fkey'
      and conrelid = 'public.perfis_usuarios'::regclass
  ) then
    alter table public.perfis_usuarios
      add constraint perfis_usuarios_auth_user_id_fkey
      foreign key (auth_user_id)
      references auth.users(id)
      on delete set null;
  end if;
end;
$$;

-- 2. Funções internas usadas pelas políticas. Não recebem IDs enviados pelo cliente.
create schema if not exists private;
revoke all on schema private from public, anon;
grant usage on schema private to authenticated;

create or replace function private.current_profile_id()
returns uuid
language sql
stable
security definer
set search_path = ''
as $$
  select p.id
  from public.perfis_usuarios as p
  where p.auth_user_id = (select auth.uid())
    and p.status = 'ativo'
  limit 1;
$$;

create or replace function private.is_active_user()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.perfis_usuarios as p
    where p.auth_user_id = (select auth.uid())
      and p.status = 'ativo'
  );
$$;

create or replace function private.is_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.perfis_usuarios as p
    where p.auth_user_id = (select auth.uid())
      and p.status = 'ativo'
      and p.cargo = 'ADM'
  );
$$;

revoke all on function private.current_profile_id() from public, anon;
revoke all on function private.is_active_user() from public, anon;
revoke all on function private.is_admin() from public, anon;
grant execute on function private.current_profile_id() to authenticated;
grant execute on function private.is_active_user() to authenticated;
grant execute on function private.is_admin() to authenticated;

-- 3. Novos cadastros via Supabase Auth recebem perfil pendente.
-- Metadados enviados pelo navegador NUNCA definem cargo, status ou is_owner.
create or replace function private.sync_auth_profile()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_profile_id uuid;
  v_linked_auth_id uuid;
  v_nome text;
begin
  update public.perfis_usuarios
     set email = new.email
   where auth_user_id = new.id;

  if found then
    return new;
  end if;

  select p.id, p.auth_user_id
    into v_profile_id, v_linked_auth_id
  from public.perfis_usuarios as p
  where lower(p.email) = lower(new.email)
  limit 1;

  if found then
    if v_linked_auth_id is not null and v_linked_auth_id <> new.id then
      raise exception 'Este perfil já está vinculado a outra identidade Auth.';
    end if;

    update public.perfis_usuarios
       set auth_user_id = new.id,
           email = new.email
     where id = v_profile_id;
  else
    v_nome := coalesce(
      nullif(trim(new.raw_user_meta_data ->> 'nome'), ''),
      nullif(trim(new.raw_user_meta_data ->> 'full_name'), ''),
      split_part(new.email, '@', 1)
    );

    insert into public.perfis_usuarios
      (auth_user_id, nome, email, cargo, status, is_owner)
    values
      (new.id, v_nome, new.email, 'Vendedor', 'pendente', false);
  end if;

  return new;
end;
$$;

revoke all on function private.sync_auth_profile() from public, anon, authenticated;

drop trigger if exists on_auth_user_sync_hend_profile on auth.users;
create trigger on_auth_user_sync_hend_profile
after insert or update of email on auth.users
for each row execute function private.sync_auth_profile();

-- 3b. Venda transacional: valida identidade, preço/comissão do catálogo e estoque.
-- O navegador não recebe permissão para inserir vendas nem alterar estoque diretamente.
create or replace function public.registrar_venda(
  p_total numeric,
  p_forma_pagamento text,
  p_itens jsonb
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $
declare
  v_profile_id uuid;
  v_vendedor_nome text;
  v_venda_id uuid;
  v_item jsonb;
  v_produto public.produtos%rowtype;
  v_quantidade integer;
  v_itens_normalizados jsonb := '[]'::jsonb;
  v_comissao_total numeric := 0;
begin
  select p.id, p.nome
    into v_profile_id, v_vendedor_nome
  from public.perfis_usuarios p
  where p.auth_user_id = (select auth.uid())
    and p.status = 'ativo'
  limit 1;

  if v_profile_id is null then
    raise exception 'Usuário não autorizado ou perfil inativo.';
  end if;

  if p_total is null or p_total <= 0 then
    raise exception 'Total da venda inválido.';
  end if;

  if p_forma_pagamento is null or length(trim(p_forma_pagamento)) = 0 then
    raise exception 'Forma de pagamento obrigatória.';
  end if;

  if p_itens is null or jsonb_typeof(p_itens) <> 'array' or jsonb_array_length(p_itens) = 0 then
    raise exception 'A venda precisa conter ao menos um item.';
  end if;

  for v_item in select value from jsonb_array_elements(p_itens)
  loop
    if coalesce(v_item->>'produto_id','') = '' then
      raise exception 'Item sem produto_id.';
    end if;

    v_quantidade := (v_item->>'quantidade')::integer;
    if v_quantidade is null or v_quantidade <= 0 then
      raise exception 'Quantidade de item inválida.';
    end if;

    select *
      into v_produto
    from public.produtos
    where id = (v_item->>'produto_id')::uuid
    for update;

    if not found then
      raise exception 'Produto não encontrado.';
    end if;

    if v_produto.estoque < v_quantidade then
      raise exception 'Estoque insuficiente para o produto %.', v_produto.nome;
    end if;

    v_itens_normalizados := v_itens_normalizados || jsonb_build_array(
      jsonb_build_object(
        'produto_id', v_produto.id,
        'nome', v_produto.nome,
        'preco', v_produto.preco,
        'comissao', v_produto.comissao,
        'quantidade', v_quantidade
      )
    );

    v_comissao_total := v_comissao_total + (v_produto.comissao * v_quantidade);

    update public.produtos
      set estoque = estoque - v_quantidade
    where id = v_produto.id;
  end loop;

  insert into public.vendas (
    vendedor_id, vendedor_nome, total, comissao_total, forma_pagamento, itens
  )
  values (
    v_profile_id::text,
    v_vendedor_nome,
    p_total,
    v_comissao_total,
    trim(p_forma_pagamento),
    v_itens_normalizados
  )
  returning id into v_venda_id;

  return v_venda_id;
end;
$;

revoke all on function public.registrar_venda(numeric, text, jsonb) from public, anon;
grant execute on function public.registrar_venda(numeric, text, jsonb) to authenticated;

-- 4. Remover as políticas antigas de acesso irrestrito.
drop policy if exists "Acesso Livre Usuarios" on public.perfis_usuarios;
drop policy if exists "Acesso Livre Produtos" on public.produtos;
drop policy if exists "Acesso Livre Vendas" on public.vendas;
drop policy if exists "Acesso Livre Despesas" on public.despesas_extras;

-- 5. RLS passa a ser obrigatório nas cinco tabelas.
alter table public.perfis_usuarios enable row level security;
alter table public.produtos enable row level security;
alter table public.vendas enable row level security;
alter table public.despesas_extras enable row level security;
alter table public.solicitacoes_exclusao enable row level security;

-- 6. Remover grants amplos e conceder somente o necessário.
revoke all privileges on table
  public.perfis_usuarios,
  public.produtos,
  public.vendas,
  public.despesas_extras,
  public.solicitacoes_exclusao
from anon, authenticated;

-- O perfil não expõe senha nem auth_user_id ao navegador.
grant select (id, nome, email, cargo, status, created_at, is_owner)
  on public.perfis_usuarios to authenticated;

grant select, insert, update, delete on public.produtos to authenticated;
grant select, update, delete on public.vendas to authenticated;
grant select, insert, update, delete on public.despesas_extras to authenticated;
grant select, insert, update on public.solicitacoes_exclusao to authenticated;

-- 7. Políticas: perfil próprio/admin; produtos compartilhados; vendas por vendedor;
-- despesas somente ADM; solicitação de exclusão própria e análise por ADM.

drop policy if exists perfis_select_proprio_ou_admin on public.perfis_usuarios;
create policy perfis_select_proprio_ou_admin
on public.perfis_usuarios
for select
to authenticated
using (
  auth_user_id = (select auth.uid())
  or (select private.is_admin())
);

drop policy if exists produtos_select_usuario_ativo on public.produtos;
create policy produtos_select_usuario_ativo
on public.produtos
for select
to authenticated
using ((select private.is_active_user()));

drop policy if exists produtos_insert_admin on public.produtos;
create policy produtos_insert_admin
on public.produtos
for insert
to authenticated
with check ((select private.is_admin()));

drop policy if exists produtos_update_admin on public.produtos;
create policy produtos_update_admin
on public.produtos
for update
to authenticated
using ((select private.is_admin()))
with check ((select private.is_admin()));

drop policy if exists produtos_delete_admin on public.produtos;
create policy produtos_delete_admin
on public.produtos
for delete
to authenticated
using ((select private.is_admin()));

drop policy if exists vendas_select_proprias_ou_admin on public.vendas;
create policy vendas_select_proprias_ou_admin
on public.vendas
for select
to authenticated
using (
  (select private.is_active_user())
  and (
    (select private.is_admin())
    or vendedor_id = (select private.current_profile_id())::text
  )
);

-- A inserção de vendas será feita exclusivamente pela RPC transacional
-- public.registrar_venda(), que valida o usuário e baixa estoque atomicamente.
drop policy if exists vendas_insert_propria on public.vendas;

drop policy if exists vendas_update_admin on public.vendas;
create policy vendas_update_admin
on public.vendas
for update
to authenticated
using ((select private.is_admin()))
with check ((select private.is_admin()));

drop policy if exists vendas_delete_admin on public.vendas;
create policy vendas_delete_admin
on public.vendas
for delete
to authenticated
using ((select private.is_admin()));

drop policy if exists despesas_admin_all on public.despesas_extras;
create policy despesas_admin_all
on public.despesas_extras
for all
to authenticated
using ((select private.is_admin()))
with check ((select private.is_admin()));

drop policy if exists solicitacoes_select_propria_ou_admin on public.solicitacoes_exclusao;
create policy solicitacoes_select_propria_ou_admin
on public.solicitacoes_exclusao
for select
to authenticated
using (
  user_id = (select private.current_profile_id())
  or (select private.is_admin())
);

drop policy if exists solicitacoes_insert_propria on public.solicitacoes_exclusao;
create policy solicitacoes_insert_propria
on public.solicitacoes_exclusao
for insert
to authenticated
with check (
  user_id = (select private.current_profile_id())
);

drop policy if exists solicitacoes_update_admin on public.solicitacoes_exclusao;
create policy solicitacoes_update_admin
on public.solicitacoes_exclusao
for update
to authenticated
using ((select private.is_admin()))
with check ((select private.is_admin()));

-- 8. A função antiga não deve ser chamada diretamente pela API.
revoke execute on function public.rls_auto_enable() from public, anon, authenticated;

-- A inserção de vendas e a baixa de estoque acontecem na mesma transação RPC.
-- Não conceder INSERT em vendas nem UPDATE em produtos aos clientes autenticados.
revoke insert on public.vendas from anon, authenticated;
-- UPDATE em produtos continua concedido a authenticated, mas a policy
-- produtos_update_admin impede vendedores de alterar estoque ou cadastro.


commit;

-- IMPORTANTE:
-- A coluna public.perfis_usuarios.senha foi intencionalmente preservada nesta etapa
-- para permitir uma janela de transição e rollback. Depois que a nova versão estiver
-- ativa em todos os dispositivos, confirme que nenhuma consulta a utiliza e remova-a
-- em uma migração separada. O frontend novo deve selecionar somente colunas explícitas.
--
-- As operações administrativas de criação/convite de usuário, alteração de cargo,
-- bloqueio, redefinição de senha e exclusão de conta devem passar por Edge Functions
-- que validem o JWT e o cargo ADM no banco. Nunca coloque service_role no HTML.
