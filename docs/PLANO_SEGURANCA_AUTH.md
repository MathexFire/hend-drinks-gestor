# Hend Drinks — Plano de migração de segurança

**Status:** preparação concluída; nenhuma alteração foi aplicada ao banco nesta etapa.

## Diagnóstico confirmado em 11/11/2026

- As cinco tabelas expostas em `public` estão com RLS desativado.
- Quatro tabelas possuem políticas chamadas “Acesso Livre …” com `USING (true)` e `WITH CHECK (true)`.
- Os papéis `anon` e `authenticated` possuem privilégios amplos de leitura e escrita nas tabelas.
- A função `public.rls_auto_enable()` é `SECURITY DEFINER` e tem EXECUTE concedido a `anon` e `authenticated`.
- Existem 3 perfis na tabela própria, todos ativos, mas existem **0 usuários em Supabase Auth**.
- O frontend atual não usa Supabase Auth: compara a senha no navegador com `perfis_usuarios.senha`, grava sessão em `localStorage` e consulta `select('*')`.
- O papel ADM é validado principalmente no JavaScript. Isso protege a interface, não a API.
- `vendas.vendedor_id` guarda o UUID do perfil antigo como texto. A migração preserva `perfis_usuarios.id` para manter o histórico.
- A chave publishable no HTML é própria para uso público; nenhuma chave service_role foi encontrada no frontend.

## Por que não ativar RLS agora

O aplicativo atual depende de acesso anônimo direto ao banco e não possui identidades em Supabase Auth. Ativar RLS sem trocar primeiro o login faria o sistema parar de carregar produtos, vendas, equipe e financeiro. Criar políticas permissivas para contornar isso manteria a vulnerabilidade.

## Arquivos preparados

- `supabase/00_preflight_auth_rls.sql`: consulta somente leitura para repetir a auditoria.
- `supabase/01_migracao_auth_rls.sql`: migração preparada com vínculo Auth, funções internas e políticas por perfil. Ela aborta se algum perfil ainda não estiver vinculado a uma conta Auth.
- `supabase/functions/admin-users/index.ts`: Edge Function preparada para convites, aprovação/bloqueio, redefinição de senha e exclusão de usuários; ainda não implantada nem integrada à interface.
- Este documento: sequência de implantação, validações e riscos.

**Não execute o SQL 01 antes da atualização do frontend.** Ele é a etapa de corte da API para acesso autenticado.

## Sequência obrigatória

### Etapa 1 — Backup e inventário

1. Gerar backup do banco antes de qualquer DDL.
2. Guardar uma cópia do `index.html` atualmente publicado.
3. Confirmar os 3 perfis atuais e suas permissões no painel.
4. Não exportar nem compartilhar senhas em texto puro.

### Etapa 2 — Criar identidades no Supabase Auth

1. No Supabase Dashboard, abrir Authentication → Users.
2. Convidar os usuários existentes pelos e-mails cadastrados.
3. Cada pessoa deve definir uma senha nova pelo convite recebido.
4. Confirmar que os 3 usuários aparecem em Auth → Users.
5. Não reutilizar nem copiar as senhas antigas em texto puro.

O perfil proprietário deve continuar com o mesmo `perfis_usuarios.id`, `cargo = 'ADM'` e `is_owner = true`. O vínculo novo será salvo em `auth_user_id`.

### Etapa 3 — Atualizar o frontend antes do corte

O frontend precisa:

- usar `supabase.auth.signInWithPassword()` e `supabase.auth.getSession()`;
- reagir a `onAuthStateChange` e encerrar a sessão com `signOut()`;
- solicitar cadastro com `auth.signUp()`; o perfil novo nasce como Vendedor/Pendente;
- recuperar senha por `resetPasswordForEmail()`;
- carregar o perfil com colunas explícitas, sem `select('*')`;
- remover a comparação de senhas, a sessão artesanal no `localStorage` e a promoção automática a ADM por e-mail;
- deixar o banco validar o cargo. Ocultar abas por cargo é apenas experiência visual;
- substituir `confirmarVendaBD()` por chamada a `db.rpc('registrar_venda', ...)`. A RPC valida o perfil autenticado, bloqueia o estoque com `FOR UPDATE`, valida quantidades e registra a venda + baixa de estoque atomicamente. O navegador não deve mais inserir em `vendas` nem atualizar `produtos.estoque` durante o checkout;
- enviar criação de usuários, convites, bloqueio, mudança de cargo, redefinição de senha e exclusão de conta para Edge Functions autenticadas;
- manter o UUID legado do perfil em `vendas.vendedor_id`.

A Edge Function administrativa deve validar o JWT do chamador, consultar o perfil no banco e confirmar `status = 'ativo'` e `cargo = 'ADM'` antes de usar a chave secreta do servidor. A chave secreta/service_role só pode existir nos secrets da Edge Function.

#### Etapa 3.1 — Preparar operações administrativas

1. Configurar `SUPABASE_SERVICE_ROLE_KEY` nos secrets da Edge Function (nunca no navegador).
2. Implantar `admin-users` somente depois de a migração criar a coluna `auth_user_id` e as funções auxiliares.
3. Integrar os botões de equipe à função e testar convite, aprovação, bloqueio, redefinição e exclusão.
4. Confirmar que a conta proprietária não pode ser removida e que sempre resta ao menos um ADM ativo.

## Etapa 4 — Aplicar RLS

Somente quando a nova versão estiver pronta e os 3 usuários estiverem no Supabase Auth:

1. Rodar novamente `00_preflight_auth_rls.sql`.
2. Confirmar que cada perfil corresponde a um usuário Auth pelo e-mail.
3. Executar `01_migracao_auth_rls.sql` no SQL Editor.
4. Se o script abortar, não remover o guard: corrigir o vínculo e repetir.
5. Rodar Security Advisors e os testes abaixo.

### Etapa 5 — Remover a senha antiga

A coluna `perfis_usuarios.senha` fica preservada durante a transição, mas o SQL de RLS não concede SELECT nela. Depois de confirmar que todos os clientes usam Supabase Auth e não fazem mais consultas `select('*')`, remover a coluna em uma migração separada. Não manter senhas em texto puro.

## Matriz de acesso proposta

| Recurso | Vendedor ativo | ADM ativo | Anônimo |
|---|---|---|---|
| Ler produtos | Sim | Sim | Não |
| Criar/editar/excluir produtos | Não | Sim | Não |
| Ler vendas | Apenas próprias | Todas | Não |
| Registrar venda | Própria identidade | Própria identidade | Não |
| Alterar/excluir vendas | Não | Sim | Não |
| Despesas extras | Não | Sim | Não |
| Ler próprio perfil | Sim | Sim | Não |
| Ler equipe | Não | Sim | Não |
| Solicitar exclusão da própria conta | Sim | Sim | Não |
| Analisar solicitações | Não | Sim | Não |

Operações de perfil administrativo serão executadas por Edge Functions, não por atualização direta do navegador. A RPC `registrar_venda` é parte obrigatória da migração para impedir venda sem baixa de estoque ou manipulação de vendedor/itens pelo cliente.

## Testes de aceite antes de liberar

- [ ] Anônimo não consegue ler nem escrever em nenhuma das cinco tabelas.
- [ ] Vendedor ativo consegue consultar produtos e registrar uma venda com seu próprio ID.
- [ ] Vendedor não consegue enviar venda usando o ID de outro vendedor.
- [ ] Vendedor só consegue consultar as próprias vendas.
- [ ] Vendedor não consegue editar produtos, despesas, perfis ou status.
- [ ] ADM ativo consegue consultar vendas de toda a equipe e administrar produtos/despesas.
- [ ] Perfil pendente/bloqueado não acessa os dados operacionais.
- [ ] Solicitação de exclusão fica visível ao solicitante e ao ADM, sem apagar vendas históricas.
- [ ] A função `rls_auto_enable()` deixa de ser executável por anon/authenticated.
- [ ] Security Advisors não apontam RLS desativado nem políticas abertas.

## Fora desta etapa

- Migrar imagens Data URL para Supabase Storage e apagar objetos no Storage ao excluir produto.
- Auditoria de eventos com histórico de quem fez cada alteração.
- Backup automatizado e procedimento de restauração testado.
- Revisão de rate limits, MFA do administrador e políticas de senha.
- Novos módulos mobile/loja online.

Esses itens serão feitos depois do corte seguro de autenticação e RLS.

## Referências oficiais

- [Supabase — Securing your API](https://supabase.com/docs/guides/api/securing-your-api)
- [Supabase — Row Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security)
- [Supabase — Auth user management](https://supabase.com/docs/guides/auth/managing-user-data)
- [Supabase — Integrating Auth with Edge Functions](https://supabase.com/docs/guides/functions/auth-legacy-jwt)
