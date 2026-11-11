# Edge Functions do Hend Drinks

## admin-users

Função preparada para executar operações de equipe no servidor, com verificação de JWT e cargo ADM ativo no banco.

### Secrets necessários

Configure no projeto Supabase:

- `SUPABASE_URL`
- `SUPABASE_ANON_KEY`
- `SUPABASE_SERVICE_ROLE_KEY` — somente nos secrets da função; nunca no HTML, GitHub Pages ou aplicativo.

### Ações

Todas as chamadas devem ser POST autenticado com JSON:

- `invite`: `{ "action":"invite", "email":"...", "nome":"...", "cargo":"Vendedor" }`
- `update_profile`: `{ "action":"update_profile", "profile_id":"UUID", "cargo":"Vendedor|ADM", "status":"ativo|pendente|bloqueado" }`
- `reset_password`: `{ "action":"reset_password", "profile_id":"UUID", "password":"..." }`
- `delete_user`: `{ "action":"delete_user", "profile_id":"UUID" }`

### Regras

- Valida token com Supabase Auth.
- Confirma no banco que o chamador é ADM ativo.
- Não aceita mudança de proprietário.
- Impede bloquear/remover o último ADM ativo.
- Não confia em cargo ou status enviados em metadata pelo navegador.
- A exclusão preserva as vendas antigas (o ID do perfil é texto em vendas.vendedor_id).

### Deploy

Depois de atualizar o frontend e aplicar a migração:

```bash
supabase functions deploy admin-users
```

A função ainda precisa ser integrada aos botões de equipe no frontend antes de entrar em produção.
