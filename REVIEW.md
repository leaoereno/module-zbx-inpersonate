# Revisão — módulo Impersonate (v1.1.1)

Revisão da tela (dashboard "Correios" com impersonação ativa) + código do repositório.

> **Status: implementado na v1.2.0.** Itens 1–8, 12–17 foram corrigidos; ver o Changelog no
> README. Ficaram de fora, por serem mudanças de produto e não correções:
>
> - **item 9** (notificação por e-mail ao usuário impersonado) — a justificativa obrigatória
>   (`require_reason`) foi implementada, o e-mail não;
> - **item 11**, parte do `revoke` — o dry-run com lista nominal das roles entrou; revogar acesso
>   ao módulo continua sendo pela UI do Zabbix;
> - **item 14** (ícone SVG no manifest);
> - **item 17** (trocar o anti-CSRF próprio pelo `_csrf_token` nativo) — o esquema atual
>   (POST + `X-Requested-With`) é sólido contra CSRF cross-origin; a troca é uma melhoria de
>   alinhamento com o core, não uma vulnerabilidade em aberto.
>
> **Correção da própria revisão:** o item 6 sugeria `DB::reserveIds()`. Não serve — ele chama
> `DB::getSchema($table)` e a tabela do módulo não existe em `include/schema.inc.php`, então a
> chamada lançaria `DBException`. A colisão de `logid` foi resolvida com retry na chave primária.

---

## P0 — Bug visível no screenshot

### 1. O banner é replicado dentro de CADA widget do dashboard

Na tela aparece a mesma mensagem **4 vezes**: no topo da página, dentro do widget
*Problems*, dentro do *Cluster - UP TIME* e nos demais. E os textos divergem
("Expira em 30m 00s" no topo, "29m 57s" nos widgets) — prova de que cada widget é
uma request separada.

**Causa:** `Module::init()` chama `CMessageHelper::addWarning()` em **toda** request.
Widgets de dashboard são requests próprias (`widget.problems.view`,
`widget.svggraph.view`, …) com `layout.json`, e o layout serializa as mensagens do
`CMessageHelper` na resposta — o widget então renderiza a mensagem como caixa de erro.
A cada refresh do dashboard (30s) elas voltam, mesmo depois de fechadas no "×".

`ImpersonateHelper::isNonHtmlRequest()` não pega esse caso porque o `fetch()` dos
widgets não manda `X-Requested-With` e o `Content-Type` é form-urlencoded.

**Correção:** só emitir o banner em carregamento de página HTML completa.

```php
// helper/ImpersonateHelper.php
/**
 * A request atual e um carregamento de PAGINA (e nao widget/popup/AJAX/imagem)?
 *
 * Widgets de dashboard sao requests proprias com layout.json, e o layout serializa
 * as mensagens do CMessageHelper na resposta - sem este filtro o banner de
 * impersonacao aparece dentro de cada widget da tela.
 */
public static function isPageRequest(): bool {
    if (self::isNonHtmlRequest()) {
        return false;
    }

    $action = strtolower((string) ($_REQUEST['action'] ?? ''));

    if ($action === '') {
        return true;
    }

    foreach (['widget.', 'popup.', 'dashboard.widget.'] as $prefix) {
        if (strncmp($action, $prefix, strlen($prefix)) === 0) {
            return false;
        }
    }

    return substr($action, -8) !== '.refresh' && substr($action, -5) !== '.get';
}
```

```php
// Module.php, dentro de handleActiveImpersonation()
if (self::isPageRequestOk()) {           // <- ImpersonateHelper::isPageRequest()
    \CMessageHelper::addWarning(sprintf(...));
}

// o item de menu continua fora do if - ele deve existir em toda request
```

**Melhor ainda:** trocar a mensagem descartável por uma **barra fixa** injetada por
CSS/JS inline, com contagem regressiva viva. Hoje o Super Admin pode fechar o aviso
no "×" e esquecer que está impersonando — o único lembrete que sobra é o item de menu.

```php
// no init(), quando isPageRequest() e a impersonacao esta ativa
\CMessageHelper::addWarning(...);   // mantem por acessibilidade/leitores de tela

// e uma barra fixa via inline JS (nada de .js estatico - F5 BIG-IP bloqueia)
// injetada por uma view leve chamada no layout, ou por um <script> no menu item title
```

### 2. `readonly_extra_suffixes` é opção morta

`Module.php:64` lê `$this->getOption('readonly_extra_suffixes', [])`, mas a chave
**não existe** no `config` do `manifest.json`. `getOption()` lê exatamente o bloco
`config` do manifest, então essa extensibilidade nunca funciona — sempre cai no
default `[]`.

```json
"config": {
    "session_ttl": 1800,
    "readonly": 1,
    "block_super_admin_target": 1,
    "require_module_access": 1,
    "readonly_extra_suffixes": []
}
```

---

## P1 — Segurança e robustez

### 3. `origin_sessionid` fica em texto claro no banco

`module_impersonate_log.origin_sessionid` guarda um **token de sessão Super Admin
válido** enquanto a impersonação está ativa. Quem tiver `SELECT` no banco (DBA,
backup, um SQLi em qualquer outro lugar do frontend) sequestra a sessão privilegiada.

O comentário em `getState()` explica corretamente por que ele não vai no cookie —
mas o banco não é um lugar melhor. Sugestão: cifrar em repouso com
`openssl_encrypt()` usando chave derivada de `$ZBX_SESSION_KEY` (o mesmo segredo que
`CEncryptHelper` usa), e manter o `logEnd()` limpando o campo (isso já está certo).

Alternativa mais simples e igualmente segura: **não guardar o token**. Em vez de
restaurar a sessão antiga, ao dar `stop()` chamar `CUser::loginByUsername()` no
usuário de origem, gerando sessão nova. Perde-se o "voltar para a mesma sessão", mas
elimina o segredo em repouso.

### 4. Logout nativo não encerra a impersonação

Se o usuário clicar em **"Sign out"** (que continua visível no rodapé da sidebar, como
se vê na tela) em vez de "Sair da impersonacao":

- `stop()` nunca roda;
- a linha do log fica com `ended=0` **para sempre** (contador de "abertas" do log só cresce);
- a sessão do Super Admin de origem continua viva e órfã até o GC do Zabbix;
- o `origin_sessionid` em claro fica no banco indefinidamente.

Tratar no `onBeforeAction()`:

```php
if ($action_name === 'userprofile.logout') {   // confira o nome exato na sua 7.0
    ImpersonateHelper::stop(ImpersonateHelper::END_MANUAL);
    // deixa o logout seguir - agora sobre a sessao correta
    return;
}
```

### 5. O guard de somente-leitura é blacklist — e blacklist vaza

`WRITE_SUFFIXES` é uma boa heurística, mas faltam verbos reais do 7.0: `send`
(`popup.mediatypetest.send`, `item.test.send`), `massenable`, `massdisable`,
`massclear`, `massunlink`, `mute`, `unmute`, `pause`, `resume`, `sync`, `restore`,
`apply`. E a cada minor do Zabbix a lista envelhece silenciosamente — o modo
"somente leitura" passa a permitir escrita sem ninguém perceber.

Para um módulo cuja proposta é *trava* de somente-leitura, o correto é **default-deny**:
permitir só o que é comprovadamente leitura e negar o resto.

```php
/** Segmentos que caracterizam LEITURA. Tudo que nao casar e negado. */
public const READ_SUFFIXES = [
    'view', 'list', 'edit', 'get', 'check', 'popup', 'php', 'menu',
    'search', 'export', 'print', 'widget', 'refresh', 'sort', 'filter'
];

public static function isWriteAction(string $action, array $extra_read = []): bool {
    // ... lista explicita de escrita primeiro (mantem WRITE_ACTIONS)
    // ... depois: se NENHUM segmento estiver em READ_SUFFIXES -> considera escrita
}
```

Manter a blacklist atual como modo `readonly_mode: "blacklist"` no manifest, para quem
precisar de compatibilidade, e default `"whitelist"`.

Observação secundária: `throw new \Exception($deny_message)` em `onBeforeAction()`
vira tela de erro genérica. Em request `layout.json` vira `{"error":{...}}` — ok — mas
num widget vira caixa vermelha com o texto inteiro de 3 linhas. Encurtar a mensagem
exibida e mandar o detalhe para `error_log()`.

### 6. `logid` por `MAX(logid)+1` pode colidir

`logStart()` faz `SELECT MAX(logid) ... FOR UPDATE` dentro de `DBstart()`. `FOR UPDATE`
sobre um agregado não trava a *gap* — dois Super Admins iniciando ao mesmo tempo podem
obter o mesmo `logid`, e `logEnd()` de um fecharia o evento do outro. Ironia: o próprio
`sql/role_rule.sql` documenta que o jeito certo é `DB::reserveIds`.

```php
$logid = \DB::reserveIds(self::LOG_TABLE, 1);   // usa a tabela `ids`, igual ao core
```

### 7. Só funciona em MySQL/MariaDB

Três pontos amarram o módulo ao MySQL, e o Zabbix 7.0 roda muito em PostgreSQL/Timescale:

| Local | Problema |
|---|---|
| `ensureSchema()` | `BIGINT UNSIGNED`, `ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`, `KEY idx_...` inline |
| `ensureSchema()` | `information_schema.COLUMNS ... TABLE_SCHEMA=DATABASE()` |
| `sql/role_rule.sql` | `SHOW TABLES LIKE`, `FROM_UNIXTIME`, `UNIX_TIMESTAMP`, `INTERVAL 30 DAY` |

Ramificar por `$DB['TYPE']` (`ZBX_DB_MYSQL` / `ZBX_DB_POSTGRESQL`) ou, no mínimo,
declarar no README que o suporte é MySQL-only e falhar com mensagem clara em PG.

---

## P2 — UX e qualidade

### 8. `:root` sobrescrito globalmente + tema escuro quebrado

As três views declaram `:root { --c-bg:#f4f6f9; ... }`. Isso vaza para o documento
inteiro e pode colidir com variáveis CSS do próprio Zabbix. Além disso as cores são
fixas em claro — no tema *Dark* do Zabbix a tela do módulo fica com cartões brancos.

```css
/* em vez de :root */
.im-scope {
    --c-bg:#f4f6f9; --c-card:#fff; /* ... */
}
/* e suporte a tema escuro */
[theme="dark"] .im-scope, .dark-theme .im-scope {
    --c-bg:#0e1013; --c-card:#16181c; --c-text:#e3e5e8; /* ... */
}
```

### 9. ~200 linhas de CSS duplicadas em 3 views

`zbx.impersonate.list.php`, `.log.php` e `.stop.php` repetem o mesmo bloco de
variáveis, `.btn`, `.card`, `.badge`. Já divergiram entre si. Como `.css` estático está
fora de questão (F5 BIG-IP), centralizar num helper que devolve a string:

```php
// helper/ImpersonateAssets.php
public static function css(): string { return '<style> ... </style>'; }
```
e nas views: `<?= \Modules\ZbxImpersonate\Helper\ImpersonateAssets::css() ?>`.

### 10. Falta justificativa obrigatória no start (auditoria)

O módulo se vende como auditável, mas o log responde *quem/quando/de onde* e não
**por quê**. Em ambiente com auditoria formal (e "Correios"/"finep.gov.br" sugerem
exatamente isso), o campo motivo é o que salva na hora da pergunta.

- coluna `reason VARCHAR(255)` no log;
- input obrigatório no `confirm()` do start (trocar o `window.confirm` por um modal —
  o `confirm` nativo não aceita texto);
- opção `require_reason: 1` no manifest.

Complemento: opção `notify_target` mandando e-mail via relay SMTP para o usuário
impersonado ("sua conta foi acessada por X às Y para Z"). Várias políticas exigem isso.

### 11. "Liberar em todas as roles" é tudo-ou-nada e sem volta

`grantModuleAccessToAllRoles()` altera **toda** role não-readonly de uma vez. Não há
seleção nem `revoke`. O comentário de segurança sobre `CRole::updateRules()` está
correto e bem pesquisado, mas o botão devia:

- listar as roles afetadas **antes** (dry-run) com checkbox por role;
- ter um "Revogar" simétrico;
- registrar a alteração no log do módulo (hoje só aparece no audit log nativo).

### 12. Strings da UI sem acentuação

"impersonacao", "sessao", "somente leitura", "Usuario", "Nao", "Permissao". O banco é
utf8mb4, o PHP declara UTF-8 e as views escapam com `htmlspecialchars(..., 'UTF-8')` —
não há razão técnica para o texto sem acento, e ele aparece direto na tela do usuário
final (o banner é a coisa mais visível do módulo). Comentários de código podem
continuar sem acento; strings de UI não.

Se a ideia é publicar no GitHub, vale ainda passar as strings por `_()` e ter o
inglês como default.

### 13. Detalhes do menu

- `->setIcon('zi-user')` → `zi-sign-out` comunica melhor a ação.
- O rótulo `Sair da impersonacao (fcsilva@finep.gov.br)` estoura a largura da sidebar
  com username longo. Truncar em ~18 chars e jogar o nome completo no `setTitle()`.
- Ao lado do "Sign out" nativo, dois itens de saída confundem — ver item 4.

### 14. `"icon": ""` no manifest

Administration → Modules mostra placeholder genérico. Um SVG inline de 1KB resolve.

### 15. Wildcards de LIKE não escapados

`ImpersonateList::doAction()` e `ImpersonateHelper::getLog()` interpolam a busca com
`zbx_dbstr('%'.$search.'%')`. Injeção está coberta, mas `%` ou `_` digitados pelo
usuário viram wildcard — buscar `_` retorna tudo.

```php
$term = str_replace(['\\', '%', '_'], ['\\\\', '\%', '\_'], $search);
$like = \zbx_dbstr('%'.$term.'%');
```

### 16. `catch (\Throwable)` totalmente silencioso

Os três `catch` de `Module.php` (e o de `roleHasModuleAccess()`, que **retorna `true`**
em caso de falha — fail-open numa checagem de segurança) engolem tudo. Debugar em
produção fica impossível.

```php
catch (\Throwable $e) {
    if ((int) $this->getOption('debug', 0) === 1) {
        error_log('[zbx-impersonate] '.$e->getMessage());
    }
}
```

O fail-open de `roleHasModuleAccess()` merece atenção própria: se a API falhar, o
módulo assume que a role tem acesso e a impersonação prossegue — justamente o cenário
em que o guard de somente-leitura pode não carregar. Fail-closed com mensagem clara é
mais coerente com o resto do módulo.

### 17. CSRF: preferir o nativo

`ImpersonateStart` e `ImpersonateGrant` fazem `disableCsrfValidation()` e trocam por
POST + `X-Requested-With`. O raciocínio está certo (header custom não atravessa origem
sem preflight), mas para uma ação que **assume a sessão de outro usuário** vale usar o
`_csrf_token` nativo do Zabbix por cima — custa um campo hidden na view e alinha com o
core.

---

## Não é bug: os erros dos widgets na tela

- `Cluster - UP TIME` → *"No permissions to referred object or it does not exist!"*
- `Graph (classic)` → *"Invalid parameter 'Item': cannot be empty."*

Isso é **exatamente o que a impersonação deveria mostrar**: o usuário `fcsilva` não tem
permissão nos itens/hosts referenciados pelos widgets, então o Zabbix resolve o campo
como vazio e reclama. Vale um parágrafo no README para ninguém abrir issue disso — e é
argumento de venda do módulo (foi assim que se descobriu que aquele dashboard está
quebrado para o usuário).

---

## Sugestão de ordem

1. Item 1 (banner nos widgets) — é o que incomoda hoje, correção pequena.
2. Item 2 (opção morta no manifest) — uma linha.
3. Item 4 (logout nativo) — vaza sessão e log aberto.
4. Item 6 (`DB::reserveIds`) — troca de uma chamada.
5. Item 5 (default-deny no readonly) — mais trabalhoso, mas é o coração do módulo.
6. Item 3 (token em claro no banco) — decidir entre cifrar ou não guardar.
7. O resto conforme conveniência (12, 8 e 9 dão o maior ganho de percepção por hora gasta).
