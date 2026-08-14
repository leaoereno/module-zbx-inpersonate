# module-zbx-inpersonate

Módulo de **impersonação (login as)** para Zabbix 7.0 LTS.

Um Super Admin escolhe um usuário, clica em *Impersonar* e passa a navegar o Zabbix inteiro
como aquele usuário — dashboards, permissões de host group, filtros salvos, tudo real. Um item
fixo no topo do menu lateral encerra a impersonação e devolve a sessão original.

Autor: **Rafael M. A. Leão Ereno - MALE**

---

## Como funciona por dentro

Não há truque nem SQL artesanal na tabela `sessions`. O módulo usa exatamente o mesmo caminho
que o Zabbix usa para autenticar via SSO/SAML sem senha (`ui/index_sso.php`):

```php
$wrapper = API::getWrapper();
API::setWrapper();                                    // desliga o wrapper de API

CWebUser::$data = CUser::loginByUsername($username, true);   // cria a sessão, sem senha

API::setWrapper($wrapper);

CSessionHelper::set('sessionid', CWebUser::$data['sessionid']);
API::getWrapper()->auth = ['type' => CJsonRpc::AUTH_TYPE_FRONTEND, 'auth' => ...];
```

`CUser::loginByUsername()` é `public static` e faz o trabalho pesado: valida grupo desabilitado,
role inválida, GUI access, cria a linha em `sessions` com `ZBX_SESSION_ACTIVE` e **grava o
`ACTION_LOGIN_SUCCESS` no audit log nativo do Zabbix** em nome do alvo.

O estado da impersonação (alvo, expiração, modo, `logid`) fica em `$_SESSION`. O cookie
`zbx_session` inteiro é assinado por HMAC pelo `CEncryptedCookieSession`, então o payload não é
falsificável pelo cliente — e o módulo ainda assina o próprio bloco com `CEncryptHelper::sign()`
por redundância.

**O sessionid do Super Admin não vai para o cookie.** O cookie é assinado, mas não cifrado: um
token de sessão privilegiada em texto claro no navegador seria um alvo desnecessário (XSS,
extensão maliciosa, cópia de perfil). Ele é gravado na coluna `origin_sessionid` de
`module_impersonate_log` e recuperado por `logid` na hora de voltar — e zerado assim que a
impersonação termina. Além disso, o estado só é aceito se `target_userid` bater com o usuário
autenticado da request; se a sessão impersonada morrer no meio do caminho, o estado é invalidado
em vez de continuar mostrando um banner mentiroso.

Consequência: **sem a tabela de auditoria gravável não há impersonação.** Se o usuário do banco
não tiver `CREATE`/`ALTER`, o módulo recusa com mensagem explícita em vez de rodar sem rastro.

Referências verificadas contra o código-fonte oficial da branch `release/7.0`:
`ui/index_sso.php`, `ui/include/classes/api/services/CUser.php`,
`ui/include/classes/core/CEncryptedCookieSession.php`, `ui/include/classes/core/ZBase.php`,
`ui/include/classes/core/CModule.php`.

---

## Travas de segurança

| Trava | Como funciona | Config |
|---|---|---|
| Só Super Admin inicia | `checkPermissions()` via `$this->getUserType()` (nunca SQL contra `users.type`, que não existe) | — |
| Alvo Super Admin bloqueado | Tipo do alvo lido de `users.roleid → role.type` | `block_super_admin_target` |
| Expiração automática | `Module::init()` roda a cada request; passou do prazo, restaura sozinho e avisa | `session_ttl` (segundos) |
| Somente leitura | `Module::onBeforeAction()` recusa actions de escrita | `readonly` |
| Log de auditoria | Tabela `module_impersonate_log` + audit log nativo do Zabbix | — |
| Alvo precisa enxergar o módulo | Sem isso o guard e o botão de sair não existiriam durante a impersonação | `require_module_access` |
| `guest` nunca é alvo | — | — |
| Anti-CSRF no start | Exige `POST` + header `X-Requested-With: XMLHttpRequest` (header custom não atravessa origem sem preflight CORS) | — |

Configuração fica no bloco `config` do `manifest.json`:

```json
"config": {
    "session_ttl": 1800,
    "readonly": 1,
    "block_super_admin_target": 1,
    "require_module_access": 1
}
```

Depois de editar o manifest: **Administration → Modules → Scan directory** para o Zabbix reler.

### Como o modo somente-leitura decide o que bloquear

Duas regras, nesta ordem:

**1. Lista explícita** — nomes sem verbo reconhecível e páginas legadas que escrevem:

```
popup.scriptexec, popup.acknowledge.create, jsrpc.php, popup.php
```

**2. Qualquer segmento** do nome da action batendo em:

```
create, update, delete, massupdate, massdelete, massadd, enable, disable,
execute, execute_now, import, rename, copy, clear, reset, unlink,
activate, deactivate, provision, unprovision, acknowledge, save, scriptexec
```

É **qualquer segmento**, não só o último — de propósito. `popup.massupdate.host` termina em
`host`; olhar só o sufixo deixaria passar justamente as ações de escrita em massa. Pela mesma
razão as páginas legadas têm tratamento próprio: `CLegacyAction::getAction()` devolve
`jsrpc.php`, e o último segmento aí é sempre `php`.

Passam livres: `*.view`, `*.list`, `*.edit`, `*.get`, `*.check`, `chart*.php`, `image.php`.
Para ampliar a lista sem tocar no código, acrescente `readonly_extra_suffixes` ao `config` do
manifest:

```json
"readonly_extra_suffixes": ["rank", "push"]
```

Ao bloquear, o módulo lança uma exceção que o `ZBase` transforma em tela de erro (ou em
`{"error":{"title":...}}` para actions de layout JSON), com o motivo explícito.

---

## Limitações — leia antes de habilitar em produção

1. **`api_jsonrpc.php` não passa pelo guard.** O `EXEC_MODE_API` do `ZBase` nem carrega o module
   manager, então o modo somente-leitura **não** vale para chamadas diretas à API feitas com o
   token de sessão da impersonação. O modo somente-leitura é uma trava de UI, não uma fronteira
   de segurança criptográfica.
2. **A ação fica no nome do alvo.** Se o modo escrita estiver ligado e algo for alterado durante
   a impersonação, o audit log do Zabbix registra o **usuário alvo** como autor. A correlação com
   quem realmente agiu está em `module_impersonate_log` (mesma janela de tempo). Mantenha
   `readonly: 1` a menos que tenha um motivo forte.
3. **Uma impersonação por vez, por sessão.** Iniciar outra sem encerrar a atual é recusado.
4. **Se a sessão original expirar durante a impersonação**, não há para onde voltar: o módulo
   limpa o estado, fecha o evento no log e manda para a tela de login. Por isso o `session_ttl`
   deve ser menor que o `autologout` do Super Admin.
5. **Atrás de load balancer (F5)**, instale em **todos** os frontends. O LB pode servir código
   antigo de um nó não atualizado de forma intermitente.
6. **Todo JavaScript é inline**, sem `.js` estático — o F5 BIG-IP bloqueia assets `.js` do módulo.
7. **Ao recusar uma ação de escrita, o módulo lança exceção de dentro de `onBeforeAction()`.**
   O `CModuleManager::publishEvent()` percorre todos os módulos em sequência, então os módulos
   que viriam depois deste não recebem `onBeforeAction`, e o `onTerminate` não é publicado para
   ninguém naquela request. Se você tiver outro módulo fazendo bookkeeping nesses hooks, ele
   perde a request bloqueada. Só acontece quando uma ação é recusada.
8. **`zbx.impersonate.stop` aceita GET sem token** — é um link de menu. Uma página externa
   consegue *encerrar* a impersonação de um Super Admin com um `<img src=...>`. O impacto é
   reduzir privilégio, nunca aumentar, então foi mantido assim em troca da confiabilidade de um
   link simples que sempre funciona.
9. **Auditoria obrigatória.** Sem `module_impersonate_log` gravável, a impersonação é recusada —
   o log é também onde o sessionid de origem fica guardado.

---

## Instalação

### Via git (recomendado)

```bash
cd /usr/share/zabbix/modules
git clone https://github.com/leaoereno/module-zbx-inpersonate.git
cd module-zbx-inpersonate
./install.sh
```

> `git pull` rodado como root deixa os arquivos com dono `root` e o PHP-FPM (que roda como
> `apache`) perde acesso. Rode `./install.sh` — ou pelo menos `chown -R apache:apache .` —
> depois de **qualquer** pull manual como root.
>
> Se der *"detected dubious ownership"*, resolva uma vez por servidor:
> `git config --global --add safe.directory /usr/share/zabbix/modules/module-zbx-inpersonate`

### Via cópia

```bash
tar xzf module-zbx-inpersonate.tar.gz -C /tmp
cd /tmp/module-zbx-inpersonate
./install.sh
```

### Habilitar

1. **Administration → General → Modules → Scan directory**
2. Habilitar **Impersonate**
3. O item **Users → Impersonate** aparece só para Super Admin

A tabela `module_impersonate_log` é criada sozinha, de forma idempotente, na primeira vez que
alguma action precisa dela. Não existe hook `onEnable()` no core do Zabbix — provisionamento em
módulo é sempre assim.

---

## Uso

1. **Users → Impersonate**
2. *Perfil* abre um modal read-only com role, regras de UI, grupos, permissões efetivas em host
   groups, medias, sessões ativas e histórico de impersonação — sem trocar de sessão.
3. *Impersonar* pede confirmação e troca a sessão.
4. Durante a impersonação: aviso amarelo em toda página + **Sair da impersonação (usuário)** no
   topo do menu lateral.
5. **Users → Impersonate log** mostra a auditoria completa.

Alvos bloqueados aparecem na lista com o motivo em vez do botão — *Super Admin (bloqueado por
política)*, *GUI access desabilitado*, *Role sem acesso ao módulo Impersonate*, etc.

### Liberando o módulo nas roles

Se as roles do ambiente têm "Access to modules" configurado explicitamente, o módulo novo entra
como **negado** e praticamente todo mundo aparece bloqueado. Um alerta no topo da lista mostra
quais roles precisam do toggle e oferece um botão que resolve tudo de uma vez.

O botão chama `role.update` passando **apenas** `rules.modules`. Isso é seguro por construção:
`CRole::updateRules()` faz `$role['rules'] + $old_rules` — união de arrays com precedência à
esquerda — alimentado por um `get` interno com as 15 chaves de `selectRules`. As chaves que você
não envia vêm do banco intactas, e módulos não citados no array mantêm o status atual pelo
`elseif` de `compileModulesRules()`. Nem `ui`, nem `api`, nem `actions` são tocados.

Reenviar o objeto `rules` inteiro seria **pior**: exporia a validação de `api`, que é mais
estrita que a gravação e recusa métodos herdados de versões antigas que o `compile` apenas
ignoraria.

Roles com `readonly = 1` (a *Super admin role* de fábrica) são puladas — `CRole::checkReadonly()`
recusa qualquer update nelas, e usuários Super Admin já são bloqueados como alvo de qualquer
forma.

**Liberar o módulo não dá poder nenhum ao usuário comum.** Todas as telas (`list`, `profile`,
`start`, `log`) exigem Super Admin em `checkPermissions()`, o item de menu só é adicionado para
Super Admin, e `stop` só faz algo com um estado de impersonação assinado e válido. O acesso
existe unicamente para que o `CModuleManager` carregue o `Module.php` durante a impersonação —
sem isso o guard de somente-leitura, o banner e o botão de sair simplesmente não existiriam.

---

## Estrutura

```
module-zbx-inpersonate/
├── manifest.json                     # id, namespace, actions (class + layout + view), config
├── Module.php                        # init(): expiração, banner, menu · onBeforeAction(): guard
├── actions/
│   ├── ImpersonateList.php           # zbx.impersonate.list      layout.htmlpage
│   ├── ImpersonateProfile.php        # zbx.impersonate.profile   layout.json
│   ├── ImpersonateStart.php          # zbx.impersonate.start     layout.json
│   ├── ImpersonateStop.php           # zbx.impersonate.stop      layout.htmlpage (redirect)
│   ├── ImpersonateLog.php            # zbx.impersonate.log       layout.htmlpage
│   └── ImpersonateGrant.php          # zbx.impersonate.grant     layout.json
├── helper/
│   └── ImpersonateHelper.php         # troca de sessão, políticas, auditoria, schema
├── views/
│   ├── zbx.impersonate.list.php
│   ├── zbx.impersonate.profile.php   # echo json_encode(...)
│   ├── zbx.impersonate.start.php     # echo json_encode(...)
│   ├── zbx.impersonate.stop.php      # fallback quando a sessão original morreu
│   ├── zbx.impersonate.log.php
│   └── zbx.impersonate.grant.php     # echo json_encode(...)
├── sql/role_rule.sql                 # diagnóstico (só SELECTs) + desinstalação
├── install.sh
└── README.md
```

> O autoloader do Zabbix (`CAutoloader::loadClass`) faz `strtolower()` em cada segmento de
> namespace ao montar o caminho — por isso `Modules\ZbxImpersonate\Actions\X` mora em
> `actions/X.php` e `Modules\ZbxImpersonate\Helper\Y` em `helper/Y.php`, tudo minúsculo.

---

## Esquema da tabela de auditoria

```sql
CREATE TABLE module_impersonate_log (
    logid            BIGINT UNSIGNED NOT NULL,
    actor_userid     BIGINT UNSIGNED NOT NULL,
    actor_username   VARCHAR(100)    NOT NULL DEFAULT '',
    target_userid    BIGINT UNSIGNED NOT NULL,
    target_username  VARCHAR(100)    NOT NULL DEFAULT '',
    origin_sessionid VARCHAR(32)     NOT NULL DEFAULT '',
    clientip         VARCHAR(45)     NOT NULL DEFAULT '',
    user_agent       VARCHAR(255)    NOT NULL DEFAULT '',
    readonly         INT             NOT NULL DEFAULT 1,
    started          INT             NOT NULL DEFAULT 0,
    ended            INT             NOT NULL DEFAULT 0,
    end_reason       VARCHAR(32)     NOT NULL DEFAULT '',
    PRIMARY KEY (logid),
    KEY idx_imp_started (started),
    KEY idx_imp_actor   (actor_userid),
    KEY idx_imp_target  (target_userid)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

`end_reason`: `manual` · `expired` · `invalid` · vazio enquanto a sessão está aberta.
`origin_sessionid` só tem valor enquanto a impersonação está aberta; é zerado no encerramento.

`logid` usa `MAX(logid)+1` dentro de `\DBstart()`/`\DBend()` — é tabela própria do módulo, não
passa pela tabela `ids` do Zabbix, e a transação evita que duas impersonações simultâneas gerem
o mesmo id (o que faria o encerramento de um Super Admin fechar o evento do outro).

DDL específico de MySQL/MariaDB. Em frontend sobre PostgreSQL o `CREATE TABLE` falha e o módulo
recusa impersonar com mensagem explícita — adapte o DDL em `ImpersonateHelper::ensureSchema()`.

Consultas úteis estão em `sql/role_rule.sql` (só `SELECT`s — o arquivo não altera permissão
nenhuma).

---

## Troubleshooting

**Página abre em branco (header/menu/rodapé normais, conteúdo vazio) e nada no log**
Falta a chave `"view"` em alguma action do `manifest.json`. Não é erro de PHP: o
`ZBase::processResponseFinal()` pula a renderização de propósito quando `$router->getView()` é
`null`. Confira o manifest antes de qualquer outra coisa.

**Erro 500 sem stack trace**
O pool do PHP-FPM está engolindo o `Fatal error`:

```bash
systemctl list-units --type=service | grep -i php     # nome real do unit
echo "catch_workers_output = yes" >> /etc/php-fpm.d/zabbix.conf
systemctl restart php-fpm
: > /var/log/php-fpm/error.log
tail -n 0 -f /var/log/php-fpm/error.log               # reproduza o erro no navegador
```

**"Acesso negado" para quem deveria ter permissão**
`\DBselect()`/`\DBexecute()` nunca lançam exceção — falham em silêncio retornando `false`. O
sintoma clássico é `checkPermissions()` consultando coluna inexistente. Este módulo usa
`$this->getUserType()` em todo lugar justamente por isso. Se ainda assim acontecer, rode o
diagnóstico em `sql/role_rule.sql` (bloco 2) e confira se a role enxerga o módulo.

**"Role sem acesso ao módulo Impersonate" na lista de usuários**
A role do alvo não tem o módulo liberado — típico em ambientes onde as roles foram configuradas
com "Access to modules" explícito antes deste módulo existir, então ele entra como negado.

Use o botão **Liberar o módulo em todas as roles** que aparece no alerta vermelho no topo da
lista (ver seção abaixo), ou faça manualmente em **Users → User roles → \<role\> → Access to
modules**.

Não insira `role_rule` na mão: o Zabbix aloca `role_ruleid` pela tabela `ids`
(`DB::reserveIds`), e um `INSERT` com `MAX(role_ruleid)+1` deixa o contador defasado — a próxima
edição de role pela UI quebra com chave primária duplicada.

**"Não foi possível criar/acessar a tabela de auditoria"**
O usuário de banco em `zabbix.conf.php` não tem `CREATE`/`ALTER`. Crie a tabela manualmente com
o DDL desta página e dê `INSERT`/`UPDATE`/`SELECT` nela ao usuário do frontend.

**Não consigo sair da impersonação**
Fallbacks, em ordem: (1) item **Sair da impersonação** no topo do menu; (2) URL direta
`zabbix.php?action=zbx.impersonate.stop`; (3) esperar o `session_ttl` expirar; (4) logout normal
e login de novo com a conta de Super Admin.

**O menu aparece como uma seção solta no fim da sidebar, em vez de dentro de Usuários**
`CMenu::find()` compara pelo **rótulo visível**, e o `CMenuHelper` monta a seção nativa com
`_('Users')` — que num frontend em pt-BR é "Usuários". Procurar pela string crua `'Users'` não
casa, e o `findOrAdd()` acaba criando uma seção nova. Corrigido em 1.0.1 usando `_('Users')`,
com fallback para os rótulos conhecidos.

**Erro de sintaxe SQL no `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`**
`ADD COLUMN IF NOT EXISTS` é extensão do MariaDB e não existe no MySQL. Como `\DBexecute()`
dispara `trigger_error()`, o erro vira banner vermelho no topo da tela. Corrigido em 1.0.1
consultando `information_schema.COLUMNS` antes de alterar.

**Alterações no código não refletem**
OPcache. `systemctl restart php-fpm` — em **todos** os frontends atrás do F5.

---

## Desinstalação

1. Administration → General → Modules → desabilitar **Impersonate**
2. `rm -rf /usr/share/zabbix/modules/module-zbx-inpersonate` (em cada frontend)
3. Limpeza opcional do banco (bloco 4 de `sql/role_rule.sql`):

```sql
DROP TABLE IF EXISTS module_impersonate_log;
```

O módulo não cria nenhuma linha em `role_rule` — não há o que limpar lá.

---

## Ambiente alvo

Zabbix 7.0 LTS · PHP 8.x · MariaDB 10.11 · frontends atrás de F5 BIG-IP ·
módulos em `/usr/share/zabbix/modules/`
