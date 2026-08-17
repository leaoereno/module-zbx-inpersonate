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
| Token de origem cifrado em repouso | `origin_sessionid` é gravado com AES-256-CBC, chave derivada do segredo de sessão do frontend. Enquanto a impersonação está ativa esse valor é uma sessão Super Admin **válida** | `encrypt_origin_sessionid` |
| Logout nativo encerra a impersonação | "Sign out" continua na sidebar; se usado, o evento é fechado no log e a sessão Super Admin de origem é apagada | `stop_on_logout` |
| Eventos órfãos são fechados | Impersonação sem encerramento (browser fechado, frontend reiniciado) retém o token — a tela de listagem fecha as antigas | `stale_after` |
| Justificativa obrigatória | Exige um motivo digitado, gravado em `module_impersonate_log.reason` | `require_reason` |

Configuração fica no bloco `config` do `manifest.json`:

```json
"config": {
    "session_ttl": 1800,
    "readonly": 1,
    "readonly_mode": "blacklist",
    "readonly_extra_suffixes": [],
    "block_super_admin_target": 1,
    "require_module_access": 1,
    "banner": 1,
    "menu_exit_item": 1,
    "stop_on_logout": 1,
    "encrypt_origin_sessionid": 1,
    "require_reason": 0,
    "stale_after": 86400,
    "debug": 0,
    "debug_file": ""
}
```

| Opção | Default | O que faz |
|---|---|---|
| `session_ttl` | `1800` | Expiração da impersonação, em segundos. `0` = nunca |
| `readonly` | `1` | Recusa actions de escrita durante a impersonação |
| `readonly_mode` | `blacklist` | `blacklist` = bloqueia verbos conhecidos de escrita. `whitelist` = default-deny |
| `readonly_extra_suffixes` | `[]` | Verbos extras tratados como escrita, sem tocar no código |
| `block_super_admin_target` | `1` | Impede impersonar outro Super Admin (User e Admin seguem liberados) |
| `require_module_access` | `1` | Só impersona alvo cuja role enxerga este módulo |
| `banner` | `1` | Aviso amarelo no topo da página. `0` deixa a tela **pixel a pixel** igual à do usuário |
| `menu_exit_item` | `1` | Item "Sair da impersonação" no topo da sidebar |
| `stop_on_logout` | `1` | Fecha a impersonação quando o usuário usa o "Sign out" nativo |
| `encrypt_origin_sessionid` | `1` | Cifra o token da sessão de origem no banco |
| `require_reason` | `0` | Exige justificativa antes de iniciar |
| `stale_after` | `86400` | Segundos até um evento aberto ser fechado como `stale` |
| `debug` | `0` | Registra o motivo real de cada falha interna, mais um trap de erro fatal |
| `debug_file` | `""` | Arquivo próprio de diagnóstico. Vazio = usa o `error_log()` do PHP |

### Depurando (`debug`)

Com `debug: 1` o módulo registra o motivo real de cada falha que os `catch (\Throwable)`
engolem, e arma um `register_shutdown_function()` que captura **erros fatais** — esgotamento de
memória, `Maximum execution time exceeded`, `Error` não capturado. Nenhum `try/catch` alcança
esses, e sem o trap o sintoma é um 500 pelado.

Prefira `debug_file` a depender do `error_log` do PHP:

```json
"debug": 1,
"debug_file": "/var/log/php-fpm/zbx-impersonate.log"
```

```bash
touch /var/log/php-fpm/zbx-impersonate.log
chown apache:apache /var/log/php-fpm/zbx-impersonate.log
```

O motivo é concreto: num pool de PHP-FPM **sem `error_log` definido**, o PHP manda os erros para
o stderr e o FPM **descarta tudo** quando `catch_workers_output` está off — que é o default. Nesse
cenário `error_log()` não vai a lugar nenhum e o módulo fica cego justamente na hora do problema.
Com `debug_file` ele grava onde você mandou, sem depender da configuração do PHP.

Cada linha traz data, **hostname** e PID. O hostname importa: atrás do F5 são vários frontends, e
saber qual respondeu é metade do diagnóstico.

Desligue quando terminar — o arquivo cresce sem rotação.

### Ajustes por frontend: `config.local.json`

O `manifest.json` é versionado. Editar nele para ligar `debug` ou desligar o `banner` num nó
específico faz **todo `git pull` conflitar**. Use um `config.local.json` ao lado dele — ignorado
pelo git, sobrepõe o manifest chave a chave, e vale só naquele frontend:

```bash
cd /usr/share/zabbix/modules/module-zbx-inpersonate
cp config.local.json.example config.local.json
vim config.local.json
chown apache:apache config.local.json
```

```json
{
    "debug": 1,
    "debug_file": "/usr/share/zabbix/modules/module-zbx-inpersonate/debug.log"
}
```

Só as chaves que mudam; o resto continua vindo do manifest. Quando está em uso, a tela de
listagem mostra um badge **config.local.json ativo** — sem isso, "editei e não mudou nada" vira
caça ao fantasma.

Editou qualquer um dos dois, vale na hora — **não precisa de Scan directory nem de
desabilitar/reabilitar** (Scan directory continua necessário quando uma versão nova traz *actions*
novas).

> Isso é deliberado, e vai contra o comportamento nativo. O Zabbix **não relê o `config` do
> `manifest.json` a cada request**: a tabela `module` tem uma coluna `config` preenchida quando o
> módulo é *registrado*, e a partir daí `CModule::getOption()` responde a partir do **banco**.
> Editar o manifest depois disso não muda nada — e chaves novas, adicionadas numa versão
> posterior, simplesmente não existem para o `getOption()`, que devolve o default em silêncio.
> Num frontend que já tinha o módulo registrado desde a 1.1.x, **todas** as opções novas da 1.2.0
> ficariam inertes até desregistrar e reescanear o módulo.
>
> Por isso o módulo lê as próprias opções direto do `manifest.json` em disco
> (`ImpersonateHelper::option()`), com cache por request. Editou o manifest naquele frontend, vale
> naquele frontend — que é o que faz sentido num deploy por git com um checkout por nó.

### Fidelidade da visão (troubleshooting)

A sessão passa a ser **integralmente** a do alvo — `lang`, `theme`, `timezone`, `refresh`,
`rows_per_page`, permissões e `role_rule`. A tela renderizada é a que o usuário vê, incluindo os
erros dele:

```
Cluster - UP TIME    → No permissions to referred object or it does not exist!
Graph (classic)      → Invalid parameter "Item": cannot be empty.
```

Isso **não é defeito do módulo**: são widgets referenciando itens/hosts que o alvo não tem
permissão de ler, e normalmente é exatamente o achado que se procurava.

O módulo interfere na tela em dois pontos, ambos desligáveis:

- o **banner** de aviso no topo (`banner: 0`);
- o **item de menu** de saída na sidebar (`menu_exit_item: 0`).

Desligar os dois dá uma tela 100% idêntica — mas então a única saída é `session_ttl` expirar ou
acessar `zabbix.php?action=zbx.impersonate.stop` na mão. Recomendado: manter
`menu_exit_item: 1` e usar `banner: 0` quando o layout precisar ser exato.

> O banner é emitido **somente em carregamento de página completa**. Cada widget de dashboard é
> uma request própria que passa pelo `init()` do módulo, e o `layout.json` serializa as mensagens
> do `CMessageHelper` na resposta — até a v1.1.1 o aviso aparecia **dentro de cada widget** da
> tela, com contagens regressivas diferentes em cada um.

### Como o modo somente-leitura decide o que bloquear

Duas regras, nesta ordem:

**1. Lista explícita** — nomes sem verbo reconhecível e páginas legadas que escrevem:

```
popup.scriptexec, popup.acknowledge.create, jsrpc.php, popup.php
```

**2. Qualquer segmento** do nome da action batendo em:

```
create, update, delete, massupdate, massdelete, massadd, massenable,
massdisable, massclear, massunlink, enable, disable, execute, execute_now,
import, rename, copy, clear, reset, unlink, activate, deactivate, provision,
unprovision, acknowledge, save, scriptexec, send, mute, unmute, pause,
resume, sync, restore, apply, upload
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
`{"error":{"title":...}}` para actions de layout JSON). A mensagem na tela é curta de propósito —
dentro de um widget ou popup um texto longo fica ilegível. O detalhe completo (action, alvo,
origem, modo) vai para o `error_log` com `debug: 1`.

#### Blacklist ou whitelist

Blacklist é o default, e é uma escolha consciente: ela **nunca recusa uma leitura por engano**, e
recusar leitura distorceria justamente a tela que o módulo existe para reproduzir. O preço é que
um verbo de escrita novo, introduzido num upgrade do Zabbix, passa até ser adicionado à lista.

Quem precisa da trava mais forte que da fidelidade da visão usa:

```json
"readonly_mode": "whitelist"
```

Aí vale o inverso — **default-deny**: a action só passa se algum segmento do nome estiver em
`view, list, edit, get, check, popup, php, menu, search, export, print, widget, refresh, sort,
filter, select, test, validate, compare, download, stats`.

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
10. **O token de origem existe no banco enquanto a impersonação está aberta.** Ele é cifrado
    (`encrypt_origin_sessionid: 1`), mas a chave é derivada de um segredo que o próprio frontend
    tem em mãos: isso protege contra dump de banco e SQLi, **não** contra quem já comprometeu o
    servidor de frontend. Mantenha `session_ttl` curto.
11. **Se a role do alvo perder acesso ao módulo no meio da impersonação**, o `Module.php` deixa de
    carregar: o guard de somente-leitura e o botão de sair desaparecem até a sessão expirar pelo
    `autologout` do Zabbix.

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

### Diagnóstico de dashboard

O botão **Dashboards** na linha do usuário responde a pergunta que sobra depois de impersonar:
*"a tela dele está cheia de erro — o que exatamente falta?"*.

Ele lista os dashboards que aquele usuário enxerga (dono, públicos, e os compartilhados com ele ou
com seus grupos) e, em *Analisar*, lê os widgets, resolve **todo** objeto referenciado — host
group, host, item, gráfico, mapa — e confronta com as permissões efetivas dele.

O relatório mostra só o que está quebrado, separando três causas que produzem a **mesma** mensagem
na tela do usuário e exigem correções opostas:

| Diagnóstico | O que significa | Correção |
|---|---|---|
| **Objeto não existe** | O widget aponta para um id removido do Zabbix | Não é permissão — quebra até para Super Admin. Corrija ou remova o widget |
| **DENY explícito** | Algum grupo de usuário do alvo tem DENY no host group | **Conceder mais permissão não resolve**: no Zabbix o DENY vence qualquer Read/Read-write. Remova o DENY |
| **Sem permissão** | Nenhum grupo dele concede leitura naquele host group | Conceda Read no host group para um dos grupos de usuário dele |

O relatório nomeia o host group faltante e, no caso de DENY, **qual grupo de usuário** está
negando — que é o ponto onde "mas eu já dei permissão para ele" costuma morrer.

Tudo somente leitura: o diagnóstico não altera permissão nenhuma.

> Gráficos exigem permissão em **todos** os hosts dos itens que os compõem — um gráfico com itens
> de dois hosts quebra se faltar acesso a qualquer um deles. Mapas não são protegidos por host
> group e sim por compartilhamento próprio, então para eles a checagem para na existência.

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
│   ├── ImpersonateGrant.php          # zbx.impersonate.grant      layout.json
│   ├── ImpersonateDashboards.php     # zbx.impersonate.dashboards layout.json
│   └── ImpersonateDashDiag.php       # zbx.impersonate.dashdiag   layout.json
├── helper/
│   ├── ImpersonateHelper.php         # troca de sessão, políticas, auditoria, schema
│   ├── DashboardDiagnostics.php      # permissões efetivas x objetos citados pelos widgets
│   └── ImpersonateAssets.php         # CSS inline compartilhado pelas views (escopado + tema)
├── views/
│   ├── zbx.impersonate.list.php
│   ├── zbx.impersonate.profile.php   # echo json_encode(...)
│   ├── zbx.impersonate.start.php     # echo json_encode(...)
│   ├── zbx.impersonate.stop.php      # não renderizada (todo desfecho é redirect); ver o arquivo
│   ├── zbx.impersonate.log.php
│   ├── zbx.impersonate.grant.php     # echo json_encode(...)
│   ├── zbx.impersonate.dashboards.php
│   └── zbx.impersonate.dashdiag.php
├── config.local.json.example         # modelo do override por frontend (o real é gitignorado)
├── sql/role_rule.sql                 # diagnóstico (só SELECTs) + desinstalação
├── install.sh
├── REVIEW.md                         # revisão de código que originou a 1.2.0
└── README.md
```

> Todo o CSS das views mora em `ImpersonateAssets::css()`. Até a v1.1.1 o mesmo bloco `<style>`
> era repetido nas três views (já com divergências entre elas) e declarava as variáveis em
> `:root` e o reset em `*` — ou seja, vazava para o documento inteiro do Zabbix. Agora as regras
> são escopadas por `.im-wrap` / `.modal-backdrop` e a paleta acompanha o tema do usuário.

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
    origin_sessionid VARCHAR(255)    NOT NULL DEFAULT '',
    clientip         VARCHAR(45)     NOT NULL DEFAULT '',
    user_agent       VARCHAR(255)    NOT NULL DEFAULT '',
    reason           VARCHAR(255)    NOT NULL DEFAULT '',
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

`reason`: justificativa digitada por quem impersonou (`require_reason`).
`end_reason`: `manual` · `expired` · `invalid` · `logout` · `stale` · vazio enquanto aberta.

`origin_sessionid` só tem valor enquanto a impersonação está aberta e é zerado no encerramento.
Com `encrypt_origin_sessionid: 1` (default) ele é gravado como `enc:<base64(iv+ciphertext)>`,
AES-256-CBC, chave derivada via `CEncryptHelper::sign()` do segredo de sessão do frontend — um
dump do banco sozinho não basta para decifrar. Linhas em texto claro são de instalações
anteriores à 1.2.0 e continuam sendo lidas normalmente.

### Alocação do `logid`

`MAX(logid)+1` **com retry**. O caminho canônico do Zabbix seria `DB::reserveIds()`, mas ele chama
`DB::getSchema($table)` e esta tabela não existe em `include/schema.inc.php` — a chamada lançaria
`DBException`. Então o `INSERT` usa `\DBexecute($sql, 1)` (sem banner de erro) e, se colidir na
chave primária porque duas impersonações começaram no mesmo instante, tenta o id seguinte. Até a
v1.1.1 era `SELECT MAX(logid) ... FOR UPDATE` dentro de `DBstart()`, que não trava a *gap* e podia
gerar id duplicado — fazendo o encerramento de um Super Admin fechar o evento do outro.

### MySQL e PostgreSQL

A partir da 1.2.0 o DDL é ramificado por `$DB['TYPE']`: `BIGINT UNSIGNED`/`ENGINE=`/`KEY` inline
no MySQL, `BIGINT`/`CREATE INDEX` separado no PostgreSQL. A detecção de coluna existente usa
`information_schema.columns`, presente nos dois, com o predicado de schema variando
(`DATABASE()` vs `current_schema()`).

As consultas de `sql/role_rule.sql` continuam em sintaxe MySQL — veja a nota no topo do arquivo.

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

Zabbix 7.0 LTS · PHP 8.x · MariaDB 10.11 (PostgreSQL suportado a partir da 1.2.0) ·
frontends atrás de F5 BIG-IP · módulos em `/usr/share/zabbix/modules/`

---

## Changelog

### 1.3.0

**Adicionado**

- **`config.local.json`** — override de configuração por frontend, fora do git. O `manifest.json`
  é versionado, então editá-lo em cada nó fazia todo `git pull` conflitar.
- **Diagnóstico de dashboard** (botão *Dashboards* na linha do usuário): lê os widgets, resolve
  host groups, hosts, itens, gráficos e mapas referenciados, e aponta o que quebra para aquele
  usuário — separando *objeto inexistente*, *DENY explícito* e *sem permissão*, que produzem a
  mesma mensagem na tela e pedem correções opostas. Somente leitura.

### 1.2.0

**Corrigido**

- **Banner replicado dentro de cada widget do dashboard.** Cada widget é uma request própria que
  passa pelo `init()` do módulo, e o `layout.json` serializa as mensagens do `CMessageHelper` na
  resposta. O aviso agora só é emitido em carregamento de página completa
  (`ImpersonateHelper::isPageRequest()`).
- **`readonly_extra_suffixes` era opção morta** — lida no `Module.php`, ausente do `config` do
  `manifest.json`, portanto sempre `[]`.
- **"Sign out" nativo não encerrava a impersonação**: a linha do log ficava com `ended=0` para
  sempre, a sessão Super Admin de origem sobrava órfã no banco e o token continuava lá. Coberto
  tanto na action moderna (`userprofile.logout`) quanto no caminho legado `index.php?reconnect=1`.
- **`logid` podia colidir.** `SELECT MAX(logid) ... FOR UPDATE` não trava a *gap*; duas
  impersonações simultâneas geravam o mesmo id e o encerramento de um Super Admin fechava o evento
  do outro. Agora há retry na chave primária.
- **`%` e `_` digitados na busca** (lista de usuários e log) viravam wildcard de `LIKE`.
- **`roleHasModuleAccess()` era fail-open**: qualquer falha da API de roles devolvia "tem acesso".
  Agora devolve indeterminado e a impersonação é recusada com mensagem própria.
- **`:root` e `*` vazando** das views para o documento inteiro do Zabbix; CSS duplicado em três
  views, já divergente entre elas.
- **`logEnd()` podia gerar banner vermelho** em qualquer tela quando a tabela de log não existia,
  já que é chamado de dentro do `getState()`, que roda a cada request.
- Acentuação dos textos de interface.

**Adicionado**

- **`origin_sessionid` cifrado em repouso** (AES-256-CBC, chave derivada do segredo de sessão do
  frontend). Antes era um token Super Admin válido em texto claro no banco.
- **Suporte a PostgreSQL** — o DDL anterior (`BIGINT UNSIGNED`, `ENGINE=InnoDB`, `KEY` inline,
  `TABLE_SCHEMA=DATABASE()`) só funcionava em MySQL/MariaDB.
- **`readonly_mode: "whitelist"`** — default-deny, para quem prefere a trava mais forte à
  fidelidade da visão. Blacklist segue como default, com 14 verbos novos na lista.
- **`banner` e `menu_exit_item`** desligáveis, para uma tela pixel a pixel igual à do usuário.
- **`require_reason`** — justificativa obrigatória, gravada em `module_impersonate_log.reason` e
  exibida no log e no histórico do perfil.
- **`stale_after`** — a tela de listagem fecha eventos que ficaram abertos (`end_reason=stale`),
  liberando o token retido.
- **`debug`** — manda o motivo real de cada falha interna para o `error_log` em vez de engoli-la.
- **Prévia antes de liberar roles**: o botão faz um dry-run e lista nominalmente quais roles serão
  alteradas antes de pedir confirmação.
- Tema escuro nas telas do módulo; ícone `zi-sign-out` e truncagem do username no menu.

### 1.1.1

Escape de `<role>` no alerta; versão e hostname na tela.

### 1.1.0

Botão para liberar o módulo em todas as roles; menu dentro da seção nativa *Users*;
`ALTER TABLE` compatível com MySQL.

### 1.0.0

Primeira versão.
