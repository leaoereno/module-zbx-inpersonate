-- =====================================================================
-- Impersonate - SQL de diagnostico e desinstalacao
-- Autor: Rafael M. A. Leao Ereno - MALE
--
--   mysql -u zabbix -p zabbix < role_rule.sql
--
-- IMPORTANTE: este arquivo NAO altera permissoes.
--
-- No Zabbix 7.0 o acesso a um modulo e controlado por role, na tela
-- Users -> User roles -> <role> -> Access to modules. Inserir linhas em
-- role_rule na mao e arriscado: o Zabbix aloca role_ruleid pela tabela
-- `ids` (DB::reserveIds), entao um INSERT com MAX(role_ruleid)+1 deixa o
-- contador defasado e a proxima edicao de role pela UI colide com chave
-- primaria duplicada. Use a interface.
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1. O modulo esta instalado e habilitado?
--    status: 0 = desabilitado, 1 = habilitado
-- ---------------------------------------------------------------------

SELECT moduleid, id, relative_path, status
FROM module
WHERE id = 'zbx-impersonate';

-- ---------------------------------------------------------------------
-- 2. Quais roles enxergam o modulo?
--
--    A role do usuario ALVO precisa enxergar o modulo. Sem isso o
--    CModuleManager nem instancia o Module.php durante a impersonacao:
--    o guard de somente-leitura e o item "Sair da impersonacao" deixam
--    de existir. Por isso o modulo recusa impersonar nesse caso
--    (config require_module_access no manifest.json).
--
--    Interpretacao:
--      explicit_status = 1  -> liberado explicitamente
--      explicit_status = 0  -> negado explicitamente
--      explicit_status NULL -> vale o default_access (1 = liberado)
-- ---------------------------------------------------------------------

SELECT r.roleid,
       r.name AS role_name,
       CASE r.type WHEN 1 THEN 'User' WHEN 2 THEN 'Admin' WHEN 3 THEN 'Super Admin' END AS role_type,
       MAX(CASE WHEN rr.name = 'modules.default_access' THEN rr.value_int END) AS default_access,
       MAX(CASE WHEN rr.name = CONCAT('modules.module.',
                                      (SELECT moduleid FROM module WHERE id = 'zbx-impersonate'))
                THEN rr.value_int END) AS explicit_status
FROM role r
LEFT JOIN role_rule rr ON rr.roleid = r.roleid
GROUP BY r.roleid, r.name, r.type
ORDER BY r.type DESC, r.name;

-- Se alguma role precisar de ajuste:
--   Users -> User roles -> <role> -> Access to modules -> marcar "Impersonate"

-- ---------------------------------------------------------------------
-- 3. Auditoria
-- ---------------------------------------------------------------------

-- A tabela foi criada? (o modulo cria sozinho na primeira impersonacao)
SHOW TABLES LIKE 'module_impersonate_log';

-- Quem impersonou quem nos ultimos 30 dias
SELECT logid,
       FROM_UNIXTIME(started) AS inicio,
       actor_username         AS quem,
       target_username        AS alvo,
       clientip,
       CASE readonly WHEN 1 THEN 'somente leitura' ELSE 'leitura e escrita' END AS modo,
       CASE WHEN ended = 0 THEN 'em andamento'
            ELSE CONCAT(ended - started, 's') END AS duracao,
       end_reason
FROM module_impersonate_log
WHERE started > UNIX_TIMESTAMP(NOW() - INTERVAL 30 DAY)
ORDER BY started DESC;

-- Sessoes de impersonacao que ficaram abertas (nao deveriam existir com
-- session_ttl configurado; se aparecerem, investigue)
SELECT logid, actor_username, target_username, FROM_UNIXTIME(started) AS inicio
FROM module_impersonate_log
WHERE ended = 0
ORDER BY started DESC;

-- ---------------------------------------------------------------------
-- 4. Desinstalacao (descomente para rodar)
-- ---------------------------------------------------------------------

-- Antes: Administration -> General -> Modules -> desabilitar "Impersonate"
-- e remover /usr/share/zabbix/modules/module-zbx-inpersonate de CADA frontend.

-- DROP TABLE IF EXISTS module_impersonate_log;
