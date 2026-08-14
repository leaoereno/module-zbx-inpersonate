<?php declare(strict_types=1);
/**
 * Impersonate - helper central do modulo.
 *
 * Toda a logica de troca de sessao, travas de seguranca, expiracao e auditoria
 * vive aqui. Actions e Module.php sao casca fina em cima deste helper.
 *
 * Autor: Rafael M. A. Leao Ereno - MALE
 */

namespace Modules\ZbxImpersonate\Helper;

class ImpersonateHelper {

	/** Chave do $_SESSION onde o estado da impersonacao e guardado (JSON). */
	public const SESSION_KEY = 'zbxi_state';

	/** Chave do $_SESSION com o HMAC do estado (defesa em profundidade). */
	public const SESSION_SIGN_KEY = 'zbxi_sign';

	/** Tabela de auditoria propria do modulo. */
	public const LOG_TABLE = 'module_impersonate_log';

	/** TTL padrao da sessao impersonada, em segundos. */
	public const DEFAULT_TTL = 1800;

	/** Motivos de encerramento gravados no log. */
	public const END_MANUAL  = 'manual';
	public const END_EXPIRED = 'expired';
	public const END_INVALID = 'invalid';

	/**
	 * Verbos tratados como escrita quando o modo somente-leitura esta ativo.
	 * Comparados contra CADA segmento do nome da action (separado por ponto) -
	 * comparar so o ultimo deixaria passar popup.massupdate.host e similares,
	 * onde o sufixo e o tipo do objeto e nao o verbo.
	 */
	public const WRITE_SUFFIXES = [
		'create', 'update', 'delete', 'massupdate', 'massdelete', 'massadd',
		'enable', 'disable', 'execute', 'execute_now', 'import', 'rename',
		'copy', 'clear', 'reset', 'unlink', 'activate', 'deactivate',
		'provision', 'unprovision', 'acknowledge', 'save', 'scriptexec'
	];

	/**
	 * Actions de escrita cujo nome nao contem nenhum verbo reconhecivel, e
	 * paginas legadas .php que fazem escrita (nelas o ultimo segmento e sempre
	 * "php", entao a heuristica por segmento nunca as pegaria).
	 */
	public const WRITE_ACTIONS = [
		'popup.scriptexec',
		'popup.acknowledge.create',
		'jsrpc.php',
		'popup.php'
	];

	/** Evita rodar o CREATE TABLE mais de uma vez por request. */
	private static bool $schema_checked = false;

	/** A tabela de auditoria esta realmente utilizavel? */
	private static bool $schema_ok = false;

	// -----------------------------------------------------------------------
	// Schema
	// -----------------------------------------------------------------------

	/**
	 * Cria a tabela de auditoria se ela ainda nao existir.
	 *
	 * Nao existe hook onEnable() no core do Zabbix, entao o provisionamento e
	 * feito de forma idempotente e sob demanda (so quando alguma action precisa
	 * mesmo tocar na tabela) - assim o init() do modulo nao paga DDL por request.
	 *
	 * O retorno IMPORTA: \DBexecute() nunca lanca excecao, so devolve false. Se o
	 * usuario do banco nao tiver privilegio de CREATE, a auditoria inteira ficaria
	 * silenciosamente vazia - por isso start() recusa a impersonacao nesse caso.
	 *
	 * @return bool  true se a tabela existe e esta legivel.
	 */
	public static function ensureSchema(): bool {
		if (self::$schema_checked) {
			return self::$schema_ok;
		}

		self::$schema_checked = true;

		$created = \DBexecute(
			'CREATE TABLE IF NOT EXISTS '.self::LOG_TABLE.' ('.
				'logid BIGINT UNSIGNED NOT NULL,'.
				'actor_userid BIGINT UNSIGNED NOT NULL,'.
				'actor_username VARCHAR(100) NOT NULL DEFAULT \'\','.
				'target_userid BIGINT UNSIGNED NOT NULL,'.
				'target_username VARCHAR(100) NOT NULL DEFAULT \'\','.
				'origin_sessionid VARCHAR(32) NOT NULL DEFAULT \'\','.
				'clientip VARCHAR(45) NOT NULL DEFAULT \'\','.
				'user_agent VARCHAR(255) NOT NULL DEFAULT \'\','.
				'readonly INT NOT NULL DEFAULT 1,'.
				'started INT NOT NULL DEFAULT 0,'.
				'ended INT NOT NULL DEFAULT 0,'.
				'end_reason VARCHAR(32) NOT NULL DEFAULT \'\','.
				'PRIMARY KEY (logid),'.
				'KEY idx_imp_started (started),'.
				'KEY idx_imp_actor (actor_userid),'.
				'KEY idx_imp_target (target_userid)'.
			') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
		);

		if (!$created) {
			self::$schema_ok = false;

			return false;
		}

		// Upgrade de instalacoes 1.0.0 anteriores a coluna origin_sessionid.
		// MariaDB 10.2+ aceita IF NOT EXISTS aqui; se falhar, o SELECT abaixo denuncia.
		\DBexecute(
			'ALTER TABLE '.self::LOG_TABLE.' ADD COLUMN IF NOT EXISTS'.
			' origin_sessionid VARCHAR(32) NOT NULL DEFAULT \'\' AFTER target_username'
		);

		// Le de verdade: cobre o caso de tabela existente porem inacessivel/incompativel.
		self::$schema_ok = \DBselect('SELECT origin_sessionid FROM '.self::LOG_TABLE, 1) !== false;

		return self::$schema_ok;
	}

	// -----------------------------------------------------------------------
	// Estado da impersonacao (guardado no $_SESSION, que o Zabbix ja assina)
	// -----------------------------------------------------------------------

	/**
	 * Le e valida o estado de impersonacao guardado na sessao.
	 *
	 * O cookie zbx_session inteiro ja e assinado por CEncryptedCookieSession, entao
	 * o HMAC proprio aqui e redundancia proposital: se um dia o payload for movido
	 * para outro transporte, a validacao continua valendo.
	 *
	 * NOTA: o sessionid do Super Admin NAO fica aqui - o cookie e assinado, mas nao
	 * cifrado, e um token de sessao privilegiada em texto claro no navegador seria
	 * um alvo desnecessario. Ele mora em module_impersonate_log, referenciado por logid.
	 *
	 * @return array|null  Estado valido, ou null se nao houver/estiver corrompido.
	 */
	public static function getState(): ?array {
		$raw = \CSessionHelper::get(self::SESSION_KEY);
		$sign = \CSessionHelper::get(self::SESSION_SIGN_KEY);

		if (!is_string($raw) || $raw === '' || !is_string($sign) || $sign === '') {
			return null;
		}

		if (!\CEncryptHelper::checkSign(\CEncryptHelper::sign($raw), $sign)) {
			self::clearState();

			return null;
		}

		$state = json_decode($raw, true);

		if (!is_array($state)) {
			self::clearState();

			return null;
		}

		$required = ['origin_userid', 'origin_username', 'target_userid', 'target_username',
			'started', 'expires', 'readonly', 'logid'
		];

		foreach ($required as $key) {
			if (!array_key_exists($key, $state)) {
				self::clearState();

				return null;
			}
		}

		// O estado tem que pertencer a QUEM esta autenticado agora. Sem esta amarra,
		// uma sessao impersonada que morreu (autologout do grupo do alvo, linha
		// removida de `sessions`) deixaria CWebUser em guest/default mas o cookie
		// ainda diria "impersonacao ativa" - banner mentiroso e read-only aplicado
		// sobre a sessao errada.
		$current_userid = (int) (\CWebUser::$data['userid'] ?? 0);

		if ((int) $state['target_userid'] !== $current_userid) {
			self::logEnd((int) $state['logid'], self::END_INVALID);
			self::clearState();

			return null;
		}

		return $state;
	}

	/**
	 * Grava o estado de impersonacao na sessao.
	 */
	public static function setState(array $state): void {
		$raw = json_encode($state, JSON_UNESCAPED_UNICODE);

		\CSessionHelper::set(self::SESSION_KEY, $raw);
		\CSessionHelper::set(self::SESSION_SIGN_KEY, \CEncryptHelper::sign($raw));
	}

	/**
	 * Remove o estado de impersonacao da sessao.
	 */
	public static function clearState(): void {
		\CSessionHelper::unset([self::SESSION_KEY, self::SESSION_SIGN_KEY]);
	}

	public static function isImpersonating(): bool {
		return self::getState() !== null;
	}

	// -----------------------------------------------------------------------
	// Consultas de usuario / permissao
	// -----------------------------------------------------------------------

	/**
	 * Retorna dados do usuario alvo incluindo o TIPO vindo da tabela role.
	 *
	 * A tabela users NAO tem coluna type - so roleid. O tipo mora em role.type.
	 *
	 * @return array|null
	 */
	public static function getUser(int $userid): ?array {
		$row = \DBfetch(\DBselect(
			'SELECT u.userid,u.username,u.name,u.surname,u.roleid,u.lang,u.theme,u.timezone,u.autologin,'.
				'u.autologout,u.refresh,u.rows_per_page,u.url,u.userdirectoryid,u.attempt_failed,'.
				'u.attempt_ip,u.attempt_clock,u.ts_provisioned,'.
				'r.name AS role_name,r.type AS role_type'.
			' FROM users u'.
			' LEFT JOIN role r ON r.roleid=u.roleid'.
			' WHERE u.userid='.\zbx_dbstr((string) $userid)
		));

		return $row ? $row : null;
	}

	/**
	 * Grupos do usuario, com gui_access / users_status / debug_mode.
	 */
	public static function getUserGroups(int $userid): array {
		$rows = [];
		$result = \DBselect(
			'SELECT g.usrgrpid,g.name,g.gui_access,g.users_status,g.debug_mode'.
			' FROM users_groups ug'.
			' JOIN usrgrp g ON g.usrgrpid=ug.usrgrpid'.
			' WHERE ug.userid='.\zbx_dbstr((string) $userid).
			' ORDER BY g.name'
		);

		while ($row = \DBfetch($result)) {
			$rows[] = $row;
		}

		return $rows;
	}

	/**
	 * Permissoes efetivas do usuario em host groups (tabela rights, via user groups).
	 * O maior nivel vence quando o usuario esta em mais de um grupo com o mesmo host group.
	 */
	public static function getHostGroupPermissions(int $userid): array {
		$rows = [];
		$result = \DBselect(
			'SELECT hg.groupid,MIN(hg.name) AS name,MAX(r.permission) AS permission'.
			' FROM users_groups ug'.
			' JOIN rights r ON r.groupid=ug.usrgrpid'.
			' JOIN hstgrp hg ON hg.groupid=r.id'.
			' WHERE ug.userid='.\zbx_dbstr((string) $userid).
			' GROUP BY hg.groupid'.
			' ORDER BY MIN(hg.name)'
		);

		while ($row = \DBfetch($result)) {
			$rows[] = $row;
		}

		return $rows;
	}

	/**
	 * Medias (canais de notificacao) do usuario.
	 */
	public static function getUserMedias(int $userid): array {
		$rows = [];
		$result = \DBselect(
			'SELECT m.mediaid,m.sendto,m.active,m.severity,m.period,mt.name AS media_type,mt.status AS mt_status'.
			' FROM media m'.
			' JOIN media_type mt ON mt.mediatypeid=m.mediatypeid'.
			' WHERE m.userid='.\zbx_dbstr((string) $userid).
			' ORDER BY mt.name'
		);

		while ($row = \DBfetch($result)) {
			$rows[] = $row;
		}

		return $rows;
	}

	/**
	 * Sessoes ativas do usuario (status=0).
	 */
	public static function getActiveSessions(int $userid): array {
		$rows = [];
		$result = \DBselect(
			'SELECT sessionid,lastaccess,status'.
			' FROM sessions'.
			' WHERE userid='.\zbx_dbstr((string) $userid).
				' AND status='.ZBX_SESSION_ACTIVE.
			' ORDER BY lastaccess DESC'
		);

		while ($row = \DBfetch($result)) {
			// Nunca devolver o sessionid inteiro para a tela - so um prefixo para correlacao.
			$row['sessionid'] = substr((string) $row['sessionid'], 0, 8).'...';
			$rows[] = $row;
		}

		return $rows;
	}

	/**
	 * Regras de role (UI/actions/modules) do role informado.
	 */
	public static function getRoleRules(string $roleid): array {
		$rows = [];
		$result = \DBselect(
			'SELECT name,value_int,value_str,value_moduleid'.
			' FROM role_rule'.
			' WHERE roleid='.\zbx_dbstr($roleid).
			' ORDER BY name'
		);

		while ($row = \DBfetch($result)) {
			$rows[] = $row;
		}

		return $rows;
	}

	/**
	 * O role informado tem acesso a ESTE modulo?
	 *
	 * Modelo do Zabbix: existe role_rule 'modules.module.<moduleid>' explicita (0/1);
	 * na falta dela vale 'modules.default_access' (default 1).
	 *
	 * Importa muito: se o role do alvo nao enxerga o modulo, o CModuleManager nem
	 * instancia o Module.php durante a impersonacao - ou seja, o guard de
	 * somente-leitura e o botao de sair simplesmente nao existiriam.
	 */
	public static function roleHasModuleAccess(string $roleid, string $moduleid): bool {
		if ($roleid === '' || $roleid === '0' || $moduleid === '') {
			return false;
		}

		// Via API::Role() e nao SQL cru: o layout das linhas de role_rule para modulos
		// nao e estavel entre versoes, mas o formato de saida de selectRules e. E o
		// CRoleHelper nao e confiavel dentro de modulo, por isso a chamada e direta.
		try {
			$roles = \API::Role()->get([
				'output'      => [],
				'selectRules' => ['modules', 'modules.default_access'],
				'roleids'     => $roleid
			]);
		}
		catch (\Throwable $e) {
			// Sem conseguir consultar, nao bloqueia por engano - a trava real
			// continua sendo o Super Admin ver o motivo na tela.
			return true;
		}

		if (!$roles || !array_key_exists('rules', $roles[0])) {
			return true;
		}

		$rules = $roles[0]['rules'];

		if (array_key_exists('modules', $rules) && is_array($rules['modules'])) {
			foreach ($rules['modules'] as $module) {
				if ((string) $module['moduleid'] === $moduleid) {
					return (int) $module['status'] === 1;
				}
			}
		}

		return !array_key_exists('modules.default_access', $rules)
			|| (int) $rules['modules.default_access'] === 1;
	}

	// -----------------------------------------------------------------------
	// Start / Stop
	// -----------------------------------------------------------------------

	/**
	 * Inicia a impersonacao do usuario alvo.
	 *
	 * Usa CUser::loginByUsername() - o mesmo caminho que o Zabbix usa no SSO/SAML
	 * (ui/index_sso.php) para autenticar sem senha. Isso cria a linha em `sessions`,
	 * respeita grupo desabilitado / role invalido / GUI access, e ja grava o
	 * ACTION_LOGIN_SUCCESS no audit log nativo do Zabbix.
	 *
	 * @return array  ['success' => bool, 'error' => string, 'target' => array|null]
	 */
	public static function start(int $target_userid, int $ttl, bool $readonly, bool $block_super_admin,
			bool $require_module_access, string $moduleid): array {

		$fail = static function (string $message): array {
			return ['success' => false, 'error' => $message, 'target' => null];
		};

		if (self::isImpersonating()) {
			return $fail(_('Ja existe uma impersonacao ativa. Encerre a atual antes de iniciar outra.'));
		}

		$actor_userid = (int) \CWebUser::$data['userid'];
		$actor_username = (string) \CWebUser::$data['username'];
		$origin_sessionid = (string) \CWebUser::$data['sessionid'];

		if ($actor_userid <= 0 || $origin_sessionid === '') {
			return $fail(_('Sessao de origem invalida.'));
		}

		if ($target_userid === $actor_userid) {
			return $fail(_('Voce nao pode impersonar a si mesmo.'));
		}

		$target = self::getUser($target_userid);

		if ($target === null) {
			return $fail(_('Usuario alvo nao encontrado.'));
		}

		if ((int) $target['roleid'] === 0 || $target['role_type'] === null) {
			return $fail(_('Usuario alvo nao possui role atribuida e nao pode ser impersonado.'));
		}

		if ($block_super_admin && (int) $target['role_type'] === USER_TYPE_SUPER_ADMIN) {
			return $fail(_('Impersonar outro Super Admin esta bloqueado pela politica do modulo.'));
		}

		if ($target['username'] === ZBX_GUEST_USER) {
			return $fail(_('O usuario guest nao pode ser impersonado.'));
		}

		if ($require_module_access && !self::roleHasModuleAccess((string) $target['roleid'], $moduleid)) {
			return $fail(_s(
				'A role "%1$s" do usuario alvo nao tem acesso ao modulo Impersonate. Sem isso o modo somente-leitura'.
					' e o botao de sair da impersonacao nao funcionariam. Libere o modulo para essa role em'.
					' Users -> User roles, ou desative "require_module_access" no manifest.',
				(string) $target['role_name']
			));
		}

		// Confere que a sessao de origem realmente existe e pertence ao ator.
		$origin_row = \DBfetch(\DBselect(
			'SELECT sessionid'.
			' FROM sessions'.
			' WHERE sessionid='.\zbx_dbstr($origin_sessionid).
				' AND userid='.\zbx_dbstr((string) $actor_userid)
		));

		if (!$origin_row) {
			return $fail(_('Nao foi possivel validar a sessao de origem. Faca login novamente.'));
		}

		// Sem auditoria gravavel nao ha impersonacao: o log e tambem onde o sessionid
		// de origem fica guardado, entao sem ele nem daria para voltar.
		if (!self::ensureSchema()) {
			return $fail(_s(
				'Nao foi possivel criar/acessar a tabela de auditoria "%1$s". Verifique se o usuario do banco'.
					' configurado em zabbix.conf.php tem privilegio de CREATE/ALTER. A impersonacao foi recusada'.
					' porque sem auditoria ela nao pode ser rastreada nem revertida.',
				self::LOG_TABLE
			));
		}

		// Desliga temporariamente o wrapper de API - mesmo padrao do ui/index_sso.php.
		$wrapper = \API::getWrapper();
		\API::setWrapper();

		try {
			$user_data = \CUser::loginByUsername((string) $target['username'], true);
		}
		catch (\Throwable $e) {
			\API::setWrapper($wrapper);

			return $fail(_s('Falha ao autenticar como o usuario alvo: %1$s', $e->getMessage()));
		}

		\API::setWrapper($wrapper);

		if (!is_array($user_data) || !array_key_exists('sessionid', $user_data)) {
			return $fail(_('Falha ao criar a sessao do usuario alvo.'));
		}

		if ((int) $user_data['gui_access'] === GROUP_GUI_ACCESS_DISABLED) {
			// A sessao ja foi criada pelo loginByUsername - nao deixar orfa no banco.
			\DBexecute(
				'DELETE FROM sessions'.
				' WHERE sessionid='.\zbx_dbstr((string) $user_data['sessionid']).
					' AND userid='.\zbx_dbstr((string) $target_userid)
			);

			return $fail(_('O usuario alvo esta com acesso a interface desabilitado (GUI access disabled).'));
		}

		$now = time();
		$logid = self::logStart($actor_userid, $actor_username, $target_userid, (string) $target['username'],
			$origin_sessionid, $readonly
		);

		if ($logid <= 0) {
			// Nao conseguimos registrar - desfaz a sessao recem-criada e aborta.
			\DBexecute(
				'DELETE FROM sessions'.
				' WHERE sessionid='.\zbx_dbstr((string) $user_data['sessionid']).
					' AND userid='.\zbx_dbstr((string) $target_userid)
			);

			return $fail(_('Falha ao gravar o log de auditoria. A impersonacao foi cancelada.'));
		}

		self::setState([
			'origin_userid'   => $actor_userid,
			'origin_username' => $actor_username,
			'target_userid'   => $target_userid,
			'target_username' => (string) $target['username'],
			'started'         => $now,
			'expires'         => $ttl > 0 ? $now + $ttl : 0,
			'readonly'        => $readonly ? 1 : 0,
			'logid'           => $logid
		]);

		// A partir daqui a sessao corrente passa a ser a do alvo.
		\CWebUser::$data = $user_data;
		\CSessionHelper::set('sessionid', $user_data['sessionid']);
		\API::getWrapper()->auth = [
			'type' => \CJsonRpc::AUTH_TYPE_FRONTEND,
			'auth' => $user_data['sessionid']
		];

		return ['success' => true, 'error' => '', 'target' => $target];
	}

	/**
	 * Restaura a sessao original do Super Admin.
	 *
	 * @return bool  true se havia impersonacao ativa e ela foi encerrada.
	 */
	public static function stop(string $reason = self::END_MANUAL): bool {
		$state = self::getState();

		if ($state === null) {
			return false;
		}

		$origin_userid = (int) $state['origin_userid'];

		// O sessionid de origem vive no log, nao no cookie (ver getState()).
		$origin_sessionid = self::getOriginSessionid((int) $state['logid']);

		if ($origin_sessionid === '') {
			self::logEnd((int) $state['logid'], $reason);
			self::clearState();
			\CSessionHelper::unset(['sessionid']);

			return false;
		}

		// A sessao de origem ainda e valida? Se nao for, nao adianta restaurar.
		$origin_row = \DBfetch(\DBselect(
			'SELECT sessionid'.
			' FROM sessions'.
			' WHERE sessionid='.\zbx_dbstr($origin_sessionid).
				' AND userid='.\zbx_dbstr((string) $origin_userid).
				' AND status='.ZBX_SESSION_ACTIVE
		));

		// Derruba a sessao criada para a impersonacao, seja qual for o desfecho.
		$impersonated_sessionid = (string) \CWebUser::$data['sessionid'];

		if ($impersonated_sessionid !== '' && $impersonated_sessionid !== $origin_sessionid) {
			\DBexecute(
				'DELETE FROM sessions'.
				' WHERE sessionid='.\zbx_dbstr($impersonated_sessionid).
					' AND userid='.\zbx_dbstr((string) $state['target_userid'])
			);
		}

		self::ensureSchema();
		self::logEnd((int) $state['logid'], $reason);
		self::clearState();

		if (!$origin_row) {
			// Sessao original expirou/foi derrubada: sem volta possivel, forca novo login.
			\CSessionHelper::unset(['sessionid']);

			return false;
		}

		\CSessionHelper::set('sessionid', $origin_sessionid);

		return true;
	}

	// -----------------------------------------------------------------------
	// Auditoria
	// -----------------------------------------------------------------------

	/**
	 * Grava o inicio da impersonacao.
	 *
	 * O par SELECT MAX(logid)+1 / INSERT roda dentro de \DBstart()/\DBend() porque
	 * duas impersonacoes simultaneas gerariam o mesmo logid - e um logid duplicado
	 * faria o logEnd() de um Super Admin fechar o evento do outro.
	 *
	 * @return int  logid gravado, ou 0 se a auditoria falhou.
	 */
	private static function logStart(int $actor_userid, string $actor_username, int $target_userid,
			string $target_username, string $origin_sessionid, bool $readonly): int {

		$user_agent = array_key_exists('HTTP_USER_AGENT', $_SERVER)
			? substr((string) $_SERVER['HTTP_USER_AGENT'], 0, 255)
			: '';

		\DBstart();

		$row = \DBfetch(\DBselect('SELECT MAX(logid) AS maxid FROM '.self::LOG_TABLE.' FOR UPDATE'));
		$logid = ($row && $row['maxid'] !== null) ? ((int) $row['maxid'] + 1) : 1;

		$inserted = \DBexecute(
			'INSERT INTO '.self::LOG_TABLE.
			' (logid,actor_userid,actor_username,target_userid,target_username,origin_sessionid,clientip,'.
				'user_agent,readonly,started,ended,end_reason)'.
			' VALUES ('.
				\zbx_dbstr((string) $logid).','.
				\zbx_dbstr((string) $actor_userid).','.
				\zbx_dbstr($actor_username).','.
				\zbx_dbstr((string) $target_userid).','.
				\zbx_dbstr($target_username).','.
				\zbx_dbstr($origin_sessionid).','.
				\zbx_dbstr(\CWebUser::getIp()).','.
				\zbx_dbstr($user_agent).','.
				($readonly ? '1' : '0').','.
				\zbx_dbstr((string) time()).','.
				'0,'.
				\zbx_dbstr('').
			')'
		);

		if (!\DBend((bool) $inserted)) {
			return 0;
		}

		return $logid;
	}

	/**
	 * Recupera o sessionid de origem guardado no log.
	 */
	private static function getOriginSessionid(int $logid): string {
		if ($logid <= 0 || !self::ensureSchema()) {
			return '';
		}

		$row = \DBfetch(\DBselect(
			'SELECT origin_sessionid'.
			' FROM '.self::LOG_TABLE.
			' WHERE logid='.\zbx_dbstr((string) $logid)
		));

		return $row ? (string) $row['origin_sessionid'] : '';
	}

	/**
	 * Fecha o evento no log e apaga o sessionid de origem (nao precisa mais dele).
	 */
	private static function logEnd(int $logid, string $reason): void {
		if ($logid <= 0) {
			return;
		}

		\DBexecute(
			'UPDATE '.self::LOG_TABLE.
			' SET ended='.\zbx_dbstr((string) time()).','.
				'end_reason='.\zbx_dbstr($reason).','.
				'origin_sessionid='.\zbx_dbstr('').
			' WHERE logid='.\zbx_dbstr((string) $logid).
				' AND ended=0'
		);
	}

	/**
	 * Ultimos registros do log de impersonacao.
	 */
	public static function getLog(int $limit = 200, string $search = '', int $target_userid = 0): array {
		self::ensureSchema();

		$sql = 'SELECT * FROM '.self::LOG_TABLE.' WHERE 1=1';

		if ($search !== '') {
			$like = \zbx_dbstr('%'.$search.'%');
			$sql .= ' AND (actor_username LIKE '.$like.' OR target_username LIKE '.$like.' OR clientip LIKE '.$like.')';
		}

		if ($target_userid > 0) {
			$sql .= ' AND target_userid='.\zbx_dbstr((string) $target_userid);
		}

		$sql .= ' ORDER BY started DESC, logid DESC';

		$rows = [];
		$result = \DBselect($sql, $limit);

		while ($row = \DBfetch($result)) {
			$rows[] = $row;
		}

		return $rows;
	}

	// -----------------------------------------------------------------------
	// Modo somente-leitura
	// -----------------------------------------------------------------------

	/**
	 * A action informada e considerada escrita?
	 *
	 * Duas regras, nesta ordem:
	 *
	 * 1. Lista explicita (WRITE_ACTIONS) - cobre nomes sem verbo reconhecivel
	 *    (popup.scriptexec) e paginas legadas .php, onde CLegacyAction::getAction()
	 *    devolve "jsrpc.php" e o ultimo segmento e sempre "php".
	 * 2. Qualquer SEGMENTO do nome batendo em WRITE_SUFFIXES. Olhar so o ultimo
	 *    segmento deixaria passar popup.massupdate.host / popup.massupdate.item,
	 *    que sao justamente as acoes de escrita em massa.
	 *
	 * Navegacao continua livre: *.view, *.list, *.edit, *.get, *.check.
	 */
	public static function isWriteAction(string $action, array $extra_suffixes = []): bool {
		if ($action === '') {
			return false;
		}

		$action = strtolower($action);

		if (in_array($action, self::WRITE_ACTIONS, true)) {
			return true;
		}

		// Demais paginas legadas (.php) sao leitura: chart*.php, history.php, image.php...
		if (substr($action, -4) === '.php') {
			return false;
		}

		$suffixes = array_merge(self::WRITE_SUFFIXES, array_map('strtolower', $extra_suffixes));

		foreach (explode('.', $action) as $segment) {
			if (in_array($segment, $suffixes, true)) {
				return true;
			}
		}

		return false;
	}

	/**
	 * A request atual e AJAX/JSON?
	 */
	public static function isAjaxRequest(): bool {
		if (array_key_exists('HTTP_X_REQUESTED_WITH', $_SERVER)
				&& strcasecmp((string) $_SERVER['HTTP_X_REQUESTED_WITH'], 'XMLHttpRequest') == 0) {
			return true;
		}

		return array_key_exists('CONTENT_TYPE', $_SERVER)
			&& stripos((string) $_SERVER['CONTENT_TYPE'], 'application/json') !== false;
	}

	/**
	 * A request atual devolve algo que NAO e uma pagina HTML (imagem, JSON, RPC)?
	 *
	 * Serve para nao mandar um 302 no meio de um <img src="chart2.php?..."> quando
	 * a impersonacao expira - a imagem quebraria na tela do usuario.
	 */
	public static function isNonHtmlRequest(): bool {
		if (self::isAjaxRequest()) {
			return true;
		}

		$script = basename((string) ($_SERVER['SCRIPT_NAME'] ?? ''));

		return in_array($script, ['chart.php', 'chart2.php', 'chart3.php', 'chart4.php', 'chart6.php',
			'chart7.php', 'image.php', 'imgstore.php', 'jsrpc.php', 'api_jsonrpc.php'
		], true);
	}

	// -----------------------------------------------------------------------
	// Formatacao
	// -----------------------------------------------------------------------

	public static function userTypeLabel(?int $type): string {
		switch ((int) $type) {
			case USER_TYPE_ZABBIX_USER:
				return 'User';

			case USER_TYPE_ZABBIX_ADMIN:
				return 'Admin';

			case USER_TYPE_SUPER_ADMIN:
				return 'Super Admin';
		}

		return '-';
	}

	public static function permissionLabel(?int $permission): string {
		switch ((int) $permission) {
			case PERM_DENY:
				return 'Deny';

			case PERM_READ:
				return 'Read';

			case PERM_READ_WRITE:
				return 'Read-write';
		}

		return '-';
	}

	public static function formatTs(?int $ts): string {
		$ts = (int) $ts;

		return $ts > 0 ? date('d/m/Y H:i:s', $ts) : '-';
	}

	public static function formatDuration(int $seconds): string {
		if ($seconds <= 0) {
			return '-';
		}

		$h = intdiv($seconds, 3600);
		$m = intdiv($seconds % 3600, 60);
		$s = $seconds % 60;

		if ($h > 0) {
			return sprintf('%dh %02dm %02ds', $h, $m, $s);
		}

		return $m > 0 ? sprintf('%dm %02ds', $m, $s) : sprintf('%ds', $s);
	}
}
