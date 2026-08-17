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
	public const END_LOGOUT  = 'logout';
	public const END_STALE   = 'stale';

	/** Prefixo que marca um origin_sessionid cifrado em repouso. */
	private const ENC_PREFIX = 'enc:';

	/**
	 * Actions de logout do Zabbix. Se o usuario sair por aqui em vez de usar
	 * "Sair da impersonacao", o modulo precisa fechar o evento no log e derrubar
	 * a sessao de origem - senao a linha fica com ended=0 para sempre e sobra
	 * uma sessao Super Admin orfa no banco.
	 */
	public const LOGOUT_ACTIONS = ['userprofile.logout', 'user.logout', 'logout'];

	/**
	 * A request atual e um logout do Zabbix?
	 *
	 * Duas formas convivem no core: a action moderna (userprofile.logout) e o
	 * caminho legado index.php?reconnect=1 - neste ultimo CLegacyAction::getAction()
	 * devolve "index.php", que nao diz nada, entao a deteccao e pelo parametro.
	 * Nenhuma outra tela do Zabbix usa "reconnect".
	 */
	public static function isLogoutRequest(string $action): bool {
		if (in_array(strtolower($action), self::LOGOUT_ACTIONS, true)) {
			return true;
		}

		return array_key_exists('reconnect', $_REQUEST);
	}

	/**
	 * Verbos tratados como escrita quando o modo somente-leitura esta ativo.
	 * Comparados contra CADA segmento do nome da action (separado por ponto) -
	 * comparar so o ultimo deixaria passar popup.massupdate.host e similares,
	 * onde o sufixo e o tipo do objeto e nao o verbo.
	 */
	public const WRITE_SUFFIXES = [
		'create', 'update', 'delete', 'massupdate', 'massdelete', 'massadd',
		'massenable', 'massdisable', 'massclear', 'massunlink',
		'enable', 'disable', 'execute', 'execute_now', 'import', 'rename',
		'copy', 'clear', 'reset', 'unlink', 'activate', 'deactivate',
		'provision', 'unprovision', 'acknowledge', 'save', 'scriptexec',
		'send', 'mute', 'unmute', 'pause', 'resume', 'sync', 'restore',
		'apply', 'upload'
	];

	/**
	 * Segmentos que caracterizam LEITURA. Usados apenas no modo whitelist
	 * (readonly_mode = "whitelist"), em que tudo que NAO contem um destes
	 * segmentos e recusado - default-deny.
	 *
	 * O modo blacklist continua sendo o default porque ele nunca recusa uma
	 * action de leitura por engano, e recusar leitura distorceria exatamente o
	 * que o modulo existe para mostrar: a tela como o usuario a ve.
	 */
	public const READ_SUFFIXES = [
		'view', 'list', 'edit', 'get', 'check', 'popup', 'php', 'menu',
		'search', 'export', 'print', 'widget', 'refresh', 'sort', 'filter',
		'select', 'test', 'validate', 'compare', 'download', 'stats'
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

	/** Liga o diagnostico (option "debug" do manifest). */
	private static bool $debug = false;

	/** Arquivo proprio de diagnostico (option "debug_file"). */
	private static string $debug_file = '';

	/** A gravacao no debug_file ja falhou nesta request? */
	private static bool $debug_file_failed = false;

	/** Evita registrar o trap de fatal mais de uma vez por request. */
	private static bool $trap_installed = false;

	/** Bloco "config" lido do manifest.json em disco (cache por request). */
	private static ?array $manifest_config = null;

	// -----------------------------------------------------------------------
	// Configuracao
	// -----------------------------------------------------------------------

	/**
	 * Le uma opcao do bloco "config" do manifest.json EM DISCO.
	 *
	 * Por que nao usar CModule::getOption(): o Zabbix nao le o manifest a cada
	 * request. A tabela `module` tem uma coluna `config` que e preenchida quando o
	 * modulo e REGISTRADO (Scan directory na primeira vez), e a partir dai
	 * getOption() responde a partir do banco. Editar o manifest.json depois disso
	 * nao muda nada - chaves novas simplesmente nao existem para o getOption(), que
	 * devolve o default em silencio.
	 *
	 * Na pratica isso significava que TODAS as opcoes adicionadas na 1.2.0 estavam
	 * inertes num frontend que ja tinha o modulo registrado desde a 1.1.x: era
	 * preciso desregistrar e reescanear o modulo so para trocar um valor.
	 *
	 * Lendo do arquivo, a configuracao volta a ser o que o operador espera - editou
	 * o manifest naquele frontend, vale naquele frontend. Isso tambem casa com o
	 * modelo de deploy por git com um checkout por no.
	 *
	 * @return mixed
	 */
	public static function option(string $name, $default = null) {
		if (self::$manifest_config === null) {
			self::$manifest_config = [];

			// helper/ImpersonateHelper.php -> raiz do modulo.
			$file = dirname(__DIR__).'/manifest.json';

			if (is_readable($file)) {
				$manifest = json_decode((string) file_get_contents($file), true);

				if (is_array($manifest) && array_key_exists('config', $manifest)
						&& is_array($manifest['config'])) {
					self::$manifest_config = $manifest['config'];
				}
			}
		}

		return array_key_exists($name, self::$manifest_config) ? self::$manifest_config[$name] : $default;
	}

	// -----------------------------------------------------------------------
	// Diagnostico
	// -----------------------------------------------------------------------

	public static function setDebug(bool $on, string $file = ''): void {
		self::$debug = $on;
		self::$debug_file = $file;
	}

	/**
	 * Mensagem de diagnostico.
	 *
	 * Os catch(\Throwable) do modulo sao silenciosos de proposito (nao dar tela
	 * branca no frontend), mas silencio total torna o modulo indepuravel em
	 * producao.
	 *
	 * Por que existe a opcao debug_file em vez de so error_log(): num frontend
	 * com PHP-FPM sem `error_log` definido no pool, o PHP manda os erros para o
	 * stderr e o FPM DESCARTA tudo se catch_workers_output estiver off - que e o
	 * default. Ou seja, error_log() pode nao ir a lugar nenhum, e o modulo fica
	 * cego justamente quando mais se precisa dele. Com debug_file o modulo grava
	 * onde ele mesmo escolheu, sem depender da configuracao do PHP.
	 *
	 * O hostname vai em cada linha de proposito: atras do F5 sao varios
	 * frontends, e saber QUAL respondeu e metade do diagnostico.
	 */
	public static function debug(string $message): void {
		if (!self::$debug) {
			return;
		}

		if (self::$debug_file !== '') {
			$line = sprintf('[%s] [%s] [pid %d] %s%s',
				date('Y-m-d H:i:s'), (string) gethostname(), getmypid(), $message, PHP_EOL
			);

			// SEM o operador @. A versao anterior silenciava a falha de escrita, e o
			// sintoma era o pior possivel para depurar: arquivo de log vazio, sem
			// nenhuma pista de que a gravacao estava sendo recusada (tipico de
			// SELinux negando o php-fpm em /var/log/, ou de permissao no diretorio).
			if (@file_put_contents(self::$debug_file, $line, FILE_APPEND) !== false) {
				return;
			}

			self::$debug_file_failed = true;
		}

		\error_log('[zbx-impersonate] '.$message);
	}

	/**
	 * Diagnostico do proprio diagnostico: da para gravar no debug_file?
	 *
	 * Mostrado na tela de listagem. Sem isso, "o log esta vazio" e ambiguo entre
	 * "o modulo nao registrou nada" e "o modulo nao consegue escrever" - e essas
	 * duas coisas levam a investigacoes completamente diferentes.
	 */
	public static function debugFileStatus(): string {
		if (!self::$debug) {
			return 'debug desligado';
		}

		if (self::$debug_file === '') {
			return 'usando error_log() do PHP';
		}

		if (self::$debug_file_failed) {
			return 'FALHA AO ESCREVER - checar permissao/SELinux';
		}

		$dir = dirname(self::$debug_file);

		if (!is_dir($dir)) {
			return 'diretorio nao existe: '.$dir;
		}

		if (file_exists(self::$debug_file)) {
			return is_writable(self::$debug_file)
				? 'gravavel ('.(int) filesize(self::$debug_file).' bytes)'
				: 'arquivo NAO gravavel pelo php-fpm';
		}

		return is_writable($dir) ? 'sera criado no primeiro registro' : 'diretorio NAO gravavel pelo php-fpm';
	}

	/**
	 * Joga os erros do PHP na TELA, para as telas deste modulo.
	 *
	 * Ultimo recurso de diagnostico, e existe por um motivo pratico: se o pool do
	 * PHP-FPM nao tem `error_log` definido e catch_workers_output esta off, o
	 * fatal nao aparece em log NENHUM e o navegador recebe um 500 de corpo vazio.
	 * Sem acesso a configuracao do PHP, a unica saida e o proprio modulo mandar o
	 * PHP renderizar o erro - display_errors e PHP_INI_ALL, entao da para ligar em
	 * tempo de execucao.
	 *
	 * Restricoes de proposito:
	 *   - so com debug=1;
	 *   - so nas actions zbx.impersonate.* - ligar isso no frontend inteiro faria
	 *     qualquer notice vazar para dentro das respostas JSON dos widgets e
	 *     quebrar o dashboard.
	 */
	public static function forceErrorDisplay(): void {
		if (!self::$debug) {
			return;
		}

		@ini_set('display_errors', '1');
		@ini_set('display_startup_errors', '1');
		@error_reporting(E_ALL);
	}

	/**
	 * Captura erros FATAIS, que nenhum try/catch alcanca.
	 *
	 * E_ERROR por esgotamento de memoria, "Maximum execution time exceeded" e
	 * afins nao sao Throwable - o bloco catch do doAction() nunca os ve, e o
	 * navegador recebe um 500 pelado. register_shutdown_function() roda depois do
	 * fatal e error_get_last() diz o que foi.
	 *
	 * So e armado com debug=1, entao nao custa nada em producao.
	 */
	public static function installFatalTrap(string $context): void {
		if (!self::$debug || self::$trap_installed) {
			return;
		}

		self::$trap_installed = true;

		register_shutdown_function(static function () use ($context): void {
			$error = error_get_last();

			if ($error === null) {
				return;
			}

			$fatal_types = [E_ERROR, E_PARSE, E_CORE_ERROR, E_CORE_WARNING, E_COMPILE_ERROR, E_USER_ERROR];

			if (!in_array((int) $error['type'], $fatal_types, true)) {
				return;
			}

			self::debug(sprintf('FATAL (%s) [tipo %d] %s @ %s:%d',
				$context, (int) $error['type'], (string) $error['message'],
				(string) $error['file'], (int) $error['line']
			));
		});
	}

	// -----------------------------------------------------------------------
	// Schema
	// -----------------------------------------------------------------------

	/**
	 * Cria/atualiza a tabela de auditoria se necessario.
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
		self::$schema_ok = false;

		$is_pgsql = self::isPgsql();

		$created = $is_pgsql ? self::createTablePgsql() : self::createTableMysql();

		if (!$created) {
			self::debug('ensureSchema: CREATE TABLE falhou (privilegio de CREATE no usuario do banco?)');

			return false;
		}

		self::migrateSchema($is_pgsql);

		// Le de verdade: cobre o caso de tabela existente porem inacessivel/incompativel.
		self::$schema_ok = \DBselect('SELECT origin_sessionid,reason FROM '.self::LOG_TABLE, 1) !== false;

		if (!self::$schema_ok) {
			self::debug('ensureSchema: tabela existe mas nao pode ser lida com as colunas esperadas');
		}

		return self::$schema_ok;
	}

	private static function isPgsql(): bool {
		global $DB;

		return (string) ($DB['TYPE'] ?? '') === ZBX_DB_POSTGRESQL;
	}

	private static function createTableMysql(): bool {
		return (bool) \DBexecute(
			'CREATE TABLE IF NOT EXISTS '.self::LOG_TABLE.' ('.
				'logid BIGINT UNSIGNED NOT NULL,'.
				'actor_userid BIGINT UNSIGNED NOT NULL,'.
				'actor_username VARCHAR(100) NOT NULL DEFAULT \'\','.
				'target_userid BIGINT UNSIGNED NOT NULL,'.
				'target_username VARCHAR(100) NOT NULL DEFAULT \'\','.
				'origin_sessionid VARCHAR(255) NOT NULL DEFAULT \'\','.
				'clientip VARCHAR(45) NOT NULL DEFAULT \'\','.
				'user_agent VARCHAR(255) NOT NULL DEFAULT \'\','.
				'reason VARCHAR(255) NOT NULL DEFAULT \'\','.
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
	}

	/**
	 * Mesma tabela em PostgreSQL.
	 *
	 * O Zabbix 7.0 roda em MySQL/MariaDB e em PostgreSQL/TimescaleDB; a versao
	 * anterior deste modulo so funcionava em MySQL (BIGINT UNSIGNED, ENGINE=,
	 * KEY inline - tudo invalido em PG).
	 */
	private static function createTablePgsql(): bool {
		$ok = (bool) \DBexecute(
			'CREATE TABLE IF NOT EXISTS '.self::LOG_TABLE.' ('.
				'logid BIGINT NOT NULL,'.
				'actor_userid BIGINT NOT NULL,'.
				'actor_username VARCHAR(100) DEFAULT \'\' NOT NULL,'.
				'target_userid BIGINT NOT NULL,'.
				'target_username VARCHAR(100) DEFAULT \'\' NOT NULL,'.
				'origin_sessionid VARCHAR(255) DEFAULT \'\' NOT NULL,'.
				'clientip VARCHAR(45) DEFAULT \'\' NOT NULL,'.
				'user_agent VARCHAR(255) DEFAULT \'\' NOT NULL,'.
				'reason VARCHAR(255) DEFAULT \'\' NOT NULL,'.
				'readonly INTEGER DEFAULT 1 NOT NULL,'.
				'started INTEGER DEFAULT 0 NOT NULL,'.
				'ended INTEGER DEFAULT 0 NOT NULL,'.
				'end_reason VARCHAR(32) DEFAULT \'\' NOT NULL,'.
				'PRIMARY KEY (logid)'.
			')'
		);

		if (!$ok) {
			return false;
		}

		foreach (['started' => 'idx_imp_started', 'actor_userid' => 'idx_imp_actor',
				'target_userid' => 'idx_imp_target'] as $column => $index) {
			\DBexecute('CREATE INDEX IF NOT EXISTS '.$index.' ON '.self::LOG_TABLE.' ('.$column.')', 1);
		}

		return true;
	}

	/**
	 * Upgrade de instalacoes anteriores.
	 *
	 * NAO usar "ADD COLUMN IF NOT EXISTS": isso e extensao do MariaDB e explode
	 * com erro de sintaxe no MySQL - e o \DBexecute() dispara trigger_error(),
	 * que o Zabbix mostra como banner vermelho no topo da tela. Checar antes
	 * pelo information_schema funciona nos tres bancos.
	 */
	private static function migrateSchema(bool $is_pgsql): void {
		$origin = self::columnInfo('origin_sessionid');

		if ($origin === null) {
			// 1.1.0 -> 1.1.1
			\DBexecute(
				'ALTER TABLE '.self::LOG_TABLE.
				' ADD COLUMN origin_sessionid VARCHAR(255) DEFAULT \'\' NOT NULL'
			);
		}
		elseif ((int) ($origin['character_maximum_length'] ?? 0) < 255) {
			// 1.1.x -> 1.2.0: o valor passou a ser cifrado em repouso e nao cabe mais em 32.
			\DBexecute($is_pgsql
				? 'ALTER TABLE '.self::LOG_TABLE.' ALTER COLUMN origin_sessionid TYPE VARCHAR(255)'
				: 'ALTER TABLE '.self::LOG_TABLE.' MODIFY origin_sessionid VARCHAR(255) NOT NULL DEFAULT \'\''
			);
		}

		if (self::columnInfo('reason') === null) {
			\DBexecute(
				'ALTER TABLE '.self::LOG_TABLE.' ADD COLUMN reason VARCHAR(255) DEFAULT \'\' NOT NULL'
			);
		}
	}

	/**
	 * Metadados de uma coluna da tabela de log, ou null se ela nao existir.
	 */
	private static function columnInfo(string $column): ?array {
		// information_schema existe nos dois bancos; so o predicado de schema muda.
		$schema = self::isPgsql() ? 'table_schema=current_schema()' : 'table_schema=DATABASE()';

		$row = \DBfetch(\DBselect(
			'SELECT column_name,character_maximum_length'.
			' FROM information_schema.columns'.
			' WHERE '.$schema.
				' AND table_name='.\zbx_dbstr(self::LOG_TABLE).
				' AND column_name='.\zbx_dbstr($column)
		));

		return $row ? $row : null;
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
	 * um alvo desnecessario. Ele mora em module_impersonate_log (cifrado em repouso),
	 * referenciado por logid.
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
			self::debug('getState: assinatura do estado nao confere - estado descartado');
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
			self::debug(sprintf('getState: estado orfao (target=%d, sessao atual=%d) - encerrando',
				(int) $state['target_userid'], $current_userid
			));
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
	 *
	 * @return bool|null  true = tem acesso, false = nao tem, null = NAO FOI POSSIVEL
	 *                    determinar. A versao anterior devolvia true nesse ultimo
	 *                    caso (fail-open numa checagem de seguranca); agora o
	 *                    indeterminado e explicito e quem chama decide.
	 */
	public static function roleHasModuleAccess(string $roleid, string $moduleid): ?bool {
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
			self::debug('roleHasModuleAccess: API::Role()->get falhou: '.$e->getMessage());

			return null;
		}

		if (!$roles || !array_key_exists('rules', $roles[0])) {
			self::debug('roleHasModuleAccess: resposta da API sem "rules" para roleid '.$roleid);

			return null;
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

	/**
	 * Concede acesso a este modulo em todas as roles que ainda nao o tem.
	 *
	 * Sem isso o modulo e inutil num ambiente com roles configuradas a mao: o
	 * modulo novo entra como negado e nenhum usuario dessas roles pode ser
	 * impersonado.
	 *
	 * Liberar o modulo NAO da poder nenhum ao usuario comum - list, profile,
	 * start e log exigem Super Admin em checkPermissions(), o item de menu so
	 * aparece para Super Admin, e stop so funciona com estado assinado valido.
	 * O acesso existe unicamente para que o CModuleManager carregue o Module.php
	 * durante a impersonacao, mantendo vivos o guard de somente-leitura, o
	 * banner e o botao de sair.
	 *
	 * SEGURANCA DO UPDATE (confirmado em CRole.php da branch release/7.0):
	 * enviar apenas ['roleid' => X, 'rules' => ['modules' => [...]]] preserva
	 * todas as outras regras. CRole::updateRules() faz `$role['rules'] + $old_rules`
	 * - uniao de arrays com precedencia a esquerda - e o $old_rules vem de um
	 * get() interno com as 15 chaves de selectRules. Modulos nao citados no array
	 * mantem o status atual pelo elseif de compileModulesRules(). Reenviar o objeto
	 * `rules` inteiro seria PIOR: exporia a validacao estrita de `api`, que recusa
	 * metodos herdados de versoes antigas que a gravacao apenas ignoraria.
	 *
	 * @param string   $moduleid
	 * @param string[] $only_roleids  Se nao vazio, mexe SOMENTE nestas roles.
	 * @param bool     $dry_run       true = so simula e devolve o que faria.
	 *
	 * @return array  ['granted'=>string[], 'already'=>int, 'readonly'=>string[], 'failed'=>string[],
	 *                 'would_grant'=>array[], 'error'=>string]
	 */
	public static function grantModuleAccessToAllRoles(string $moduleid, array $only_roleids = [],
			bool $dry_run = false): array {

		$out = ['granted' => [], 'already' => 0, 'readonly' => [], 'failed' => [], 'would_grant' => [],
			'error' => ''
		];

		if ($moduleid === '') {
			$out['error'] = _('Modulo sem moduleid - o modulo esta habilitado em Administration -> Modules?');

			return $out;
		}

		$options = [
			'output'      => ['roleid', 'name', 'readonly'],
			'selectRules' => ['modules'],
			'sortfield'   => 'name'
		];

		if ($only_roleids) {
			$options['roleids'] = $only_roleids;
		}

		try {
			$roles = \API::Role()->get($options);
		}
		catch (\Throwable $e) {
			$out['error'] = _s('Falha ao consultar as roles: %1$s', $e->getMessage());

			return $out;
		}

		if (!is_array($roles) || !$roles) {
			$out['error'] = _('Nenhuma role retornada pela API.');

			return $out;
		}

		foreach ($roles as $role) {
			$name = (string) $role['name'];
			$has_access = false;

			if (array_key_exists('rules', $role) && array_key_exists('modules', $role['rules'])) {
				foreach ($role['rules']['modules'] as $module) {
					// Comparacao normalizada: o get() devolve moduleid como int
					// e status como string.
					if ((string) $module['moduleid'] === $moduleid) {
						$has_access = ((int) $module['status'] === 1);
						break;
					}
				}
			}

			if ($has_access) {
				$out['already']++;
				continue;
			}

			// CRole::checkReadonly() recusa QUALQUER update em role readonly, mesmo
			// so de nome. Na pratica e a "Super admin role" (roleid 3) - e usuarios
			// Super Admin ja sao bloqueados como alvo pela politica do modulo.
			if ((int) $role['readonly'] === 1) {
				$out['readonly'][] = $name;
				continue;
			}

			if ($dry_run) {
				$out['would_grant'][] = ['roleid' => (string) $role['roleid'], 'name' => $name];
				continue;
			}

			try {
				$result = \API::Role()->update([
					'roleid' => $role['roleid'],
					'rules'  => [
						'modules' => [
							['moduleid' => $moduleid, 'status' => 1]
						]
					]
				]);
			}
			catch (\Throwable $e) {
				$out['failed'][] = $name.' ('.$e->getMessage().')';
				continue;
			}

			// O wrapper de frontend nao lanca excecao: empilha a mensagem e retorna false.
			if ($result === false) {
				$messages = \CMessageHelper::getMessages();
				$detail = $messages ? (string) end($messages)['message'] : _('erro desconhecido');

				$out['failed'][] = $name.' ('.$detail.')';
				continue;
			}

			$out['granted'][] = $name;
		}

		return $out;
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
	 * Como a sessao passa a ser integralmente a do alvo (lang, theme, timezone,
	 * refresh, rows_per_page, permissoes, role_rules), a tela renderizada e
	 * exatamente a que o usuario ve - inclusive os erros dele. Widget reclamando
	 * "No permissions to referred object" nao e defeito do modulo: e o achado.
	 *
	 * @param int   $target_userid
	 * @param array $opts  ttl, readonly, block_super_admin, require_module_access,
	 *                     moduleid, reason, encrypt
	 *
	 * @return array  ['success' => bool, 'error' => string, 'target' => array|null]
	 */
	public static function start(int $target_userid, array $opts): array {
		$ttl = (int) ($opts['ttl'] ?? self::DEFAULT_TTL);
		$readonly = (bool) ($opts['readonly'] ?? true);
		$block_super_admin = (bool) ($opts['block_super_admin'] ?? true);
		$require_module_access = (bool) ($opts['require_module_access'] ?? true);
		$moduleid = (string) ($opts['moduleid'] ?? '');
		$reason = mb_substr(trim((string) ($opts['reason'] ?? '')), 0, 255);
		$encrypt = (bool) ($opts['encrypt'] ?? true);

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

		if ($require_module_access) {
			$has_access = self::roleHasModuleAccess((string) $target['roleid'], $moduleid);

			if ($has_access === null) {
				return $fail(_s(
					'Nao foi possivel verificar se a role "%1$s" tem acesso ao modulo Impersonate (falha na API'.
						' de roles). A impersonacao foi recusada por precaucao. Ligue "debug" no manifest para ver'.
						' o erro no log do PHP, ou desative "require_module_access".',
					(string) $target['role_name']
				));
			}

			if (!$has_access) {
				return $fail(_s(
					'A role "%1$s" do usuario alvo nao tem acesso ao modulo Impersonate. Sem isso o modo'.
						' somente-leitura e o botao de sair da impersonacao nao funcionariam. Libere o modulo para'.
						' essa role em Users -> User roles, ou desative "require_module_access" no manifest.',
					(string) $target['role_name']
				));
			}
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
			self::deleteSession((string) $user_data['sessionid'], $target_userid);

			return $fail(_('O usuario alvo esta com acesso a interface desabilitado (GUI access disabled).'));
		}

		$now = time();
		$logid = self::logStart($actor_userid, $actor_username, $target_userid, (string) $target['username'],
			$origin_sessionid, $readonly, $reason, $encrypt
		);

		if ($logid <= 0) {
			// Nao conseguimos registrar - desfaz a sessao recem-criada e aborta.
			self::deleteSession((string) $user_data['sessionid'], $target_userid);

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

		self::debug(sprintf('start: %s -> %s (logid=%d, readonly=%d, ttl=%d)',
			$actor_username, (string) $target['username'], $logid, $readonly ? 1 : 0, $ttl
		));

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
			self::debug('stop: origin_sessionid indisponivel (logid='.(int) $state['logid'].')');
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
		$impersonated_sessionid = (string) (\CWebUser::$data['sessionid'] ?? '');

		if ($impersonated_sessionid !== '' && $impersonated_sessionid !== $origin_sessionid) {
			self::deleteSession($impersonated_sessionid, (int) $state['target_userid']);
		}

		self::ensureSchema();
		self::logEnd((int) $state['logid'], $reason);
		self::clearState();

		if (!$origin_row) {
			// Sessao original expirou/foi derrubada: sem volta possivel, forca novo login.
			self::debug(sprintf(
				'stop: sessao de origem nao esta mais ativa em `sessions` (userid=%d) - forcando novo login',
				$origin_userid
			));

			\CSessionHelper::unset(['sessionid']);

			return false;
		}

		\CSessionHelper::set('sessionid', $origin_sessionid);

		self::debug('stop: sessao de origem restaurada');

		return true;
	}

	/**
	 * Encerra a impersonacao SEM restaurar a sessao de origem, derrubando as duas.
	 *
	 * Usado no logout nativo do Zabbix ("Sign out"), que continua visivel na sidebar
	 * durante a impersonacao. Restaurar a sessao de origem aqui nao serve: o
	 * controller de logout iria em seguida derrubar justamente a sessao que
	 * acabamos de restaurar, usando um token que ja nao existe. Entao aqui o
	 * caminho e: fechar o evento no log, apagar a sessao Super Admin de origem
	 * (para nao sobrar token orfao no banco) e deixar o logout seguir normalmente
	 * sobre a sessao do alvo.
	 */
	public static function abandon(string $reason = self::END_LOGOUT): void {
		$state = self::getState();

		if ($state === null) {
			return;
		}

		$origin_sessionid = self::getOriginSessionid((int) $state['logid']);

		if ($origin_sessionid !== '') {
			self::deleteSession($origin_sessionid, (int) $state['origin_userid']);
		}

		self::ensureSchema();
		self::logEnd((int) $state['logid'], $reason);
		self::clearState();

		self::debug(sprintf('abandon: logid=%d reason=%s (logout durante impersonacao)',
			(int) $state['logid'], $reason
		));
	}

	/**
	 * Apaga uma linha de `sessions`. Erros sao silenciados: nao ha o que fazer
	 * a respeito e um trigger_error viraria banner vermelho na tela.
	 */
	private static function deleteSession(string $sessionid, int $userid): void {
		if ($sessionid === '' || $userid <= 0) {
			return;
		}

		\DBexecute(
			'DELETE FROM sessions'.
			' WHERE sessionid='.\zbx_dbstr($sessionid).
				' AND userid='.\zbx_dbstr((string) $userid),
			1
		);
	}

	// -----------------------------------------------------------------------
	// Auditoria
	// -----------------------------------------------------------------------

	/**
	 * Grava o inicio da impersonacao.
	 *
	 * Sobre a alocacao do logid: o caminho canonico do Zabbix seria
	 * DB::reserveIds(), mas ele chama DB::getSchema($table) e a tabela deste
	 * modulo nao existe em include/schema.inc.php - a chamada lancaria
	 * DBException. Por isso a alocacao e MAX(logid)+1 COM retry: a insercao usa
	 * \DBexecute($sql, 1) para nao gerar banner de erro, e uma colisao de chave
	 * primaria (duas impersonacoes iniciadas no mesmo instante) simplesmente
	 * tenta o proximo id. Sem o retry, uma das duas perdia o logid e o logEnd()
	 * de um Super Admin fechava o evento do outro.
	 *
	 * @return int  logid gravado, ou 0 se a auditoria falhou.
	 */
	private static function logStart(int $actor_userid, string $actor_username, int $target_userid,
			string $target_username, string $origin_sessionid, bool $readonly, string $reason,
			bool $encrypt): int {

		$user_agent = array_key_exists('HTTP_USER_AGENT', $_SERVER)
			? substr((string) $_SERVER['HTTP_USER_AGENT'], 0, 255)
			: '';

		$stored_sessionid = $encrypt ? self::protectSessionid($origin_sessionid) : $origin_sessionid;

		for ($attempt = 0; $attempt < 5; $attempt++) {
			$row = \DBfetch(\DBselect('SELECT MAX(logid) AS maxid FROM '.self::LOG_TABLE));
			$logid = ($row && $row['maxid'] !== null) ? ((int) $row['maxid'] + 1 + $attempt) : (1 + $attempt);

			$inserted = \DBexecute(
				'INSERT INTO '.self::LOG_TABLE.
				' (logid,actor_userid,actor_username,target_userid,target_username,origin_sessionid,clientip,'.
					'user_agent,reason,readonly,started,ended,end_reason)'.
				' VALUES ('.
					\zbx_dbstr((string) $logid).','.
					\zbx_dbstr((string) $actor_userid).','.
					\zbx_dbstr($actor_username).','.
					\zbx_dbstr((string) $target_userid).','.
					\zbx_dbstr($target_username).','.
					\zbx_dbstr($stored_sessionid).','.
					\zbx_dbstr(\CWebUser::getIp()).','.
					\zbx_dbstr($user_agent).','.
					\zbx_dbstr($reason).','.
					($readonly ? '1' : '0').','.
					\zbx_dbstr((string) time()).','.
					'0,'.
					\zbx_dbstr('').
				')',
				1
			);

			if ($inserted) {
				return $logid;
			}

			self::debug(sprintf('logStart: colisao/erro no logid %d (tentativa %d)', $logid, $attempt + 1));
		}

		return 0;
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

		if (!$row) {
			self::debug('getOriginSessionid: nenhuma linha para logid '.$logid);

			return '';
		}

		$stored = (string) $row['origin_sessionid'];
		$plain = self::revealSessionid($stored);

		if ($plain === '' && $stored !== '') {
			// Diferenciar os dois casos importa: valor truncado no banco (coluna
			// origin_sessionid estreita) tem cara de base64 curto; falha de chave
			// tem o tamanho certo e nao decifra.
			self::debug(sprintf(
				'getOriginSessionid: valor ilegivel (logid=%d, %d chars armazenados, cifrado=%s)',
				$logid, strlen($stored), strncmp($stored, self::ENC_PREFIX, 4) === 0 ? 'sim' : 'nao'
			));
		}

		return $plain;
	}

	/**
	 * Fecha o evento no log e apaga o sessionid de origem (nao precisa mais dele).
	 */
	private static function logEnd(int $logid, string $reason): void {
		if ($logid <= 0) {
			return;
		}

		// Segundo argumento = 1: suprime a mensagem de erro do Zabbix. logEnd() e
		// chamado de dentro do getState(), que roda no init() do modulo em TODA
		// request - se a tabela nao existir (modulo recem-instalado, banco sem
		// privilegio de CREATE), um trigger_error aqui viraria banner vermelho em
		// cima de qualquer tela do frontend.
		\DBexecute(
			'UPDATE '.self::LOG_TABLE.
			' SET ended='.\zbx_dbstr((string) time()).','.
				'end_reason='.\zbx_dbstr($reason).','.
				'origin_sessionid='.\zbx_dbstr('').
			' WHERE logid='.\zbx_dbstr((string) $logid).
				' AND ended=0',
			1
		);
	}

	/**
	 * Fecha eventos que ficaram abertos indefinidamente.
	 *
	 * Um crash do PHP, um kill do frontend ou um navegador fechado no meio da
	 * impersonacao deixam a linha com ended=0 e - pior - o token de origem
	 * guardado. Chamado pela tela de listagem, que e por onde o Super Admin passa.
	 *
	 * @return int  quantidade de eventos fechados.
	 */
	public static function closeStaleLogRows(int $stale_after): int {
		if ($stale_after <= 0 || !self::ensureSchema()) {
			return 0;
		}

		$cutoff = time() - $stale_after;

		$rows = [];
		$result = \DBselect(
			'SELECT logid FROM '.self::LOG_TABLE.
			' WHERE ended=0 AND started<'.\zbx_dbstr((string) $cutoff)
		);

		while ($row = \DBfetch($result)) {
			$rows[] = (int) $row['logid'];
		}

		foreach ($rows as $logid) {
			self::logEnd($logid, self::END_STALE);
		}

		if ($rows) {
			self::debug('closeStaleLogRows: '.count($rows).' evento(s) fechado(s) como stale');
		}

		return count($rows);
	}

	/**
	 * Ultimos registros do log de impersonacao.
	 */
	public static function getLog(int $limit = 200, string $search = '', int $target_userid = 0): array {
		if (!self::ensureSchema()) {
			return [];
		}

		$sql = 'SELECT * FROM '.self::LOG_TABLE.' WHERE 1=1';

		if ($search !== '') {
			$like = \zbx_dbstr('%'.self::escapeLike($search).'%');
			$sql .= ' AND (actor_username LIKE '.$like.' OR target_username LIKE '.$like.
				' OR clientip LIKE '.$like.' OR reason LIKE '.$like.')';
		}

		if ($target_userid > 0) {
			$sql .= ' AND target_userid='.\zbx_dbstr((string) $target_userid);
		}

		$sql .= ' ORDER BY started DESC, logid DESC';

		$rows = [];
		$result = \DBselect($sql, $limit);

		while ($row = \DBfetch($result)) {
			// O token de origem NUNCA sai deste helper.
			unset($row['origin_sessionid']);
			$rows[] = $row;
		}

		return $rows;
	}

	// -----------------------------------------------------------------------
	// Protecao do sessionid de origem em repouso
	// -----------------------------------------------------------------------

	/**
	 * Cifra o sessionid de origem antes de gravar no banco.
	 *
	 * Enquanto a impersonacao esta ativa, esse valor e um token de sessao Super
	 * Admin VALIDO. Em texto claro, qualquer SELECT no banco (DBA, backup, SQLi
	 * em outro ponto do frontend) resultaria em sequestro de sessao privilegiada.
	 *
	 * A chave e derivada do segredo de sessao do proprio frontend via
	 * CEncryptHelper::sign() - assim nao ha segredo novo para gerenciar, e um dump
	 * do banco sozinho nao basta para decifrar.
	 */
	private static function protectSessionid(string $sessionid): string {
		if ($sessionid === '' || !function_exists('openssl_encrypt')) {
			return $sessionid;
		}

		$key = self::cryptoKey();

		if ($key === '') {
			return $sessionid;
		}

		try {
			$iv = random_bytes(16);
			$cipher = openssl_encrypt($sessionid, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
		}
		catch (\Throwable $e) {
			self::debug('protectSessionid: '.$e->getMessage());

			return $sessionid;
		}

		return $cipher === false ? $sessionid : self::ENC_PREFIX.base64_encode($iv.$cipher);
	}

	/**
	 * Decifra o valor lido do banco. Valores sem o prefixo sao de instalacoes
	 * anteriores a 1.2.0 (texto claro) e passam direto.
	 */
	private static function revealSessionid(string $stored): string {
		if ($stored === '' || strncmp($stored, self::ENC_PREFIX, strlen(self::ENC_PREFIX)) !== 0) {
			return $stored;
		}

		$raw = base64_decode(substr($stored, strlen(self::ENC_PREFIX)), true);

		if ($raw === false || strlen($raw) <= 16 || !function_exists('openssl_decrypt')) {
			return '';
		}

		$key = self::cryptoKey();

		if ($key === '') {
			return '';
		}

		$plain = openssl_decrypt(substr($raw, 16), 'aes-256-cbc', $key, OPENSSL_RAW_DATA, substr($raw, 0, 16));

		if ($plain === false) {
			self::debug('revealSessionid: falha ao decifrar (chave de sessao do frontend mudou?)');

			return '';
		}

		return $plain;
	}

	private static function cryptoKey(): string {
		try {
			$material = \CEncryptHelper::sign(self::LOG_TABLE.'|origin_sessionid');
		}
		catch (\Throwable $e) {
			self::debug('cryptoKey: '.$e->getMessage());

			return '';
		}

		return (is_string($material) && $material !== '') ? hash('sha256', $material, true) : '';
	}

	// -----------------------------------------------------------------------
	// Modo somente-leitura
	// -----------------------------------------------------------------------

	/**
	 * A action informada e considerada escrita?
	 *
	 * Modo "blacklist" (default):
	 *   1. Lista explicita (WRITE_ACTIONS) - cobre nomes sem verbo reconhecivel
	 *      (popup.scriptexec) e paginas legadas .php, onde CLegacyAction::getAction()
	 *      devolve "jsrpc.php" e o ultimo segmento e sempre "php".
	 *   2. Qualquer SEGMENTO do nome batendo em WRITE_SUFFIXES. Olhar so o ultimo
	 *      segmento deixaria passar popup.massupdate.host / popup.massupdate.item,
	 *      que sao justamente as acoes de escrita em massa.
	 *   Navegacao continua livre: *.view, *.list, *.edit, *.get, *.check.
	 *
	 * Modo "whitelist" (default-deny): a action so passa se algum segmento estiver
	 * em READ_SUFFIXES. Mais seguro contra verbos novos que apareçam num upgrade do
	 * Zabbix, mas pode recusar leitura legitima - o que distorce a tela e atrapalha
	 * o troubleshooting. Use quando a trava importar mais que a fidelidade da visao.
	 *
	 * @param string   $action
	 * @param string[] $extra_suffixes  Verbos adicionais tratados como escrita.
	 * @param string   $mode            'blacklist' | 'whitelist'
	 */
	public static function isWriteAction(string $action, array $extra_suffixes = [],
			string $mode = 'blacklist'): bool {

		if ($action === '') {
			return false;
		}

		$action = strtolower($action);

		if (in_array($action, self::WRITE_ACTIONS, true)) {
			return true;
		}

		$segments = explode('.', $action);

		if ($mode === 'whitelist') {
			// Demais paginas legadas (.php) sao leitura: chart*.php, history.php, image.php...
			foreach ($segments as $segment) {
				if (in_array($segment, self::READ_SUFFIXES, true)) {
					return false;
				}
			}

			return true;
		}

		if (substr($action, -4) === '.php') {
			return false;
		}

		$suffixes = array_merge(self::WRITE_SUFFIXES, array_map('strtolower', $extra_suffixes));

		foreach ($segments as $segment) {
			if (in_array($segment, $suffixes, true)) {
				return true;
			}
		}

		return false;
	}

	// -----------------------------------------------------------------------
	// Natureza da request
	// -----------------------------------------------------------------------

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

	/**
	 * A request atual e um carregamento de PAGINA completa?
	 *
	 * Motivo de existir: cada widget de dashboard e uma request propria
	 * (widget.problems.view, widget.svggraph.view, ...) que passa pelo init() do
	 * modulo, e o layout.json serializa as mensagens do CMessageHelper na
	 * resposta. Sem este filtro, o banner "IMPERSONACAO ATIVA" aparecia DENTRO de
	 * cada widget da tela, com contagens regressivas diferentes em cada um, e
	 * voltava a cada refresh automatico do dashboard.
	 *
	 * O nome da action e o discriminador confiavel aqui: nem todo fetch de widget
	 * manda X-Requested-With, entao isNonHtmlRequest() sozinho nao resolve.
	 */
	public static function isPageRequest(): bool {
		if (self::isNonHtmlRequest()) {
			return false;
		}

		$action = strtolower((string) ($_REQUEST['action'] ?? ''));

		if ($action === '') {
			// index.php, zabbix.php sem action - pagina de verdade.
			return true;
		}

		foreach (['widget.', 'dashboard.widget.', 'popup.', 'menu.'] as $prefix) {
			if (strncmp($action, $prefix, strlen($prefix)) === 0) {
				return false;
			}
		}

		foreach (['.refresh', '.get', '.check', '.rank', '.progress'] as $suffix) {
			if (substr($action, -strlen($suffix)) === $suffix) {
				return false;
			}
		}

		return true;
	}

	// -----------------------------------------------------------------------
	// Formatacao
	// -----------------------------------------------------------------------

	/**
	 * Neutraliza os wildcards de LIKE no texto digitado pelo usuario.
	 *
	 * zbx_dbstr() cuida da injecao, mas nao de "%" e "_": sem isso, buscar por
	 * "_" no log retorna todas as linhas.
	 */
	public static function escapeLike(string $term): string {
		return str_replace(['\\', '%', '_'], ['\\\\', '\%', '\_'], $term);
	}

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
