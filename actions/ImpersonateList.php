<?php declare(strict_types=1);
/**
 * Impersonate - tela principal: lista de usuarios impersonaveis.
 *
 * Autor: Rafael M. A. Leao Ereno - MALE
 */

namespace Modules\ZbxImpersonate\Actions;

use CController;
use CControllerResponseData;
use Modules\ZbxImpersonate\Helper\ImpersonateHelper;

class ImpersonateList extends CController {

	protected function init(): void {
		$this->disableCsrfValidation();
	}

	protected function checkInput(): bool {
		return $this->validateInput([
			'search'    => 'string',
			'show_type' => 'in 0,1,2,3'
		]);
	}

	protected function checkPermissions(): bool {
		// users.type nao existe como coluna - usar sempre getUserType().
		return $this->getUserType() == USER_TYPE_SUPER_ADMIN;
	}

	protected function doAction(): void {
		$search = trim((string) $this->getInput('search', ''));
		$show_type = (int) $this->getInput('show_type', 0);

		$self_userid = (int) \CWebUser::$data['userid'];

		$config = $this->getModuleConfig();

		$sql = 'SELECT u.userid,u.username,u.name,u.surname,u.roleid,u.userdirectoryid,u.attempt_failed,'.
				'r.name AS role_name,r.type AS role_type'.
			' FROM users u'.
			' LEFT JOIN role r ON r.roleid=u.roleid'.
			' WHERE 1=1';

		if ($search !== '') {
			$like = \zbx_dbstr('%'.$search.'%');
			$sql .= ' AND (u.username LIKE '.$like.' OR u.name LIKE '.$like.' OR u.surname LIKE '.$like.')';
		}

		if ($show_type > 0) {
			$sql .= ' AND r.type='.\zbx_dbstr((string) $show_type);
		}

		$sql .= ' ORDER BY u.username';

		$users = [];
		$result = \DBselect($sql, 1000);

		while ($row = \DBfetch($result)) {
			$row['userid'] = (int) $row['userid'];
			$row['role_type'] = $row['role_type'] === null ? null : (int) $row['role_type'];
			$row['groups'] = [];
			$row['disabled'] = false;
			$row['gui_disabled'] = false;
			$row['lastaccess'] = 0;
			$row['is_self'] = ($row['userid'] === $self_userid);
			$row['can_impersonate'] = true;
			$row['block_reason'] = '';

			$users[$row['userid']] = $row;
		}

		$roles_missing_access = [];

		if ($users) {
			$this->attachGroups($users);
			$this->attachLastAccess($users);
			$this->applyPolicy($users, $self_userid, $config, $roles_missing_access);
		}

		$stats = [
			'total'       => count($users),
			'impersonable' => 0,
			'blocked'     => 0
		];

		foreach ($users as $user) {
			if ($user['can_impersonate']) {
				$stats['impersonable']++;
			}
			else {
				$stats['blocked']++;
			}
		}

		sort($roles_missing_access);

		$this->setResponse(new CControllerResponseData([
			'users'                => array_values($users),
			'search'               => $search,
			'show_type'            => $show_type,
			'stats'                => $stats,
			'config'               => $config,
			'roles_missing_access' => $roles_missing_access,
			'recent'               => ImpersonateHelper::getLog(10)
		]));
	}

	// -----------------------------------------------------------------------

	private function getModuleConfig(): array {
		$module = \APP::ModuleManager()->getModule('zbx-impersonate');

		$ttl = ImpersonateHelper::DEFAULT_TTL;
		$readonly = 1;
		$block_sa = 1;
		$require_access = 1;
		$moduleid = '';
		$version = '?';

		if ($module !== null) {
			$ttl = (int) $module->getOption('session_ttl', ImpersonateHelper::DEFAULT_TTL);
			$readonly = (int) $module->getOption('readonly', 1);
			$block_sa = (int) $module->getOption('block_super_admin_target', 1);
			$require_access = (int) $module->getOption('require_module_access', 1);
			$moduleid = $module->getModuleId();
			$version = $module->getVersion();
		}

		return [
			'session_ttl'              => $ttl,
			'readonly'                 => $readonly,
			'block_super_admin_target' => $block_sa,
			'require_module_access'    => $require_access,
			'moduleid'                 => $moduleid,
			'version'                  => $version,
			// Atras do F5 os dois frontends respondem alternadamente. Sem saber QUAL
			// no serviu a pagina, "atualizei e nao mudou nada" vira caca ao fantasma.
			'hostname'                 => (string) gethostname()
		];
	}

	private function attachGroups(array &$users): void {
		$result = \DBselect(
			'SELECT ug.userid,g.name,g.users_status,g.gui_access'.
			' FROM users_groups ug'.
			' JOIN usrgrp g ON g.usrgrpid=ug.usrgrpid'.
			' WHERE '.\dbConditionId('ug.userid', array_keys($users)).
			' ORDER BY g.name'
		);

		while ($row = \DBfetch($result)) {
			$userid = (int) $row['userid'];

			if (!array_key_exists($userid, $users)) {
				continue;
			}

			$users[$userid]['groups'][] = (string) $row['name'];

			if ((int) $row['users_status'] == GROUP_STATUS_DISABLED) {
				$users[$userid]['disabled'] = true;
			}

			if ((int) $row['gui_access'] == GROUP_GUI_ACCESS_DISABLED) {
				$users[$userid]['gui_disabled'] = true;
			}
		}
	}

	private function attachLastAccess(array &$users): void {
		$result = \DBselect(
			'SELECT userid,MAX(lastaccess) AS lastaccess'.
			' FROM sessions'.
			' WHERE '.\dbConditionId('userid', array_keys($users)).
			' GROUP BY userid'
		);

		while ($row = \DBfetch($result)) {
			$userid = (int) $row['userid'];

			if (array_key_exists($userid, $users)) {
				$users[$userid]['lastaccess'] = (int) $row['lastaccess'];
			}
		}
	}

	/**
	 * Aplica as travas do modulo linha a linha, para a tela ja mostrar o motivo
	 * do bloqueio em vez de deixar o usuario descobrir clicando.
	 */
	private function applyPolicy(array &$users, int $self_userid, array $config,
			array &$roles_missing_access): void {

		// Cache por roleid: sem isso seria uma chamada de API por usuario listado.
		$module_access = [];

		foreach ($users as $userid => $user) {
			$reason = '';

			if ($user['is_self']) {
				$reason = 'Voce mesmo';
			}
			elseif ($user['username'] === ZBX_GUEST_USER) {
				$reason = 'Usuario guest';
			}
			elseif ($user['role_type'] === null || (int) $user['roleid'] === 0) {
				$reason = 'Sem role atribuida';
			}
			elseif ($config['block_super_admin_target'] == 1 && $user['role_type'] === USER_TYPE_SUPER_ADMIN) {
				$reason = 'Super Admin (bloqueado por politica)';
			}
			elseif ($user['gui_disabled']) {
				$reason = 'GUI access desabilitado';
			}
			elseif ($user['disabled']) {
				$reason = 'Usuario desabilitado';
			}
			elseif ($config['require_module_access'] == 1 && $config['moduleid'] !== '') {
				$roleid = (string) $user['roleid'];

				if (!array_key_exists($roleid, $module_access)) {
					$module_access[$roleid] = ImpersonateHelper::roleHasModuleAccess($roleid, $config['moduleid']);
				}

				if (!$module_access[$roleid]) {
					$reason = 'Role sem acesso ao modulo Impersonate';
					$roles_missing_access[(string) $user['role_name']] = true;
				}
			}

			if ($reason !== '') {
				$users[$userid]['can_impersonate'] = false;
				$users[$userid]['block_reason'] = $reason;
			}
		}

		$roles_missing_access = array_keys($roles_missing_access);
	}
}
