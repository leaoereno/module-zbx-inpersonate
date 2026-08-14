<?php declare(strict_types=1);
/**
 * Impersonate - perfil completo do usuario, somente leitura (AJAX / layout.json).
 *
 * Mostra tudo que o Super Admin normalmente teria que garimpar em varias telas:
 * role e regras, grupos, permissoes efetivas em host groups, medias, sessoes
 * ativas e historico de impersonacao - sem trocar de sessao.
 *
 * Autor: Rafael M. A. Leao Ereno - MALE
 */

namespace Modules\ZbxImpersonate\Actions;

use CController;
use CControllerResponseData;
use Modules\ZbxImpersonate\Helper\ImpersonateHelper;

class ImpersonateProfile extends CController {

	protected function init(): void {
		$this->disableCsrfValidation();
	}

	protected function checkInput(): bool {
		$ret = $this->validateInput([
			'userid' => 'required|db users.userid'
		]);

		// Sem isso, input invalido cai em CControllerResponseFatal e o Zabbix devolve
		// HTML para um endpoint layout.json - o r.json() do front estoura com
		// SyntaxError e o usuario nunca ve o motivo real.
		if (!$ret) {
			$this->setResponse(new CControllerResponseData([
				'payload' => ['success' => false, 'error' => 'Parametros invalidos.']
			]));
		}

		return $ret;
	}

	protected function checkPermissions(): bool {
		return $this->getUserType() == USER_TYPE_SUPER_ADMIN;
	}

	protected function doAction(): void {
		$userid = (int) $this->getInput('userid');
		$user = ImpersonateHelper::getUser($userid);

		if ($user === null) {
			$this->setResponse(new CControllerResponseData([
				'payload' => ['success' => false, 'error' => 'Usuario nao encontrado.']
			]));

			return;
		}

		$groups = ImpersonateHelper::getUserGroups($userid);
		$perms = ImpersonateHelper::getHostGroupPermissions($userid);
		$medias = ImpersonateHelper::getUserMedias($userid);
		$sessions = ImpersonateHelper::getActiveSessions($userid);
		$rules = ImpersonateHelper::getRoleRules((string) $user['roleid']);
		$history = ImpersonateHelper::getLog(20, '', $userid);

		$ui_allowed = [];
		$ui_denied = [];
		$actions_allowed = [];
		$modules_denied = [];

		foreach ($rules as $rule) {
			$name = (string) $rule['name'];
			$allowed = (int) $rule['value_int'] === 1;

			if (strpos($name, 'ui.') === 0 && $name !== 'ui.default_access') {
				if ($allowed) {
					$ui_allowed[] = substr($name, 3);
				}
				else {
					$ui_denied[] = substr($name, 3);
				}
			}
			elseif (strpos($name, 'actions.') === 0 && $name !== 'actions.default_access' && $allowed) {
				$actions_allowed[] = substr($name, 8);
			}
			elseif (strpos($name, 'modules.module.') === 0 && !$allowed) {
				$modules_denied[] = substr($name, 15);
			}
		}

		$disabled = false;
		$gui_disabled = false;

		foreach ($groups as $group) {
			if ((int) $group['users_status'] == GROUP_STATUS_DISABLED) {
				$disabled = true;
			}

			if ((int) $group['gui_access'] == GROUP_GUI_ACCESS_DISABLED) {
				$gui_disabled = true;
			}
		}

		$this->setResponse(new CControllerResponseData([
			'payload' => [
				'success' => true,
				'user' => [
					'userid'          => (int) $user['userid'],
					'username'        => (string) $user['username'],
					'fullname'        => trim((string) $user['name'].' '.(string) $user['surname']),
					'role_name'       => (string) $user['role_name'],
					'role_type'       => (int) $user['role_type'],
					'role_type_label' => ImpersonateHelper::userTypeLabel((int) $user['role_type']),
					'lang'            => (string) $user['lang'],
					'theme'           => (string) $user['theme'],
					'timezone'        => (string) $user['timezone'],
					'autologin'       => (int) $user['autologin'],
					'autologout'      => (string) $user['autologout'],
					'refresh'         => (string) $user['refresh'],
					'rows_per_page'   => (int) $user['rows_per_page'],
					'url'             => (string) $user['url'],
					'provisioned'     => (int) $user['userdirectoryid'] > 0,
					'attempt_failed'  => (int) $user['attempt_failed'],
					'attempt_ip'      => (string) $user['attempt_ip'],
					'attempt_clock'   => ImpersonateHelper::formatTs((int) $user['attempt_clock']),
					'disabled'        => $disabled,
					'gui_disabled'    => $gui_disabled
				],
				'groups' => array_map(static function (array $g): array {
					return [
						'name'         => (string) $g['name'],
						'users_status' => (int) $g['users_status'] == GROUP_STATUS_DISABLED ? 'Disabled' : 'Enabled',
						'gui_access'   => (int) $g['gui_access'] == GROUP_GUI_ACCESS_DISABLED
							? 'Disabled'
							: 'Enabled',
						'debug_mode'   => (int) $g['debug_mode'] == GROUP_DEBUG_MODE_ENABLED ? 'On' : 'Off'
					];
				}, $groups),
				'permissions' => array_map(static function (array $p): array {
					return [
						'name'       => (string) $p['name'],
						'permission' => ImpersonateHelper::permissionLabel((int) $p['permission'])
					];
				}, $perms),
				'medias' => array_map(static function (array $m): array {
					return [
						'media_type' => (string) $m['media_type'],
						'sendto'     => (string) $m['sendto'],
						'active'     => (int) $m['active'] === 0 ? 'Enabled' : 'Disabled',
						'period'     => (string) $m['period'],
						'mt_status'  => (int) $m['mt_status'] === 0 ? 'Enabled' : 'Disabled'
					];
				}, $medias),
				'sessions' => array_map(static function (array $s): array {
					return [
						'sessionid'  => (string) $s['sessionid'],
						'lastaccess' => ImpersonateHelper::formatTs((int) $s['lastaccess'])
					];
				}, $sessions),
				'role_rules' => [
					'ui_allowed'      => $ui_allowed,
					'ui_denied'       => $ui_denied,
					'actions_allowed' => $actions_allowed,
					'modules_denied'  => $modules_denied
				],
				'history' => array_map(static function (array $h): array {
					return [
						'actor_username' => (string) $h['actor_username'],
						'started'        => ImpersonateHelper::formatTs((int) $h['started']),
						'ended'          => ImpersonateHelper::formatTs((int) $h['ended']),
						'end_reason'     => (string) $h['end_reason'],
						'readonly'       => (int) $h['readonly'] === 1
					];
				}, $history)
			]
		]));
	}
}
