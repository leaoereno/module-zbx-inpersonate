<?php declare(strict_types=1);
/**
 * Impersonate - inicia a impersonacao (AJAX / layout.json).
 *
 * Autor: Rafael M. A. Leao Ereno - MALE
 */

namespace Modules\ZbxImpersonate\Actions;

use CController;
use CControllerResponseData;
use Modules\ZbxImpersonate\Helper\ImpersonateHelper;

class ImpersonateStart extends CController {

	protected function init(): void {
		// O CSRF do Zabbix e substituido aqui por uma checagem propria: POST
		// obrigatorio + header X-Requested-With. Header customizado nao pode ser
		// enviado cross-origin sem preflight CORS, entao serve como anti-CSRF.
		$this->disableCsrfValidation();
	}

	protected function checkInput(): bool {
		$ret = $this->validateInput([
			'userid'        => 'required|db users.userid',
			'submit_action' => 'string'
		]);

		// Endpoint layout.json precisa responder JSON tambem quando o input e invalido.
		if (!$ret) {
			$this->respond(false, 'Parametros invalidos.');
		}

		return $ret;
	}

	protected function checkPermissions(): bool {
		return $this->getUserType() == USER_TYPE_SUPER_ADMIN;
	}

	protected function doAction(): void {
		if (!\isRequestMethod('post') || !ImpersonateHelper::isAjaxRequest()) {
			$this->respond(false, 'Requisicao invalida: use POST via XMLHttpRequest.');

			return;
		}

		$module = \APP::ModuleManager()->getModule('zbx-impersonate');

		if ($module === null) {
			$this->respond(false, 'Modulo Impersonate nao esta carregado.');

			return;
		}

		$ttl = (int) $module->getOption('session_ttl', ImpersonateHelper::DEFAULT_TTL);
		$readonly = (int) $module->getOption('readonly', 1) === 1;
		$block_sa = (int) $module->getOption('block_super_admin_target', 1) === 1;
		$require_access = (int) $module->getOption('require_module_access', 1) === 1;

		$result = ImpersonateHelper::start((int) $this->getInput('userid'), $ttl, $readonly, $block_sa,
			$require_access, $module->getModuleId()
		);

		if (!$result['success']) {
			$this->respond(false, (string) $result['error']);

			return;
		}

		$this->respond(true, '', [
			'redirect' => (new \CUrl('zabbix.php'))->setArgument('action', 'dashboard.view')->getUrl(),
			'target'   => (string) $result['target']['username']
		]);
	}

	private function respond(bool $success, string $error, array $extra = []): void {
		$this->setResponse(new CControllerResponseData([
			'payload' => ['success' => $success, 'error' => $error] + $extra
		]));
	}
}
