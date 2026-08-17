<?php declare(strict_types=1);
/**
 * Impersonate - dashboards visiveis para um usuario (AJAX / layout.json).
 *
 * Autor: Rafael M. A. Leao Ereno - MALE
 */

namespace Modules\ZbxImpersonate\Actions;

use CController;
use CControllerResponseData;
use Modules\ZbxImpersonate\Helper\ImpersonateHelper;
use Modules\ZbxImpersonate\Helper\DashboardDiagnostics;

class ImpersonateDashboards extends CController {

	protected function init(): void {
		$this->disableCsrfValidation();
	}

	protected function checkInput(): bool {
		$ret = $this->validateInput([
			'userid' => 'required|db users.userid'
		]);

		// Endpoint layout.json tem que responder JSON tambem com input invalido -
		// senao o r.json() do front estoura com SyntaxError e o usuario nunca ve o
		// motivo real.
		if (!$ret) {
			$this->respond(['success' => false, 'error' => 'Parametros invalidos.']);
		}

		return $ret;
	}

	protected function checkPermissions(): bool {
		return $this->getUserType() == USER_TYPE_SUPER_ADMIN;
	}

	protected function doAction(): void {
		if (!\isRequestMethod('post') || !ImpersonateHelper::isAjaxRequest()) {
			$this->respond(['success' => false, 'error' => 'Requisicao invalida: use POST via XMLHttpRequest.']);

			return;
		}

		$userid = (int) $this->getInput('userid');
		$user = ImpersonateHelper::getUser($userid);

		if ($user === null) {
			$this->respond(['success' => false, 'error' => 'Usuario nao encontrado.']);

			return;
		}

		$this->respond([
			'success'    => true,
			'error'      => '',
			'username'   => (string) $user['username'],
			'dashboards' => DashboardDiagnostics::listDashboards($userid)
		]);
	}

	private function respond(array $payload): void {
		$this->setResponse(new CControllerResponseData(['payload' => $payload]));
	}
}
