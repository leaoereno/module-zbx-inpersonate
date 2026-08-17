<?php declare(strict_types=1);
/**
 * Impersonate - diagnostico de um dashboard para um usuario (AJAX / layout.json).
 *
 * Autor: Rafael M. A. Leao Ereno - MALE
 */

namespace Modules\ZbxImpersonate\Actions;

use CController;
use CControllerResponseData;
use Modules\ZbxImpersonate\Helper\ImpersonateHelper;
use Modules\ZbxImpersonate\Helper\DashboardDiagnostics;

class ImpersonateDashDiag extends CController {

	protected function init(): void {
		$this->disableCsrfValidation();
	}

	protected function checkInput(): bool {
		$ret = $this->validateInput([
			'userid'      => 'required|db users.userid',
			'dashboardid' => 'required|db dashboard.dashboardid'
		]);

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

		$report = DashboardDiagnostics::analyze($userid, (int) $this->getInput('dashboardid'));

		if (array_key_exists('error', $report)) {
			$this->respond(['success' => false, 'error' => (string) $report['error']]);

			return;
		}

		$this->respond([
			'success'  => true,
			'error'    => '',
			'username' => (string) $user['username'],
			'role'     => (string) $user['role_name'],
			'report'   => $report
		]);
	}

	private function respond(array $payload): void {
		$this->setResponse(new CControllerResponseData(['payload' => $payload]));
	}
}
