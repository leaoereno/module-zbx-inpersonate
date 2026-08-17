<?php declare(strict_types=1);
/**
 * Impersonate - libera o modulo nas roles que ainda nao o enxergam (AJAX / layout.json).
 *
 * Autor: Rafael M. A. Leao Ereno - MALE
 */

namespace Modules\ZbxImpersonate\Actions;

use CController;
use CControllerResponseData;
use Modules\ZbxImpersonate\Helper\ImpersonateHelper;

class ImpersonateGrant extends CController {

	protected function init(): void {
		// Anti-CSRF proprio: POST + X-Requested-With (header custom nao atravessa
		// origem sem preflight CORS). Ver doAction().
		$this->disableCsrfValidation();
	}

	protected function checkInput(): bool {
		$ret = $this->validateInput([
			'dry_run'       => 'in 0,1',
			'submit_action' => 'string'
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

		// Nunca durante uma impersonacao ativa: a sessao corrente nao e a do
		// Super Admin de verdade, e alterar roles nesse estado seria registrado
		// em nome do usuario alvo no audit log.
		if (ImpersonateHelper::isImpersonating()) {
			$this->respond([
				'success' => false,
				'error'   => 'Encerre a impersonacao ativa antes de alterar permissoes de role.'
			]);

			return;
		}

		$module = \APP::ModuleManager()->getModule('zbx-impersonate');

		if ($module === null) {
			$this->respond(['success' => false, 'error' => 'Modulo Impersonate nao esta carregado.']);

			return;
		}

		// dry_run=1: nao altera nada, so devolve QUAIS roles seriam alteradas, para o
		// front confirmar nominalmente antes de mexer em permissoes.
		$dry_run = (int) $this->getInput('dry_run', 0) === 1;

		$result = ImpersonateHelper::grantModuleAccessToAllRoles($module->getModuleId(), [], $dry_run);

		if ($result['error'] !== '') {
			$this->respond(['success' => false, 'error' => $result['error']]);

			return;
		}

		$this->respond([
			'success'     => true,
			'error'       => '',
			'dry_run'     => $dry_run,
			'would_grant' => array_column($result['would_grant'], 'name'),
			'granted'     => $result['granted'],
			'already'     => $result['already'],
			'readonly'    => $result['readonly'],
			'failed'      => $result['failed']
		]);
	}

	private function respond(array $payload): void {
		$this->setResponse(new CControllerResponseData(['payload' => $payload]));
	}
}
