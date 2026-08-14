<?php declare(strict_types=1);
/**
 * Impersonate - encerra a impersonacao e devolve a sessao original.
 *
 * Esta action roda com a sessao do usuario IMPERSONADO (que pode ser um User
 * comum), entao checkPermissions() nao pode exigir Super Admin. A autorizacao
 * real vem do estado assinado guardado na sessao.
 *
 * Autor: Rafael M. A. Leao Ereno - MALE
 */

namespace Modules\ZbxImpersonate\Actions;

use CController;
use CControllerResponseRedirect;
use CControllerResponseData;
use Modules\ZbxImpersonate\Helper\ImpersonateHelper;

class ImpersonateStop extends CController {

	protected function init(): void {
		$this->disableCsrfValidation();
	}

	protected function checkInput(): bool {
		return $this->validateInput([]);
	}

	protected function checkPermissions(): bool {
		// Qualquer usuario autenticado pode sair de uma impersonacao ativa.
		// Sem estado valido na sessao a action nao faz nada (ver doAction).
		return (int) \CWebUser::$data['userid'] > 0;
	}

	protected function doAction(): void {
		$state = ImpersonateHelper::getState();

		if ($state === null) {
			\CMessageHelper::addWarning('Nao ha impersonacao ativa nesta sessao.');

			$this->setResponse(new CControllerResponseRedirect(
				(new \CUrl('zabbix.php'))->setArgument('action', 'dashboard.view')->getUrl()
			));

			return;
		}

		$origin_username = (string) $state['origin_username'];
		$target_username = (string) $state['target_username'];

		$restored = ImpersonateHelper::stop(ImpersonateHelper::END_MANUAL);

		if (!$restored) {
			// A sessao original ja tinha expirado - nao ha para onde voltar.
			$this->setResponse(new CControllerResponseData([
				'restored'        => false,
				'origin_username' => $origin_username,
				'target_username' => $target_username
			]));

			return;
		}

		\CMessageHelper::addSuccess(sprintf(
			'Impersonacao de "%s" encerrada. Sessao de "%s" restaurada.', $target_username, $origin_username
		));

		$this->setResponse(new CControllerResponseRedirect(
			(new \CUrl('zabbix.php'))->setArgument('action', 'zbx.impersonate.list')->getUrl()
		));
	}
}
