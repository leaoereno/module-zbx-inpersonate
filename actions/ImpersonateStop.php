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
use Modules\ZbxImpersonate\Helper\ImpersonateHelper;

class ImpersonateStop extends CController {

	/*
	 * CUIDADO AO MEXER NOS REDIRECTS DESTE ARQUIVO.
	 *
	 * No Zabbix 7.0 a assinatura e:
	 *
	 *     CControllerResponseRedirect::__construct(CUrl $location)
	 *
	 * O argumento e TIPADO como CUrl. Passar o resultado de ->getUrl(), que e
	 * string, lanca TypeError - e como isso acontece dentro do doAction(), o
	 * ZBase nao trata: vira "Uncaught TypeError", HTTP 500 de corpo vazio.
	 *
	 * Era exatamente esse o erro que quebrava a saida da impersonacao desde o
	 * primeiro commit do modulo. Passe o objeto CUrl, nunca ->getUrl().
	 *
	 * Nao confundir com a funcao global redirect($url), usada no Module.php,
	 * que continua recebendo string.
	 */

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

	/**
	 * A saida NUNCA pode falhar em aberto.
	 *
	 * Se qualquer coisa explodir aqui, o Super Admin fica preso na sessao do
	 * usuario alvo - sem tela de saida e, se o modo somente-leitura estiver
	 * ativo, sem poder fazer nada ate o autologout do Zabbix. Por isso o corpo
	 * inteiro roda dentro de um try: no pior caso o estado e limpo, a sessao e
	 * derrubada e o navegador vai para o login.
	 */
	protected function doAction(): void {
		try {
			$this->stopImpersonation();
		}
		catch (\Throwable $e) {
			ImpersonateHelper::debug(sprintf('stop FALHOU: %s @ %s:%d',
				$e->getMessage(), $e->getFile(), $e->getLine()
			));

			$this->bailOutToLogin();
		}
	}

	// -----------------------------------------------------------------------

	private function stopImpersonation(): void {
		$state = ImpersonateHelper::getState();

		if ($state === null) {
			\CMessageHelper::addWarning('Nao ha impersonacao ativa nesta sessao.');

			$this->setResponse(new CControllerResponseRedirect(
				(new \CUrl('zabbix.php'))->setArgument('action', 'dashboard.view')
			));

			return;
		}

		$origin_username = (string) $state['origin_username'];
		$target_username = (string) $state['target_username'];

		ImpersonateHelper::debug(sprintf('stop: iniciando (logid=%d, target=%s, origin=%s)',
			(int) $state['logid'], $target_username, $origin_username
		));

		$restored = ImpersonateHelper::stop(ImpersonateHelper::END_MANUAL);

		ImpersonateHelper::debug('stop: restored='.($restored ? '1' : '0'));

		if (!$restored) {
			// Nao ha para onde voltar: a sessao de origem expirou, foi derrubada, ou
			// o token guardado no log ficou ilegivel.
			//
			// Aqui NAO se renderiza pagina. O stop() ja fez CSessionHelper::unset()
			// - obrigatorio, senao o Super Admin ficaria logado como o alvo sem
			// nenhum estado de impersonacao, o que e uma troca silenciosa de
			// privilegio - e mandar o layout.htmlpage inteiro renderizar depois
			// disso e pedir para o frontend quebrar. So o redirect para o login.
			ImpersonateHelper::debug('stop: sem sessao de origem para restaurar - redirecionando para o login');

			$this->setResponse(new CControllerResponseRedirect(
				(new \CUrl('index.php'))->setArgument('reconnect', 1)
			));

			return;
		}

		\CMessageHelper::addSuccess(sprintf(
			'Impersonacao de "%s" encerrada. Sessao de "%s" restaurada.', $target_username, $origin_username
		));

		$this->setResponse(new CControllerResponseRedirect(
			(new \CUrl('zabbix.php'))->setArgument('action', 'zbx.impersonate.list')
		));
	}

	/**
	 * Ultimo recurso: sai da impersonacao a qualquer custo e manda para o login.
	 *
	 * De proposito sem CMessageHelper, sem view e sem nada que dependa de estado
	 * do frontend - e o caminho que roda justamente quando algo do frontend
	 * quebrou. Um redirect e so um header HTTP.
	 */
	private function bailOutToLogin(): void {
		try {
			ImpersonateHelper::clearState();
			\CSessionHelper::unset(['sessionid']);
		}
		catch (\Throwable $e) {
			// nada a fazer - o redirect abaixo ainda vale
		}

		$this->setResponse(new CControllerResponseRedirect(
			(new \CUrl('index.php'))->setArgument('reconnect', 1)
		));
	}
}
