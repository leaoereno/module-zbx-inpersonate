<?php declare(strict_types=1);
/**
 * Impersonate - modulo de troca de sessao (login as) para Zabbix 7.0 LTS.
 *
 * Autor: Rafael M. A. Leao Ereno - MALE
 */

namespace Modules\ZbxImpersonate;

use Zabbix\Core\CModule;
use CController as CAction;
use CMenuItem;
use Modules\ZbxImpersonate\Helper\ImpersonateHelper;

class Module extends CModule {

	/**
	 * Chamado a cada request enquanto o modulo estiver habilitado.
	 *
	 * Nao existe hook onEnable()/onDisable() no core do Zabbix, entao tudo que
	 * precisa valer "sempre" (expiracao da impersonacao, banner, menu) mora aqui.
	 * DDL/DML pesado NAO entra aqui - o schema e criado sob demanda pelas actions.
	 */
	public function init(): void {
		try {
			$state = ImpersonateHelper::getState();

			if ($state !== null) {
				$this->handleActiveImpersonation($state);
			}
			else {
				$this->addSuperAdminMenu();
			}
		}
		catch (\Throwable $e) {
			// Nunca derrubar o frontend inteiro por causa do modulo.
		}
	}

	/**
	 * Guard de somente-leitura. Roda logo antes de qualquer action do Zabbix
	 * (inclusive das paginas legadas .php, que passam por CLegacyAction).
	 *
	 * ATENCAO: nao cobre chamadas diretas a api_jsonrpc.php - o EXEC_MODE_API do
	 * ZBase nem carrega o module manager. Isso esta documentado no README.
	 */
	public function onBeforeAction(CAction $action): void {
		$deny_message = null;

		try {
			$state = ImpersonateHelper::getState();

			if ($state === null || (int) $state['readonly'] !== 1) {
				return;
			}

			$action_name = (string) $action->getAction();

			// Sair da impersonacao nunca pode ser bloqueado.
			if ($action_name === 'zbx.impersonate.stop') {
				return;
			}

			$extra = $this->getOption('readonly_extra_suffixes', []);

			if (!ImpersonateHelper::isWriteAction($action_name, is_array($extra) ? $extra : [])) {
				return;
			}

			$deny_message = sprintf(
				'Bloqueado pelo modulo Impersonate: a sessao esta em modo somente-leitura (impersonando "%s"'.
					' a partir de "%s"). A acao "%s" altera dados e foi recusada.',
				(string) $state['target_username'],
				(string) $state['origin_username'],
				$action_name
			);
		}
		catch (\Throwable $e) {
			// Falha interna do guard nao pode virar tela branca nem bloquear navegacao.
			return;
		}

		// Lancado FORA do try para nao ser engolido pelo proprio catch.
		// ZBase::processRequest() converte em tela de erro (ou {"error":{...}} em layout.json).
		throw new \Exception($deny_message);
	}

	// -----------------------------------------------------------------------

	/**
	 * Impersonacao ativa: checa expiracao, monta o banner e o menu de saida.
	 */
	private function handleActiveImpersonation(array $state): void {
		$expires = (int) $state['expires'];

		if ($expires > 0 && time() >= $expires) {
			ImpersonateHelper::stop(ImpersonateHelper::END_EXPIRED);

			// Em request AJAX/imagem nao adianta redirecionar (302 numa <img> quebra o
			// grafico): a sessao ja foi restaurada e o proximo carregamento de pagina
			// inteiro ja vem com o usuario original.
			if (ImpersonateHelper::isNonHtmlRequest()) {
				return;
			}

			// Mensagem via cookie - e o unico jeito de ela sobreviver ao redirect
			// (mesmo mecanismo que o CControllerResponseRedirect usa).
			\CCookieHelper::set('system-message-ok', sprintf(
				'A impersonacao de "%s" expirou e sua sessao original foi restaurada.',
				(string) $state['target_username']
			));

			\redirect((new \CUrl('zabbix.php'))->setArgument('action', 'zbx.impersonate.list')->getUrl());

			return;
		}

		$remaining = $expires > 0 ? $expires - time() : 0;

		\CMessageHelper::addWarning(sprintf(
			'IMPERSONACAO ATIVA - voce esta navegando como "%s" (sessao original: "%s"). Modo: %s.%s',
			(string) $state['target_username'],
			(string) $state['origin_username'],
			((int) $state['readonly'] === 1) ? 'somente leitura' : 'leitura e escrita',
			$expires > 0 ? ' Expira em '.ImpersonateHelper::formatDuration($remaining).'.' : ''
		));

		$menu = \APP::Component()->get('menu.main');

		$label = sprintf('Sair da impersonacao (%s)', (string) $state['target_username']);

		$menu->insertBefore('Dashboards',
			(new CMenuItem($label))
				->setAction('zbx.impersonate.stop')
				->setIcon('zi-user')
				->setTitle('Encerrar a impersonacao e voltar para '.(string) $state['origin_username'])
		);
	}

	/**
	 * Menu normal do Super Admin (sem impersonacao ativa).
	 */
	private function addSuperAdminMenu(): void {
		if (\CWebUser::getType() != USER_TYPE_SUPER_ADMIN) {
			return;
		}

		$submenu = \APP::Component()->get('menu.main')
			->findOrAdd('Users')
			->getSubMenu();

		$submenu->add((new CMenuItem('Impersonate'))->setAction('zbx.impersonate.list'));
		$submenu->add((new CMenuItem('Impersonate log'))->setAction('zbx.impersonate.log'));
	}
}
