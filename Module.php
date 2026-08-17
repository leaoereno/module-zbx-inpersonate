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

	/** Tamanho maximo do username no rotulo do menu antes de truncar. */
	private const MENU_LABEL_MAX = 18;

	/**
	 * Chamado a cada request enquanto o modulo estiver habilitado.
	 *
	 * Nao existe hook onEnable()/onDisable() no core do Zabbix, entao tudo que
	 * precisa valer "sempre" (expiracao da impersonacao, banner, menu) mora aqui.
	 * DDL/DML pesado NAO entra aqui - o schema e criado sob demanda pelas actions.
	 */
	public function init(): void {
		try {
			ImpersonateHelper::setDebug(
				(int) ImpersonateHelper::option('debug', 0) === 1,
				(string) ImpersonateHelper::option('debug_file', '')
			);

			$action = (string) ($_REQUEST['action'] ?? '');

			// Armado antes de qualquer coisa: um fatal que aconteca DEPOIS daqui -
			// no proprio init(), na action, ou na renderizacao da resposta - fica
			// registrado. E o unico jeito de ver 500 que nao passa por try/catch.
			ImpersonateHelper::installFatalTrap($action !== '' ? $action : 'sem-action');

			// Nas telas DO MODULO, com debug ligado, o erro tambem vai para a tela.
			// Num frontend onde o PHP descarta os proprios erros, e a unica forma de
			// ver a mensagem real por tras de um 500 de corpo vazio. Restrito a
			// zbx.impersonate.* para nao vazar notice dentro do JSON dos widgets.
			if (strncmp($action, 'zbx.impersonate.', strlen('zbx.impersonate.')) === 0) {
				ImpersonateHelper::forceErrorDisplay();
			}

			$state = ImpersonateHelper::getState();

			if ($state !== null) {
				$this->handleActiveImpersonation($state);
			}
			else {
				$this->addSuperAdminMenu();
			}
		}
		catch (\Throwable $e) {
			// Nunca derrubar o frontend inteiro por causa do modulo - mas tambem
			// nao engolir o motivo em silencio (option "debug" no manifest).
			ImpersonateHelper::debug('init: '.$e->getMessage().' @ '.$e->getFile().':'.$e->getLine());
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

			if ($state === null) {
				return;
			}

			$action_name = (string) $action->getAction();

			// Sair da impersonacao nunca pode ser bloqueado.
			if ($action_name === 'zbx.impersonate.stop') {
				return;
			}

			// "Sign out" nativo continua na sidebar durante a impersonacao. Se o
			// usuario sair por ali, o evento tem que ser fechado no log e a sessao
			// Super Admin de origem apagada - senao sobra linha com ended=0 para
			// sempre e um token privilegiado orfao no banco.
			if ((int) ImpersonateHelper::option('stop_on_logout', 1) === 1
					&& ImpersonateHelper::isLogoutRequest($action_name)) {
				ImpersonateHelper::abandon(ImpersonateHelper::END_LOGOUT);

				return;
			}

			if ((int) $state['readonly'] !== 1) {
				return;
			}

			$extra = ImpersonateHelper::option('readonly_extra_suffixes', []);
			$mode = (string) ImpersonateHelper::option('readonly_mode', 'blacklist');

			if (!ImpersonateHelper::isWriteAction($action_name, is_array($extra) ? $extra : [], $mode)) {
				return;
			}

			// Detalhe completo vai para o log; a tela recebe algo curto - a mensagem
			// longa da versao anterior ficava enorme dentro de widgets e popups.
			ImpersonateHelper::debug(sprintf(
				'readonly deny: action=%s target=%s origin=%s mode=%s',
				$action_name, (string) $state['target_username'], (string) $state['origin_username'], $mode
			));

			$deny_message = sprintf(
				'Impersonate: sessao em modo somente leitura (navegando como "%s"). A acao "%s" altera dados'.
					' e foi recusada.',
				(string) $state['target_username'],
				$action_name
			);
		}
		catch (\Throwable $e) {
			// Falha interna do guard nao pode virar tela branca nem bloquear navegacao.
			ImpersonateHelper::debug('onBeforeAction: '.$e->getMessage());

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

		$this->addBanner($state, $expires);
		$this->addExitMenuItem($state);
	}

	/**
	 * Banner de aviso no topo da pagina.
	 *
	 * Restrito a carregamento de PAGINA (ImpersonateHelper::isPageRequest()). Cada
	 * widget de dashboard e uma request propria que tambem passa por aqui, e o
	 * layout.json serializa as mensagens do CMessageHelper na resposta - por isso a
	 * versao anterior repetia o banner dentro de todo widget da tela, com contagens
	 * regressivas diferentes, e ele reaparecia a cada refresh automatico.
	 *
	 * Para uma tela 100% identica a do usuario (troubleshooting pixel a pixel),
	 * basta "banner": 0 no manifest - o item de menu continua sendo a saida.
	 */
	private function addBanner(array $state, int $expires): void {
		if ((int) ImpersonateHelper::option('banner', 1) !== 1 || !ImpersonateHelper::isPageRequest()) {
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
	}

	/**
	 * Item "Sair da impersonacao" no topo do menu lateral.
	 *
	 * Adicionado em TODA request (nao so nas de pagina): e a unica saida garantida
	 * e nao depende de JS.
	 */
	private function addExitMenuItem(array $state): void {
		if ((int) ImpersonateHelper::option('menu_exit_item', 1) !== 1) {
			return;
		}

		$menu = \APP::Component()->get('menu.main');
		$username = (string) $state['target_username'];

		// Username longo (e-mail, tipicamente) estoura a largura da sidebar.
		$short = mb_strlen($username) > self::MENU_LABEL_MAX
			? mb_substr($username, 0, self::MENU_LABEL_MAX - 1).'...'
			: $username;

		// _('Dashboards') e nao a string crua: o rotulo do menu nativo vem traduzido
		// para o idioma do usuario. Se nao casar, insertBefore() cai na posicao 0,
		// que tambem e o topo - entao o item aparece no lugar certo de qualquer jeito.
		$menu->insertBefore(_('Dashboards'),
			(new CMenuItem(sprintf('Sair da impersonacao (%s)', $short)))
				->setAction('zbx.impersonate.stop')
				->setIcon('zi-sign-out')
				->setTitle(sprintf('Encerrar a impersonacao de "%s" e voltar para "%s"',
					$username, (string) $state['origin_username']
				))
		);
	}

	/**
	 * Menu normal do Super Admin (sem impersonacao ativa).
	 *
	 * O item entra dentro da secao nativa de usuarios do Zabbix.
	 */
	private function addSuperAdminMenu(): void {
		if (\CWebUser::getType() != USER_TYPE_SUPER_ADMIN) {
			return;
		}

		$menu = \APP::Component()->get('menu.main');

		// CMenu::find() compara pelo ROTULO VISIVEL, e o CMenuHelper monta a secao
		// nativa com _('Users') - ou seja, "Usuarios" num frontend em pt-BR.
		// Procurar pela string crua 'Users' nao casa e o findOrAdd() acabaria
		// criando uma secao nova solta no fim da sidebar.
		$section = $menu->find(_('Users'));

		if ($section === null) {
			// Fallback para instalacoes em que o idioma da sessao nao bate com o
			// rotulo ja renderizado (ex.: usuario com lang diferente do default).
			foreach (['Users', 'Usuários', 'Usuarios'] as $label) {
				$section = $menu->find($label);

				if ($section !== null) {
					break;
				}
			}
		}

		if ($section === null) {
			$section = $menu->findOrAdd(_('Users'));
		}

		$submenu = $section->getSubMenu();

		$submenu->add($this->buildImpersonateMenuItem());
	}

	/**
	 * Item "Impersonate" dentro de Usuarios, com os dois destinos abaixo dele.
	 *
	 * Navegacao desejada:
	 *
	 *     Usuarios -> Impersonate -> Impersonate User
	 *                             -> Impersonate Logs
	 *
	 * A sidebar nativa do Zabbix trabalha com DOIS niveis (secao -> item); onde o
	 * core precisa de um terceiro, ele usa sub-navegacao dentro da propria pagina
	 * (Administration -> General e o exemplo). Entao aqui a hierarquia e tentada
	 * pelo caminho nativo, e as duas telas do modulo trazem as abas
	 * "Impersonate User" / "Impersonate Logs" de qualquer forma - assim a
	 * navegacao pedida existe mesmo que a sidebar ignore o terceiro nivel.
	 *
	 * O try/catch e proposital: setSubMenu()/CMenu nao sao API estavel entre
	 * versoes, e uma excecao aqui apagaria o menu inteiro do modulo (o init()
	 * engole Throwable). No pior caso cai para o item simples, que sempre funciona.
	 */
	private function buildImpersonateMenuItem(): CMenuItem {
		$item = (new CMenuItem('Impersonate'))->setAction('zbx.impersonate.list');

		try {
			$item->setSubMenu(new \CMenu([
				(new CMenuItem('Impersonate User'))->setAction('zbx.impersonate.list'),
				(new CMenuItem('Impersonate Logs'))->setAction('zbx.impersonate.log')
			]));
		}
		catch (\Throwable $e) {
			ImpersonateHelper::debug('menu: sidebar sem suporte a submenu - '.$e->getMessage());
		}

		return $item;
	}
}
