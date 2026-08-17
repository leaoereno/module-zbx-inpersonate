<?php declare(strict_types=1);
/**
 * Impersonate - diagnostico de dashboard.
 *
 * Responde a pergunta que sobra depois de impersonar: "o dashboard dele esta
 * cheio de erro; o que exatamente falta?".
 *
 * Le os widgets do dashboard, resolve TODO objeto que eles referenciam (host
 * group, host, item, grafico, mapa) e confronta com as permissoes efetivas do
 * usuario alvo, apontando o host group que falta e por qual grupo de usuario a
 * concessao passaria.
 *
 * SOMENTE LEITURA: nao altera permissao nenhuma.
 *
 * Autor: Rafael M. A. Leao Ereno - MALE
 */

namespace Modules\ZbxImpersonate\Helper;

class DashboardDiagnostics {

	/** Tipos de objeto referenciados por widget_field. */
	public const KIND_GROUP = 'Host group';
	public const KIND_HOST  = 'Host';
	public const KIND_ITEM  = 'Item';
	public const KIND_GRAPH = 'Grafico';
	public const KIND_MAP   = 'Mapa';

	/** Por que a referencia esta quebrada. */
	public const ST_MISSING = 'missing';
	public const ST_DENY    = 'deny';
	public const ST_NOPERM  = 'noperm';

	// -----------------------------------------------------------------------
	// Dashboards visiveis para o usuario
	// -----------------------------------------------------------------------

	/**
	 * Dashboards que o usuario alvo consegue abrir.
	 *
	 * Regra do Zabbix: o dono sempre ve; private=0 e publico; private=1 exige
	 * compartilhamento explicito em dashboard_user ou dashboard_usrgrp.
	 * Dashboards de template (templateid preenchido) ficam de fora - nao sao
	 * telas que um usuario abre.
	 */
	public static function listDashboards(int $userid): array {
		$usrgrpids = self::userGroupIds($userid);

		$conditions = [
			'd.userid='.\zbx_dbstr((string) $userid),
			'd.private=0',
			'EXISTS (SELECT 1 FROM dashboard_user du WHERE du.dashboardid=d.dashboardid'.
				' AND du.userid='.\zbx_dbstr((string) $userid).')'
		];

		if ($usrgrpids) {
			$conditions[] = 'EXISTS (SELECT 1 FROM dashboard_usrgrp dg WHERE dg.dashboardid=d.dashboardid'.
				' AND '.\dbConditionId('dg.usrgrpid', $usrgrpids).')';
		}

		$rows = [];
		$result = \DBselect(
			'SELECT d.dashboardid,d.name,d.private,d.userid AS owner_userid,u.username AS owner_username'.
			' FROM dashboard d'.
			' LEFT JOIN users u ON u.userid=d.userid'.
			' WHERE d.templateid IS NULL'.
				' AND ('.implode(' OR ', $conditions).')'.
			' ORDER BY d.name'
		);

		while ($row = \DBfetch($result)) {
			$rows[(int) $row['dashboardid']] = [
				'dashboardid'     => (int) $row['dashboardid'],
				'name'            => (string) $row['name'],
				'private'         => (int) $row['private'] === 1,
				'owner_username'  => (string) ($row['owner_username'] ?? '-'),
				'is_owner'        => (int) $row['owner_userid'] === $userid,
				'widgets'         => 0
			];
		}

		if ($rows) {
			self::attachWidgetCount($rows);
		}

		return array_values($rows);
	}

	private static function attachWidgetCount(array &$dashboards): void {
		$result = \DBselect(
			'SELECT dp.dashboardid,COUNT(w.widgetid) AS total'.
			' FROM dashboard_page dp'.
			' LEFT JOIN widget w ON w.dashboard_pageid=dp.dashboard_pageid'.
			' WHERE '.\dbConditionId('dp.dashboardid', array_keys($dashboards)).
			' GROUP BY dp.dashboardid'
		);

		while ($row = \DBfetch($result)) {
			$id = (int) $row['dashboardid'];

			if (array_key_exists($id, $dashboards)) {
				$dashboards[$id]['widgets'] = (int) $row['total'];
			}
		}
	}

	// -----------------------------------------------------------------------
	// Analise
	// -----------------------------------------------------------------------

	/**
	 * Analisa um dashboard sob a otica do usuario alvo.
	 *
	 * @return array  ['dashboard'=>..., 'ui_blocked'=>bool, 'summary'=>..., 'problems'=>[...]]
	 */
	public static function analyze(int $userid, int $dashboardid): array {
		$dashboard = \DBfetch(\DBselect(
			'SELECT dashboardid,name,private,userid FROM dashboard'.
			' WHERE dashboardid='.\zbx_dbstr((string) $dashboardid).
				' AND templateid IS NULL'
		));

		if (!$dashboard) {
			return ['error' => 'Dashboard nao encontrado.'];
		}

		$user = ImpersonateHelper::getUser($userid);

		if ($user === null) {
			return ['error' => 'Usuario nao encontrado.'];
		}

		$is_super_admin = (int) $user['role_type'] === USER_TYPE_SUPER_ADMIN;

		// Estrutura do dashboard.
		$pages = self::loadPages($dashboardid);
		$widgets = $pages ? self::loadWidgets(array_keys($pages)) : [];

		if (!$widgets) {
			return [
				'dashboard'  => ['name' => (string) $dashboard['name'], 'pages' => count($pages)],
				'ui_blocked' => self::isDashboardUiBlocked((string) $user['roleid']),
				'summary'    => ['widgets' => 0, 'broken' => 0, 'refs_broken' => 0],
				'problems'   => []
			];
		}

		$refs = self::loadReferences(array_keys($widgets));
		$catalog = self::resolveObjects($refs);
		$perms = $is_super_admin ? [] : self::groupPermissions($userid);
		$usrgrps = self::userGroupNames($userid);

		$problems = [];
		$refs_broken = 0;

		foreach ($widgets as $widgetid => $widget) {
			if (!array_key_exists($widgetid, $refs)) {
				// Widget sem referencia a objeto (clock, url, texto): nada a checar.
				continue;
			}

			$broken = [];

			foreach ($refs[$widgetid] as $ref) {
				$verdict = self::checkReference($ref, $catalog, $perms, $usrgrps, $is_super_admin);

				if ($verdict !== null) {
					$broken[] = $verdict;
				}
			}

			if (!$broken) {
				continue;
			}

			$refs_broken += count($broken);

			$page = $pages[$widget['dashboard_pageid']] ?? ['name' => '?', 'sortorder' => 0];

			$problems[] = [
				'page'        => $page['name'] !== '' ? $page['name'] : 'Pagina '.((int) $page['sortorder'] + 1),
				'widget_type' => (string) $widget['type'],
				'widget_name' => (string) $widget['name'] !== '' ? (string) $widget['name'] : '(sem titulo)',
				'broken'      => $broken
			];
		}

		return [
			'dashboard'  => ['name' => (string) $dashboard['name'], 'pages' => count($pages)],
			'ui_blocked' => self::isDashboardUiBlocked((string) $user['roleid']),
			'summary'    => [
				'widgets'     => count($widgets),
				'broken'      => count($problems),
				'refs_broken' => $refs_broken
			],
			'problems'   => $problems
		];
	}

	// -----------------------------------------------------------------------
	// Estrutura do dashboard
	// -----------------------------------------------------------------------

	private static function loadPages(int $dashboardid): array {
		$pages = [];
		$result = \DBselect(
			'SELECT dashboard_pageid,name,sortorder FROM dashboard_page'.
			' WHERE dashboardid='.\zbx_dbstr((string) $dashboardid).
			' ORDER BY sortorder'
		);

		while ($row = \DBfetch($result)) {
			$pages[(int) $row['dashboard_pageid']] = [
				'name'      => (string) $row['name'],
				'sortorder' => (int) $row['sortorder']
			];
		}

		return $pages;
	}

	private static function loadWidgets(array $pageids): array {
		$widgets = [];
		$result = \DBselect(
			'SELECT widgetid,dashboard_pageid,type,name,x,y FROM widget'.
			' WHERE '.\dbConditionId('dashboard_pageid', $pageids).
			' ORDER BY y,x'
		);

		while ($row = \DBfetch($result)) {
			$widgets[(int) $row['widgetid']] = [
				'dashboard_pageid' => (int) $row['dashboard_pageid'],
				'type'             => (string) $row['type'],
				'name'             => (string) $row['name']
			];
		}

		return $widgets;
	}

	/**
	 * Referencias a objetos, lidas das colunas tipadas de widget_field.
	 *
	 * Ler value_hostid/value_itemid/... em vez de interpretar widget_field.type e
	 * de proposito: os numeros de tipo mudam entre versoes do Zabbix, os nomes das
	 * colunas nao.
	 *
	 * @return array  widgetid => [['kind'=>..., 'id'=>int, 'field'=>string], ...]
	 */
	private static function loadReferences(array $widgetids): array {
		$map = [
			'value_groupid'  => self::KIND_GROUP,
			'value_hostid'   => self::KIND_HOST,
			'value_itemid'   => self::KIND_ITEM,
			'value_graphid'  => self::KIND_GRAPH,
			'value_sysmapid' => self::KIND_MAP
		];

		$refs = [];
		$result = \DBselect(
			'SELECT widgetid,name,value_groupid,value_hostid,value_itemid,value_graphid,value_sysmapid'.
			' FROM widget_field'.
			' WHERE '.\dbConditionId('widgetid', $widgetids)
		);

		while ($row = \DBfetch($result)) {
			$widgetid = (int) $row['widgetid'];

			foreach ($map as $column => $kind) {
				if ($row[$column] === null || (int) $row[$column] === 0) {
					continue;
				}

				$refs[$widgetid][] = [
					'kind'  => $kind,
					'id'    => (int) $row[$column],
					'field' => (string) $row['name']
				];
			}
		}

		return $refs;
	}

	// -----------------------------------------------------------------------
	// Resolucao dos objetos referenciados
	// -----------------------------------------------------------------------

	/**
	 * Busca nome e host group de cada objeto citado pelos widgets.
	 *
	 * Objeto ausente do catalogo = foi apagado do Zabbix, e a mensagem na tela do
	 * usuario e a mesma de falta de permissao. Distinguir os dois casos e metade
	 * do valor deste diagnostico.
	 */
	private static function resolveObjects(array $refs): array {
		$ids = [self::KIND_GROUP => [], self::KIND_HOST => [], self::KIND_ITEM => [],
			self::KIND_GRAPH => [], self::KIND_MAP => []
		];

		foreach ($refs as $widget_refs) {
			foreach ($widget_refs as $ref) {
				$ids[$ref['kind']][$ref['id']] = $ref['id'];
			}
		}

		$catalog = [self::KIND_GROUP => [], self::KIND_HOST => [], self::KIND_ITEM => [],
			self::KIND_GRAPH => [], self::KIND_MAP => []
		];

		if ($ids[self::KIND_GROUP]) {
			$result = \DBselect('SELECT groupid,name FROM hstgrp WHERE '.
				\dbConditionId('groupid', array_keys($ids[self::KIND_GROUP]))
			);

			while ($row = \DBfetch($result)) {
				$catalog[self::KIND_GROUP][(int) $row['groupid']] = [
					'name'   => (string) $row['name'],
					'groups' => [(int) $row['groupid']]
				];
			}
		}

		if ($ids[self::KIND_HOST]) {
			$catalog[self::KIND_HOST] = self::resolveHosts(array_keys($ids[self::KIND_HOST]));
		}

		if ($ids[self::KIND_ITEM]) {
			$catalog[self::KIND_ITEM] = self::resolveItems(array_keys($ids[self::KIND_ITEM]));
		}

		if ($ids[self::KIND_GRAPH]) {
			$catalog[self::KIND_GRAPH] = self::resolveGraphs(array_keys($ids[self::KIND_GRAPH]));
		}

		if ($ids[self::KIND_MAP]) {
			$result = \DBselect('SELECT sysmapid,name FROM sysmaps WHERE '.
				\dbConditionId('sysmapid', array_keys($ids[self::KIND_MAP]))
			);

			while ($row = \DBfetch($result)) {
				// Mapa nao e protegido por host group e sim por compartilhamento
				// proprio: sem groups, a checagem so reporta existencia.
				$catalog[self::KIND_MAP][(int) $row['sysmapid']] = [
					'name'   => (string) $row['name'],
					'groups' => []
				];
			}
		}

		return $catalog;
	}

	private static function resolveHosts(array $hostids): array {
		$out = [];
		$result = \DBselect(
			'SELECT h.hostid,h.name,hg.groupid'.
			' FROM hosts h'.
			' LEFT JOIN hosts_groups hg ON hg.hostid=h.hostid'.
			' WHERE '.\dbConditionId('h.hostid', $hostids)
		);

		while ($row = \DBfetch($result)) {
			$hostid = (int) $row['hostid'];

			if (!array_key_exists($hostid, $out)) {
				$out[$hostid] = ['name' => (string) $row['name'], 'groups' => []];
			}

			if ($row['groupid'] !== null) {
				$out[$hostid]['groups'][] = (int) $row['groupid'];
			}
		}

		return $out;
	}

	private static function resolveItems(array $itemids): array {
		$out = [];
		$result = \DBselect(
			'SELECT i.itemid,i.name,i.key_,h.name AS host_name,hg.groupid'.
			' FROM items i'.
			' JOIN hosts h ON h.hostid=i.hostid'.
			' LEFT JOIN hosts_groups hg ON hg.hostid=h.hostid'.
			' WHERE '.\dbConditionId('i.itemid', $itemids)
		);

		while ($row = \DBfetch($result)) {
			$itemid = (int) $row['itemid'];

			if (!array_key_exists($itemid, $out)) {
				$out[$itemid] = [
					'name'   => (string) $row['host_name'].': '.(string) $row['name'],
					'key'    => (string) $row['key_'],
					'groups' => []
				];
			}

			if ($row['groupid'] !== null) {
				$out[$itemid]['groups'][] = (int) $row['groupid'];
			}
		}

		return $out;
	}

	/**
	 * Graficos: a permissao vem dos hosts dos itens que compoem o grafico.
	 * Um grafico com itens de varios hosts exige permissao em TODOS eles.
	 */
	private static function resolveGraphs(array $graphids): array {
		$out = [];
		$result = \DBselect(
			'SELECT g.graphid,g.name,hg.groupid'.
			' FROM graphs g'.
			' JOIN graphs_items gi ON gi.graphid=g.graphid'.
			' JOIN items i ON i.itemid=gi.itemid'.
			' LEFT JOIN hosts_groups hg ON hg.hostid=i.hostid'.
			' WHERE '.\dbConditionId('g.graphid', $graphids)
		);

		while ($row = \DBfetch($result)) {
			$graphid = (int) $row['graphid'];

			if (!array_key_exists($graphid, $out)) {
				$out[$graphid] = ['name' => (string) $row['name'], 'groups' => []];
			}

			if ($row['groupid'] !== null && !in_array((int) $row['groupid'], $out[$graphid]['groups'], true)) {
				$out[$graphid]['groups'][] = (int) $row['groupid'];
			}
		}

		return $out;
	}

	// -----------------------------------------------------------------------
	// Permissoes efetivas
	// -----------------------------------------------------------------------

	/**
	 * Permissao do usuario por host group, ja com a regra do Zabbix aplicada:
	 * DENY em QUALQUER grupo de usuario vence Read e Read-write de todos os
	 * outros. Fora isso, vale o maior nivel concedido.
	 *
	 * @return array  groupid => ['permission'=>int, 'via'=>[usrgrpid=>permission]]
	 */
	private static function groupPermissions(int $userid): array {
		$out = [];
		$result = \DBselect(
			'SELECT r.id AS groupid,r.permission,ug.usrgrpid'.
			' FROM users_groups ug'.
			' JOIN rights r ON r.groupid=ug.usrgrpid'.
			' WHERE ug.userid='.\zbx_dbstr((string) $userid)
		);

		while ($row = \DBfetch($result)) {
			$groupid = (int) $row['groupid'];
			$permission = (int) $row['permission'];
			$usrgrpid = (int) $row['usrgrpid'];

			if (!array_key_exists($groupid, $out)) {
				$out[$groupid] = ['permission' => $permission, 'via' => []];
			}
			elseif ($permission === PERM_DENY || $out[$groupid]['permission'] === PERM_DENY) {
				$out[$groupid]['permission'] = PERM_DENY;
			}
			else {
				$out[$groupid]['permission'] = max($out[$groupid]['permission'], $permission);
			}

			$out[$groupid]['via'][$usrgrpid] = $permission;
		}

		return $out;
	}

	private static function userGroupIds(int $userid): array {
		$ids = [];
		$result = \DBselect('SELECT usrgrpid FROM users_groups WHERE userid='.\zbx_dbstr((string) $userid));

		while ($row = \DBfetch($result)) {
			$ids[] = (int) $row['usrgrpid'];
		}

		return $ids;
	}

	private static function userGroupNames(int $userid): array {
		$names = [];
		$result = \DBselect(
			'SELECT g.usrgrpid,g.name FROM users_groups ug'.
			' JOIN usrgrp g ON g.usrgrpid=ug.usrgrpid'.
			' WHERE ug.userid='.\zbx_dbstr((string) $userid)
		);

		while ($row = \DBfetch($result)) {
			$names[(int) $row['usrgrpid']] = (string) $row['name'];
		}

		return $names;
	}

	/**
	 * A role do usuario esconde a secao de dashboards inteira?
	 *
	 * Se esconder, nenhum widget importa - o usuario nem chega na tela. Vale
	 * dizer isso primeiro, antes de listar 30 problemas de permissao.
	 */
	private static function isDashboardUiBlocked(string $roleid): bool {
		$row = \DBfetch(\DBselect(
			'SELECT value_int FROM role_rule'.
			' WHERE roleid='.\zbx_dbstr($roleid).
				' AND name LIKE '.\zbx_dbstr('ui.monitoring.dash%')
		));

		return $row ? (int) $row['value_int'] === 0 : false;
	}

	// -----------------------------------------------------------------------
	// Veredito por referencia
	// -----------------------------------------------------------------------

	/**
	 * @return array|null  null quando a referencia esta OK.
	 */
	private static function checkReference(array $ref, array $catalog, array $perms, array $usrgrps,
			bool $is_super_admin): ?array {

		$kind = $ref['kind'];
		$id = $ref['id'];

		if (!array_key_exists($id, $catalog[$kind])) {
			return [
				'kind'    => $kind,
				'id'      => $id,
				'name'    => '(objeto inexistente)',
				'field'   => $ref['field'],
				'status'  => self::ST_MISSING,
				'label'   => 'Objeto nao existe mais',
				'detail'  => 'O widget aponta para um '.$kind.' de id '.$id.' que foi removido do Zabbix.'.
					' Isso nao e permissao: o widget quebra para QUALQUER usuario, inclusive Super Admin.'.
					' Corrija ou remova o widget.',
				'groups'  => []
			];
		}

		$object = $catalog[$kind][$id];

		if ($is_super_admin) {
			return null;
		}

		// Mapa nao e protegido por host group - a checagem para na existencia.
		if ($kind === self::KIND_MAP) {
			return null;
		}

		$groups = $object['groups'];

		if (!$groups) {
			return null;
		}

		$deny = [];
		$granted = PERM_DENY;
		$missing = [];

		foreach ($groups as $groupid) {
			if (!array_key_exists($groupid, $perms)) {
				$missing[] = $groupid;
				continue;
			}

			if ($perms[$groupid]['permission'] === PERM_DENY) {
				$deny[] = $groupid;
				continue;
			}

			$granted = max($granted, $perms[$groupid]['permission']);
		}

		// DENY explicito vence tudo - inclusive um Read-write concedido em outro
		// grupo. E a causa mais confundida de "mas eu dei permissao para ele".
		if ($deny) {
			return [
				'kind'   => $kind,
				'id'     => $id,
				'name'   => (string) $object['name'],
				'field'  => $ref['field'],
				'status' => self::ST_DENY,
				'label'  => 'DENY explicito',
				'detail' => 'Ha DENY em '.self::groupNames($deny).', via o(s) grupo(s) de usuario '.
					self::denyingUserGroups($deny, $perms, $usrgrps).'. No Zabbix o DENY vence qualquer'.
					' Read ou Read-write concedido em outro grupo - conceder mais permissao NAO resolve.'.
					' Remova o DENY em Users -> User groups -> <grupo> -> Host permissions.',
				'groups' => self::groupList($deny)
			];
		}

		if ($granted >= PERM_READ) {
			return null;
		}

		return [
			'kind'   => $kind,
			'id'     => $id,
			'name'   => (string) $object['name'],
			'field'  => $ref['field'],
			'status' => self::ST_NOPERM,
			'label'  => 'Sem permissao',
			'detail' => 'Nenhum grupo de usuario do alvo concede leitura em '.self::groupNames($missing ?: $groups).
				'. Conceda Read nesse host group para um dos grupos dele ('.
				($usrgrps ? implode(', ', $usrgrps) : 'o usuario nao esta em nenhum grupo').
				') em Users -> User groups -> <grupo> -> Host permissions.',
			'groups' => self::groupList($missing ?: $groups)
		];
	}

	private static function groupList(array $groupids): array {
		if (!$groupids) {
			return [];
		}

		$names = [];
		$result = \DBselect('SELECT groupid,name FROM hstgrp WHERE '.\dbConditionId('groupid', $groupids));

		while ($row = \DBfetch($result)) {
			$names[] = (string) $row['name'];
		}

		sort($names);

		return $names;
	}

	private static function groupNames(array $groupids): string {
		$names = self::groupList($groupids);

		return $names ? '"'.implode('", "', $names).'"' : '(host group desconhecido)';
	}

	private static function denyingUserGroups(array $groupids, array $perms, array $usrgrps): string {
		$names = [];

		foreach ($groupids as $groupid) {
			foreach ($perms[$groupid]['via'] ?? [] as $usrgrpid => $permission) {
				if ($permission === PERM_DENY && array_key_exists($usrgrpid, $usrgrps)) {
					$names[$usrgrpid] = $usrgrps[$usrgrpid];
				}
			}
		}

		return $names ? '"'.implode('", "', $names).'"' : '(nao identificado)';
	}
}
