<?php declare(strict_types=1);
/**
 * Impersonate - view principal.
 *
 * @var CView $this
 * @var array $data
 *
 * Autor: Rafael M. A. Leao Ereno - MALE
 */

$e = static function ($v): string {
	return htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8');
};

$type_badge = static function (?int $type): array {
	switch ((int) $type) {
		case 1:  return ['User', 'badge-gray'];
		case 2:  return ['Admin', 'badge-info'];
		case 3:  return ['Super Admin', 'badge-warn'];
	}

	return ['sem role', 'badge-err'];
};

$ttl = (int) $data['config']['session_ttl'];
$readonly = (int) $data['config']['readonly'] === 1;
$require_reason = (int) $data['config']['require_reason'] === 1;
?>
<?= \Modules\ZbxImpersonate\Helper\ImpersonateAssets::css() ?>

<div class="im-wrap">
    <div class="im-title">🎭 Impersonate</div>
    <div class="im-sub">
        Assuma a sessão de um usuário <strong>User</strong> ou <strong>Admin</strong> do Zabbix e veja a
        interface exatamente como ele a vê &mdash; mesmas permissões, mesmo tema, mesmo idioma e os
        mesmos erros de tela.
        <span class="im-build">
            v<?= $e($data['config']['version']) ?> &middot; servido por <?= $e($data['config']['hostname']) ?>
        </span>
        <?php if ((int) $data['config']['debug'] === 1): ?>
            <?php $debug_broken = strpos((string) $data['config']['debug_status'], 'NAO') !== false
                || strpos((string) $data['config']['debug_status'], 'FALHA') !== false; ?>
            <span class="badge <?= $debug_broken ? 'badge-err' : 'badge-warn' ?>" style="margin-left:6px;">
                debug ligado<?= $data['config']['debug_file'] !== ''
                    ? ' &rarr; '.$e($data['config']['debug_file'])
                    : '' ?>
                &middot; <?= $e($data['config']['debug_status']) ?>
            </span>
        <?php endif; ?>
    </div>

    <div id="im-status" class="status-msg"></div>

    <div class="im-callout">
        <div class="im-callout-icon">🔒</div>
        <div>
            <div class="im-callout-title">Política ativa deste módulo</div>
            <div class="im-callout-body">
                Modo <strong><?= $readonly ? 'somente leitura' : 'leitura e escrita' ?></strong><?= $readonly ? ' ('.$e($data['config']['readonly_mode']).')' : '' ?> durante a
                impersonação&nbsp;&middot;
                expiração automática em <strong><?= $ttl > 0 ? (int) round($ttl / 60).' minutos' : 'nunca' ?></strong>&nbsp;&middot;
                alvos Super Admin <strong><?= (int) $data['config']['block_super_admin_target'] === 1 ? 'bloqueados' : 'permitidos' ?></strong>&nbsp;&middot;
                banner de aviso <strong><?= (int) $data['config']['banner'] === 1 ? 'ligado' : 'desligado' ?></strong>&nbsp;&middot;
                motivo obrigatório <strong><?= $require_reason ? 'sim' : 'não' ?></strong>.
                Toda impersonação é gravada em <code>module_impersonate_log</code> e também gera um
                <code>Login</code> no audit log nativo do Zabbix, em nome do usuário alvo.
                <div style="margin-top:8px;">
                    Erros como <em>"No permissions to referred object"</em> ou <em>"Invalid parameter Item"</em>
                    aparecendo nos widgets durante a impersonação <strong>não são falha do módulo</strong>:
                    é o que o usuário realmente vê &mdash; e normalmente é o achado do troubleshooting.
                </div>
            </div>
        </div>
    </div>

    <?php if ((int) $data['stale_closed'] > 0): ?>
    <div class="im-callout">
        <div class="im-callout-icon">🧹</div>
        <div>
            <div class="im-callout-title">
                <?= (int) $data['stale_closed'] ?> evento(s) de impersonação estavam abertos e foram encerrados
            </div>
            <div class="im-callout-body">
                Impersonações que nunca receberam um encerramento (navegador fechado, frontend reiniciado)
                ficam com <code>ended=0</code> no log e retêm o token da sessão de origem. Foram fechadas
                agora com <code>end_reason=stale</code>.
            </div>
        </div>
    </div>
    <?php endif; ?>

    <?php if ($data['roles_missing_access']): ?>
    <div class="im-callout im-callout-danger">
        <div class="im-callout-icon">🔒</div>
        <div>
            <div class="im-callout-title" style="color:var(--c-danger);">
                <?= count($data['roles_missing_access']) ?> role(s) sem acesso ao módulo &mdash; usuários delas não podem ser impersonados
            </div>
            <div class="im-callout-body">
                Se a role do usuário alvo não enxerga este módulo, o Zabbix nem carrega o
                <code>Module.php</code> durante a impersonação: o modo somente-leitura e o item
                <em>Sair da impersonação</em> deixariam de existir. Por isso o módulo recusa.
                <div style="margin-top:8px;">
                    Libere em <strong>Users &rarr; User roles &rarr; &lt;role&gt; &rarr; Access to modules</strong>, marcando
                    <em>Impersonate</em> nestas roles:
                </div>
                <div class="im-chiplist" style="margin-top:8px;">
                    <?php foreach ($data['roles_missing_access'] as $role_name): ?>
                        <span class="badge badge-err"><?= $e($role_name) ?></span>
                    <?php endforeach; ?>
                </div>
                <div style="margin-top:12px;">
                    <button type="button" class="btn btn-primary btn-sm" id="im-grant">Liberar o módulo nas roles que precisam</button>
                    <span class="form-hint" style="margin-left:10px;">
                        Marca apenas <em>Access to modules &rarr; Impersonate</em>. Nenhuma outra permissão da role é
                        tocada, e liberar o módulo não dá poder algum ao usuário comum &mdash; todas as telas exigem
                        Super Admin.
                    </span>
                </div>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <div class="im-stats">
        <div class="im-stat">
            <div class="im-stat-num"><?= (int) $data['stats']['total'] ?></div>
            <div class="im-stat-lbl">Usuários listados</div>
        </div>
        <div class="im-stat">
            <div class="im-stat-num"><?= (int) $data['stats']['impersonable'] ?></div>
            <div class="im-stat-lbl">Impersonáveis</div>
        </div>
        <div class="im-stat">
            <div class="im-stat-num"><?= (int) $data['stats']['blocked'] ?></div>
            <div class="im-stat-lbl">Bloqueados</div>
        </div>
        <div class="im-stat">
            <div class="im-stat-num"><?= count($data['recent']) ?></div>
            <div class="im-stat-lbl">Eventos recentes</div>
        </div>
    </div>

    <form class="im-filter" method="get" action="zabbix.php">
        <input type="hidden" name="action" value="zbx.impersonate.list">
        <div class="form-group">
            <label class="form-label" for="im-search">Buscar</label>
            <input class="form-input" type="text" id="im-search" name="search"
                   value="<?= $e($data['search']) ?>" placeholder="username, nome ou sobrenome">
        </div>
        <div class="form-group">
            <label class="form-label" for="im-type">Tipo</label>
            <select class="form-input" id="im-type" name="show_type">
                <option value="0"<?= (int) $data['show_type'] === 0 ? ' selected' : '' ?>>Todos</option>
                <option value="1"<?= (int) $data['show_type'] === 1 ? ' selected' : '' ?>>User</option>
                <option value="2"<?= (int) $data['show_type'] === 2 ? ' selected' : '' ?>>Admin</option>
                <option value="3"<?= (int) $data['show_type'] === 3 ? ' selected' : '' ?>>Super Admin</option>
            </select>
        </div>
        <button type="submit" class="btn btn-primary">Filtrar</button>
        <a class="btn btn-outline" href="zabbix.php?action=zbx.impersonate.log">📋 Ver log de auditoria</a>
    </form>

    <div class="card">
        <div class="card-hdr">
            <h3>👥 Usuários</h3>
            <p>Clique em <em>Perfil</em> para inspecionar permissões sem trocar de sessão.</p>
        </div>
        <?php if (!$data['users']): ?>
            <div class="empty">
                <span class="empty-icon">🔍</span>
                <div class="empty-title">Nenhum usuário encontrado</div>
                <div class="empty-desc">Ajuste os filtros e tente novamente.</div>
            </div>
        <?php else: ?>
        <table class="tbl">
            <thead>
                <tr>
                    <th>Usuário</th>
                    <th>Role</th>
                    <th>Tipo</th>
                    <th>Grupos</th>
                    <th>Último acesso</th>
                    <th style="text-align:right;">Ações</th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($data['users'] as $user): ?>
                <?php [$badge_label, $badge_class] = $type_badge($user['role_type']); ?>
                <tr>
                    <td>
                        <div class="im-user"><?= $e($user['username']) ?></div>
                        <?php $fullname = trim((string) $user['name'].' '.(string) $user['surname']); ?>
                        <?php if ($fullname !== ''): ?>
                            <div class="im-fullname"><?= $e($fullname) ?></div>
                        <?php endif; ?>
                        <?php if ((int) $user['userdirectoryid'] > 0): ?>
                            <span class="badge badge-info" style="margin-top:4px;">SSO / LDAP</span>
                        <?php endif; ?>
                    </td>
                    <td><span class="mono"><?= $e($user['role_name'] ?? '-') ?></span></td>
                    <td><span class="badge <?= $e($badge_class) ?>"><?= $e($badge_label) ?></span></td>
                    <td class="im-groups"><?= $user['groups'] ? $e(implode(', ', $user['groups'])) : '-' ?></td>
                    <td class="mono">
                        <?= (int) $user['lastaccess'] > 0 ? $e(date('d/m/Y H:i', (int) $user['lastaccess'])) : '-' ?>
                    </td>
                    <td>
                        <div class="im-actions">
                            <button type="button" class="btn btn-outline btn-sm"
                                    data-profile="<?= (int) $user['userid'] ?>">Perfil</button>
                            <button type="button" class="btn btn-outline btn-sm"
                                    data-dashboards="<?= (int) $user['userid'] ?>"
                                    data-username="<?= $e($user['username']) ?>"
                                    title="Descobrir por que os dashboards deste usuário mostram erro">Dashboards</button>
                            <?php if ($user['can_impersonate']): ?>
                                <button type="button" class="btn btn-danger-outline btn-sm"
                                        data-impersonate="<?= (int) $user['userid'] ?>"
                                        data-username="<?= $e($user['username']) ?>">Impersonar</button>
                            <?php else: ?>
                                <span class="im-block" title="<?= $e($user['block_reason']) ?>">
                                    <?= $e($user['block_reason']) ?>
                                </span>
                            <?php endif; ?>
                        </div>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        <?php endif; ?>
    </div>
</div>

<div class="modal-backdrop" id="im-modal">
    <div class="modal-box">
        <div class="modal-hdr">
            <h3 id="im-modal-title">Perfil</h3>
            <button type="button" class="modal-close" id="im-modal-close">&times;</button>
        </div>
        <div class="modal-body" id="im-modal-body"></div>
        <div class="modal-footer">
            <button type="button" class="btn btn-outline" id="im-modal-dismiss">Fechar</button>
        </div>
    </div>
</div>

<script>
(function () {
    'use strict';

    var REQUIRE_REASON = <?= $require_reason ? 'true' : 'false' ?>;

    var modal = document.getElementById('im-modal');
    var modalBody = document.getElementById('im-modal-body');
    var modalTitle = document.getElementById('im-modal-title');
    var statusBox = document.getElementById('im-status');

    function esc(v) {
        return String(v === null || v === undefined ? '' : v)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    function showStatus(message, ok) {
        statusBox.className = 'status-msg ' + (ok ? 'ok' : 'err');
        statusBox.textContent = message;

        if (ok) {
            return;
        }

        window.setTimeout(function () { statusBox.className = 'status-msg'; }, 8000);
    }

    function post(action, params) {
        return fetch('zabbix.php?action=' + action, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: new URLSearchParams(params)
        }).then(function (r) { return r.json(); });
    }

    function section(title, html) {
        return '<div class="im-sec"><div class="im-sec-title">' + esc(title) + '</div>' + html + '</div>';
    }

    function kv(pairs) {
        var out = '<div class="im-kv">';
        pairs.forEach(function (p) {
            out += '<div><span>' + esc(p[0]) + '</span>' + esc(p[1]) + '</div>';
        });
        return out + '</div>';
    }

    function table(headers, rows) {
        if (!rows.length) {
            return '<div class="im-block">Nenhum registro.</div>';
        }
        var out = '<table class="tbl"><thead><tr>';
        headers.forEach(function (h) { out += '<th>' + esc(h) + '</th>'; });
        out += '</tr></thead><tbody>';
        rows.forEach(function (row) {
            out += '<tr>';
            row.forEach(function (cell) { out += '<td>' + esc(cell) + '</td>'; });
            out += '</tr>';
        });
        return out + '</tbody></table>';
    }

    function chips(items, cls) {
        if (!items.length) {
            return '<div class="im-block">Nenhum.</div>';
        }
        return '<div class="im-chiplist">' + items.map(function (i) {
            return '<span class="badge ' + cls + '">' + esc(i) + '</span>';
        }).join('') + '</div>';
    }

    function renderProfile(p) {
        var u = p.user;
        var html = '';

        html += section('Identificação', kv([
            ['Username', u.username],
            ['Nome', u.fullname || '-'],
            ['Role', u.role_name + ' (' + u.role_type_label + ')'],
            ['Origem', u.provisioned ? 'Provisionado (SSO/LDAP)' : 'Interno'],
            ['Idioma / Tema', u.lang + ' / ' + u.theme],
            ['Timezone', u.timezone],
            ['Autologin', u.autologin ? 'Sim' : 'Não'],
            ['Autologout', u.autologout],
            ['Refresh', u.refresh],
            ['Linhas por página', u.rows_per_page],
            ['URL inicial', u.url || '-'],
            ['Status', u.disabled ? 'DESABILITADO' : (u.gui_disabled ? 'GUI desabilitada' : 'Ativo')]
        ]));

        if (u.attempt_failed > 0) {
            html += section('Tentativas de login falhas', kv([
                ['Falhas', u.attempt_failed],
                ['Último IP', u.attempt_ip || '-'],
                ['Quando', u.attempt_clock]
            ]));
        }

        html += section('Grupos de usuário', table(
            ['Grupo', 'Usuários', 'GUI access', 'Debug'],
            p.groups.map(function (g) { return [g.name, g.users_status, g.gui_access, g.debug_mode]; })
        ));

        html += section('Permissões efetivas em host groups', table(
            ['Host group', 'Permissão'],
            p.permissions.map(function (x) { return [x.name, x.permission]; })
        ));

        html += section('Mídias / notificações', table(
            ['Tipo de mídia', 'Enviar para', 'Mídia ativa', 'Media type ativo', 'Período'],
            p.medias.map(function (m) { return [m.media_type, m.sendto, m.active, m.mt_status, m.period]; })
        ));

        html += section('Sessões ativas', table(
            ['Session (prefixo)', 'Último acesso'],
            p.sessions.map(function (s) { return [s.sessionid, s.lastaccess]; })
        ));

        html += section('UI liberada pela role', chips(p.role_rules.ui_allowed, 'badge-ok'));
        html += section('UI negada pela role', chips(p.role_rules.ui_denied, 'badge-err'));
        html += section('Ações liberadas', chips(p.role_rules.actions_allowed, 'badge-info'));

        html += section('Histórico de impersonação deste usuário', table(
            ['Quem impersonou', 'Início', 'Fim', 'Justificativa', 'Encerramento', 'Somente leitura'],
            p.history.map(function (h) {
                return [h.actor_username, h.started, h.ended, h.reason || '-', h.end_reason || '-',
                    h.readonly ? 'Sim' : 'Não'];
            })
        ));

        modalTitle.textContent = 'Perfil de ' + u.username;
        modalBody.innerHTML = html;
        modal.classList.add('open');
    }

    function closeModal() {
        modal.classList.remove('open');
        modalBody.innerHTML = '';
    }

    // ---------------------------------------------------------------- dashboards

    function renderDashboardList(res) {
        var html = '';

        if (!res.dashboards.length) {
            html = '<div class="im-block">Este usuário não enxerga nenhum dashboard: ele não é dono de ' +
                'nenhum, não há dashboard público, e nada foi compartilhado com ele nem com seus grupos.</div>';
        }
        else {
            html += '<div class="im-sec"><div class="im-sec-title">Dashboards visíveis para ' +
                esc(res.username) + '</div>' +
                '<div class="im-block" style="margin-bottom:10px;">Clique em <em>Analisar</em> para ver o que ' +
                'quebra na tela dele e por quê.</div>' +
                '<table class="tbl"><thead><tr><th>Dashboard</th><th>Dono</th><th>Acesso</th>' +
                '<th>Widgets</th><th></th></tr></thead><tbody>';

            res.dashboards.forEach(function (d) {
                html += '<tr>' +
                    '<td><strong>' + esc(d.name) + '</strong></td>' +
                    '<td class="mono">' + esc(d.owner_username) + '</td>' +
                    '<td>' + (d.is_owner
                        ? '<span class="badge badge-ok">dono</span>'
                        : (d.private
                            ? '<span class="badge badge-info">compartilhado</span>'
                            : '<span class="badge badge-gray">público</span>')) + '</td>' +
                    '<td class="mono">' + esc(d.widgets) + '</td>' +
                    '<td style="text-align:right;">' +
                        '<button type="button" class="btn btn-outline btn-sm" data-diag="' + esc(d.dashboardid) +
                        '">Analisar</button></td>' +
                    '</tr>';
            });

            html += '</tbody></table></div>';
        }

        modalTitle.textContent = 'Dashboards de ' + res.username;
        modalBody.innerHTML = html;
        modal.classList.add('open');
    }

    function renderDiagnostic(res) {
        var r = res.report;
        var html = '';

        html += '<div class="im-sec"><div class="im-sec-title">' + esc(r.dashboard.name) + '</div>' +
            '<div class="im-kv">' +
            '<div><span>Usuário</span>' + esc(res.username) + '</div>' +
            '<div><span>Role</span>' + esc(res.role) + '</div>' +
            '<div><span>Páginas</span>' + esc(r.dashboard.pages) + '</div>' +
            '<div><span>Widgets</span>' + esc(r.summary.widgets) + '</div>' +
            '<div><span>Widgets com problema</span>' + esc(r.summary.broken) + '</div>' +
            '<div><span>Referências quebradas</span>' + esc(r.summary.refs_broken) + '</div>' +
            '</div></div>';

        if (r.ui_blocked) {
            html += '<div class="im-callout im-callout-danger"><div class="im-callout-icon">⛔</div><div>' +
                '<div class="im-callout-title" style="color:var(--c-danger);">A role deste usuário esconde ' +
                'a seção de dashboards</div>' +
                '<div class="im-callout-body">Nenhum widget importa: ele nem chega nesta tela. Libere em ' +
                '<strong>Users &rarr; User roles &rarr; ' + esc(res.role) + ' &rarr; Access to UI elements ' +
                '&rarr; Monitoring &rarr; Dashboards</strong>.</div></div></div>';
        }

        if (!r.problems.length) {
            html += '<div class="im-callout"><div class="im-callout-icon">✅</div><div>' +
                '<div class="im-callout-title">Nenhuma referência quebrada</div>' +
                '<div class="im-callout-body">Todos os host groups, hosts, itens e gráficos citados pelos ' +
                'widgets existem e são legíveis por este usuário. Se a tela dele ainda mostra erro, o ' +
                'problema não é de permissão em objeto — vale conferir filtros do widget e período.' +
                '</div></div></div>';
        }
        else {
            r.problems.forEach(function (p) {
                html += '<div class="im-sec"><div class="im-sec-title">' + esc(p.page) + ' &middot; ' +
                    esc(p.widget_name) + ' <span class="mono">(' + esc(p.widget_type) + ')</span></div>';

                p.broken.forEach(function (b) {
                    var cls = b.status === 'deny' ? 'badge-err'
                        : (b.status === 'missing' ? 'badge-warn' : 'badge-err');

                    html += '<div class="im-callout im-callout-danger" style="margin-bottom:8px;">' +
                        '<div class="im-callout-icon">' +
                            (b.status === 'missing' ? '🗑️' : (b.status === 'deny' ? '⛔' : '🔒')) +
                        '</div><div>' +
                        '<div class="im-callout-title" style="color:var(--c-danger);">' +
                            '<span class="badge ' + cls + '">' + esc(b.label) + '</span> ' +
                            esc(b.kind) + ': ' + esc(b.name) +
                        '</div>' +
                        '<div class="im-callout-body">' + esc(b.detail) +
                            (b.field ? '<div style="margin-top:6px;">Campo do widget: <code>' +
                                esc(b.field) + '</code></div>' : '') +
                        '</div></div></div>';
                });

                html += '</div>';
            });
        }

        modalTitle.textContent = 'Diagnóstico · ' + r.dashboard.name;
        modalBody.innerHTML = html;
        modal.classList.add('open');
    }

    document.getElementById('im-modal-close').addEventListener('click', closeModal);
    document.getElementById('im-modal-dismiss').addEventListener('click', closeModal);
    modal.addEventListener('click', function (ev) { if (ev.target === modal) { closeModal(); } });
    document.addEventListener('keydown', function (ev) { if (ev.key === 'Escape') { closeModal(); } });

    var grantBtn = document.getElementById('im-grant');

    if (grantBtn) {
        var GRANT_LABEL = 'Liberar o módulo nas roles que precisam';

        function applyGrant() {
            grantBtn.textContent = 'Liberando...';

            return post('zbx.impersonate.grant', { submit_action: 'grant', dry_run: '0' })
                .then(function (res) {
                    if (res && res.error && res.error.title) {
                        showStatus(res.error.title, false);
                        return;
                    }

                    if (!res || !res.success) {
                        showStatus((res && res.error) || 'Falha ao liberar o módulo.', false);
                        return;
                    }

                    var parts = [];

                    if (res.granted.length) {
                        parts.push(res.granted.length + ' role(s) liberada(s): ' + res.granted.join(', '));
                    }
                    if (res.already) {
                        parts.push(res.already + ' já tinha(m) acesso');
                    }
                    if (res.readonly.length) {
                        parts.push('ignorada(s) por serem readonly: ' + res.readonly.join(', '));
                    }
                    if (res.failed.length) {
                        parts.push('FALHOU em: ' + res.failed.join('; '));
                    }

                    showStatus(parts.join(' · ') || 'Nada a fazer.', res.failed.length === 0);

                    if (res.granted.length) {
                        window.setTimeout(function () { window.location.reload(); }, 1800);
                    }
                });
        }

        grantBtn.addEventListener('click', function () {
            grantBtn.disabled = true;
            grantBtn.textContent = 'Verificando...';

            // Passo 1: dry-run. Alterar permissão de role sem dizer QUAIS roles seriam
            // tocadas e pedir confirmacao no escuro.
            post('zbx.impersonate.grant', { submit_action: 'preview', dry_run: '1' })
                .then(function (res) {
                    if (res && res.error && res.error.title) {
                        showStatus(res.error.title, false);
                        return;
                    }

                    if (!res || !res.success) {
                        showStatus((res && res.error) || 'Falha ao verificar as roles.', false);
                        return;
                    }

                    if (!res.would_grant.length) {
                        var msg = 'Nenhuma role a alterar.';

                        if (res.readonly.length) {
                            msg += ' Somente roles readonly pendentes (não editáveis pela API): ' +
                                res.readonly.join(', ') + '.';
                        }

                        showStatus(msg, true);
                        return;
                    }

                    if (!window.confirm(
                        'Liberar o módulo Impersonate nestas ' + res.would_grant.length + ' role(s)?\n\n' +
                        '  · ' + res.would_grant.join('\n  · ') + '\n\n' +
                        'Isso marca APENAS "Access to modules -> Impersonate". Nenhuma outra permissão ' +
                        'da role é alterada.\n\n' +
                        'Sem esse acesso o Zabbix não carrega o módulo durante a impersonação, e o modo ' +
                        'somente-leitura e o botão de sair deixam de existir.'
                    )) {
                        showStatus('Nada foi alterado.', true);
                        return;
                    }

                    return applyGrant();
                })
                .catch(function (err) { showStatus('Erro de rede: ' + err, false); })
                .finally(function () {
                    grantBtn.disabled = false;
                    grantBtn.textContent = GRANT_LABEL;
                });
        });
    }

    // Guardado ao abrir a lista de dashboards: o botao "Analisar" vive dentro do
    // modal e precisa saber de QUAL usuario e o diagnostico.
    var diagUserid = null;

    document.addEventListener('click', function (ev) {
        var dashBtn = ev.target.closest('[data-dashboards]');

        if (dashBtn) {
            diagUserid = dashBtn.dataset.dashboards;
            dashBtn.disabled = true;

            post('zbx.impersonate.dashboards', { userid: diagUserid })
                .then(function (res) {
                    if (res && res.error && res.error.title) {
                        showStatus(res.error.title, false);
                        return;
                    }
                    if (!res || !res.success) {
                        showStatus((res && res.error) || 'Falha ao listar os dashboards.', false);
                        return;
                    }
                    renderDashboardList(res);
                })
                .catch(function (err) { showStatus('Erro de rede: ' + err, false); })
                .finally(function () { dashBtn.disabled = false; });

            return;
        }

        var diagBtn = ev.target.closest('[data-diag]');

        if (diagBtn) {
            diagBtn.disabled = true;
            diagBtn.textContent = 'Analisando...';

            post('zbx.impersonate.dashdiag', { userid: diagUserid, dashboardid: diagBtn.dataset.diag })
                .then(function (res) {
                    if (res && res.error && res.error.title) {
                        showStatus(res.error.title, false);
                        return;
                    }
                    if (!res || !res.success) {
                        showStatus((res && res.error) || 'Falha ao analisar o dashboard.', false);
                        return;
                    }
                    renderDiagnostic(res);
                })
                .catch(function (err) { showStatus('Erro de rede: ' + err, false); })
                .finally(function () {
                    diagBtn.disabled = false;
                    diagBtn.textContent = 'Analisar';
                });

            return;
        }

        var profileBtn = ev.target.closest('[data-profile]');

        if (profileBtn) {
            profileBtn.disabled = true;
            post('zbx.impersonate.profile', { userid: profileBtn.dataset.profile })
                .then(function (res) {
                    if (res && res.error) {
                        showStatus(res.error.title || 'Falha ao carregar o perfil.', false);
                        return;
                    }
                    if (!res || !res.success) {
                        showStatus((res && res.error) || 'Falha ao carregar o perfil.', false);
                        return;
                    }
                    renderProfile(res);
                })
                .catch(function (err) { showStatus('Erro de rede: ' + err, false); })
                .finally(function () { profileBtn.disabled = false; });

            return;
        }

        var impBtn = ev.target.closest('[data-impersonate]');

        if (!impBtn) {
            return;
        }

        var username = impBtn.dataset.username;

        if (!window.confirm(
            'Assumir a sessão de "' + username + '"?\n\n' +
            'Você sai da sua própria sessão até encerrar a impersonação pelo item ' +
            '"Sair da impersonação" no topo do menu lateral.\n\n' +
            'Esta ação fica registrada no log de auditoria.'
        )) {
            return;
        }

        var reason = '';

        if (REQUIRE_REASON) {
            reason = window.prompt(
                'Motivo da impersonação (obrigatório, vai para o log de auditoria):\n\n' +
                'Ex.: "ticket 12345 - usuário relata dashboard vazio"'
            );

            if (reason === null) {
                return;
            }

            reason = reason.trim();

            if (reason === '') {
                showStatus('Motivo obrigatório: a impersonação não foi iniciada.', false);
                return;
            }
        }

        impBtn.disabled = true;
        impBtn.textContent = 'Entrando...';

        post('zbx.impersonate.start', {
                userid: impBtn.dataset.impersonate,
                reason: reason,
                submit_action: 'start'
            })
            .then(function (res) {
                if (res && res.error && res.error.title) {
                    showStatus(res.error.title, false);
                    impBtn.disabled = false;
                    impBtn.textContent = 'Impersonar';
                    return;
                }

                if (!res || !res.success) {
                    showStatus((res && res.error) || 'Falha ao iniciar a impersonação.', false);
                    impBtn.disabled = false;
                    impBtn.textContent = 'Impersonar';
                    return;
                }

                showStatus('Impersonação iniciada. Redirecionando...', true);
                window.location.href = res.redirect;
            })
            .catch(function (err) {
                showStatus('Erro de rede: ' + err, false);
                impBtn.disabled = false;
                impBtn.textContent = 'Impersonar';
            });
    });
})();
</script>
