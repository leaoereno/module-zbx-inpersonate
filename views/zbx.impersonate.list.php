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
?>
<style>
:root {
    --c-bg:#f4f6f9; --c-card:#fff; --c-border:#dde3ec;
    --c-accent:#1565c0; --c-accent-light:#e8f0fe; --c-accent-hover:#0d47a1;
    --c-text:#1a1f36; --c-muted:#6b7a99;
    --c-success:#1b7e47; --c-success-bg:#e8f5e9;
    --c-danger:#b71c1c;  --c-danger-bg:#fff5f5; --c-danger-border:#f5c6c6;
    --c-warn:#bf6000;    --c-warn-bg:#fff8e1;    --c-warn-border:#ffe082;
    --c-shadow:0 1px 4px rgba(0,0,0,.08);
    --c-shadow-md:0 4px 6px rgba(0,0,0,.05),0 2px 4px rgba(0,0,0,.04);
    --c-term-bg:#0d1117; --c-term-fg:#c9d1d9; --c-term-border:#30363d;
}
* { box-sizing:border-box; }

.im-wrap { padding:16px 18px; }
.im-title { font-size:19px; font-weight:800; color:var(--c-text); margin-bottom:4px; }
.im-sub { font-size:12px; color:var(--c-muted); margin-bottom:16px; }

.im-callout { display:flex; gap:12px; align-items:flex-start; background:var(--c-warn-bg);
    border:1px solid var(--c-warn-border); border-radius:10px; padding:12px 16px; margin-bottom:16px; }
.im-callout-danger { background:var(--c-danger-bg); border-color:var(--c-danger-border); }
.im-callout-icon { font-size:20px; line-height:1.2; }
.im-callout-title { font-size:13px; font-weight:700; color:var(--c-warn); margin-bottom:4px; }
.im-callout-body { font-size:12px; color:var(--c-text); line-height:1.55; }
.im-callout-body code { background:rgba(0,0,0,.06); padding:1px 5px; border-radius:4px;
    font-family:'JetBrains Mono','Courier New',monospace; font-size:11px; }

.im-stats { display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:10px; margin-bottom:16px; }
.im-stat { background:var(--c-card); border:1px solid var(--c-border); border-radius:10px;
    box-shadow:var(--c-shadow); padding:12px 16px; }
.im-stat-num { font-size:22px; font-weight:800; color:var(--c-text); line-height:1.1; }
.im-stat-lbl { font-size:10px; font-weight:700; color:var(--c-muted);
    text-transform:uppercase; letter-spacing:.6px; margin-top:4px; }

.im-filter { display:flex; gap:10px; align-items:flex-end; flex-wrap:wrap; margin-bottom:14px; }
.form-group { margin-bottom:0; }
.form-label { font-size:11px; font-weight:700; color:var(--c-muted);
    text-transform:uppercase; letter-spacing:.4px; margin-bottom:5px; display:block; }
.form-input { width:260px; padding:8px 11px; border:1px solid var(--c-border); border-radius:7px;
    font-size:13px; color:var(--c-text); background:#fff; }
.form-input:focus { outline:2px solid var(--c-accent); border-color:var(--c-accent); }
select.form-input { height:auto !important; min-height:38px !important; line-height:1.4 !important;
    box-sizing:border-box !important; -webkit-appearance:menulist !important;
    appearance:menulist !important; padding:8px 11px !important; width:200px; }
select.form-input option { font-size:13px; padding:6px; line-height:1.4; }

.btn { display:inline-flex; align-items:center; justify-content:center; gap:6px;
    padding:0 18px; height:36px; border-radius:7px; cursor:pointer; font-size:13px;
    font-weight:600; border:none; line-height:1; white-space:nowrap; transition:all .15s;
    font-family:inherit; text-decoration:none; }
.btn-primary { background:var(--c-accent); color:#fff; }
.btn-primary:hover { background:var(--c-accent-hover); }
.btn-primary:disabled { background:#9eb4d4; cursor:not-allowed; }
.btn-outline { background:#fff; color:var(--c-text); border:1px solid var(--c-border); }
.btn-outline:hover { border-color:var(--c-accent); color:var(--c-accent); background:var(--c-accent-light); }
.btn-danger-outline { background:#fff; color:var(--c-danger); border:1px solid var(--c-danger-border); }
.btn-danger-outline:hover { background:var(--c-danger-bg); }
.btn-danger-outline:disabled { color:#c7b1b1; border-color:#eee; cursor:not-allowed; background:#fafafa; }
.btn-sm { height:30px; padding:0 12px; font-size:12px; }

.badge { display:inline-flex; align-items:center; gap:3px; padding:3px 9px; border-radius:20px;
    font-size:11px; font-weight:600; white-space:nowrap; }
.badge-ok { background:var(--c-success-bg); color:var(--c-success); }
.badge-warn { background:var(--c-warn-bg); color:var(--c-warn); }
.badge-err { background:var(--c-danger-bg); color:var(--c-danger); }
.badge-info { background:var(--c-accent-light); color:var(--c-accent); }
.badge-gray { background:#f1f5f9; color:#64748b; }

.card { background:var(--c-card); border:1px solid var(--c-border); border-radius:10px;
    box-shadow:var(--c-shadow); overflow:hidden; }
.card-hdr { padding:14px 18px; border-bottom:1px solid var(--c-border); background:var(--c-bg); }
.card-hdr h3 { font-size:15px; font-weight:700; color:var(--c-text); margin:0; }
.card-hdr p { font-size:12px; color:var(--c-muted); margin:4px 0 0; }

.tbl { width:100%; border-collapse:collapse; font-size:13px; }
.tbl th { background:var(--c-bg); font-weight:600; padding:10px 14px; text-align:left;
    border-bottom:2px solid var(--c-border); color:var(--c-muted);
    font-size:11px; text-transform:uppercase; letter-spacing:.5px; white-space:nowrap; }
.tbl td { padding:10px 14px; border-bottom:1px solid #f1f5f9; vertical-align:middle; }
.tbl tr:last-child td { border-bottom:none; }
.tbl tr:hover td { background:#fafbff; }
.tbl .mono { font-family:'JetBrains Mono','Courier New',monospace; font-size:11px; color:var(--c-muted); }
.im-user { font-weight:700; color:var(--c-text); }
.im-fullname { font-size:11px; color:var(--c-muted); }
.im-groups { font-size:11px; color:var(--c-muted); max-width:260px; }
.im-actions { display:flex; gap:6px; justify-content:flex-end; }
.im-block { font-size:11px; color:var(--c-muted); font-style:italic; }

.empty { padding:48px 20px; text-align:center; }
.empty-icon { font-size:48px; display:block; margin-bottom:14px; line-height:1; }
.empty-title { font-size:15px; font-weight:700; color:var(--c-text); margin-bottom:6px; }
.empty-desc { font-size:13px; color:var(--c-muted); }

.modal-backdrop { display:none; position:fixed; inset:0; background:rgba(0,0,0,.45);
    z-index:9000; align-items:center; justify-content:center; }
.modal-backdrop.open { display:flex; }
.modal-box { background:#fff; border-radius:10px; box-shadow:0 8px 32px rgba(0,0,0,.2);
    width:840px; max-width:96vw; max-height:88vh; display:flex; flex-direction:column; }
.modal-hdr { padding:14px 18px; border-bottom:1px solid var(--c-border);
    display:flex; align-items:center; justify-content:space-between; }
.modal-hdr h3 { margin:0; font-size:15px; font-weight:700; color:var(--c-text); }
.modal-body { padding:18px; flex:1; overflow-y:auto; white-space:normal;
    word-wrap:break-word; overflow-wrap:break-word; }
.modal-footer { padding:12px 18px; border-top:1px solid var(--c-border);
    display:flex; gap:8px; justify-content:flex-end; }
.modal-close { background:none; border:none; font-size:20px; cursor:pointer; color:var(--c-muted); line-height:1; }

.im-sec { margin-bottom:18px; }
.im-sec-title { font-size:11px; font-weight:700; color:var(--c-muted); text-transform:uppercase;
    letter-spacing:.6px; margin-bottom:8px; padding-bottom:5px; border-bottom:1px solid var(--c-border); }
.im-kv { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:8px 16px; }
.im-kv div { font-size:12px; color:var(--c-text); }
.im-kv span { color:var(--c-muted); display:block; font-size:10px; text-transform:uppercase;
    letter-spacing:.4px; font-weight:700; }
.im-chiplist { display:flex; flex-wrap:wrap; gap:5px; }

.status-msg { font-size:12px; font-weight:600; padding:8px 12px; border-radius:7px; margin-bottom:12px; display:none; }
.status-msg.ok { display:block; background:var(--c-success-bg); color:var(--c-success); }
.status-msg.err { display:block; background:var(--c-danger-bg); color:var(--c-danger); }
</style>

<div class="im-wrap">
    <div class="im-title">🎭 Impersonate</div>
    <div class="im-sub">Assuma a sessao de um usuario do Zabbix para reproduzir exatamente o que ele ve.</div>

    <div id="im-status" class="status-msg"></div>

    <div class="im-callout">
        <div class="im-callout-icon">🔒</div>
        <div>
            <div class="im-callout-title">Politica ativa deste modulo</div>
            <div class="im-callout-body">
                Modo <strong><?= $readonly ? 'somente leitura' : 'leitura e escrita' ?></strong> durante a
                impersonacao&nbsp;&middot;
                expiracao automatica em <strong><?= $ttl > 0 ? (int) round($ttl / 60).' minutos' : 'nunca' ?></strong>&nbsp;&middot;
                alvos Super Admin <strong><?= (int) $data['config']['block_super_admin_target'] === 1 ? 'bloqueados' : 'permitidos' ?></strong>.
                Toda impersonacao e gravada em <code>module_impersonate_log</code> e tambem gera um
                <code>Login</code> no audit log nativo do Zabbix, em nome do usuario alvo.
            </div>
        </div>
    </div>

    <?php if ($data['roles_missing_access']): ?>
    <div class="im-callout im-callout-danger">
        <div class="im-callout-icon">🔒</div>
        <div>
            <div class="im-callout-title" style="color:var(--c-danger);">
                <?= count($data['roles_missing_access']) ?> role(s) sem acesso ao modulo &mdash; usuarios delas nao podem ser impersonados
            </div>
            <div class="im-callout-body">
                Se a role do usuario alvo nao enxerga este modulo, o Zabbix nem carrega o
                <code>Module.php</code> durante a impersonacao: o modo somente-leitura e o item
                <em>Sair da impersonacao</em> deixariam de existir. Por isso o modulo recusa.
                <div style="margin-top:8px;">
                    Libere em <strong>Users &rarr; User roles &rarr; \<role\> &rarr; Access to modules</strong>, marcando
                    <em>Impersonate</em> nestas roles:
                </div>
                <div class="im-chiplist" style="margin-top:8px;">
                    <?php foreach ($data['roles_missing_access'] as $role_name): ?>
                        <span class="badge badge-err"><?= $e($role_name) ?></span>
                    <?php endforeach; ?>
                </div>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <div class="im-stats">
        <div class="im-stat">
            <div class="im-stat-num"><?= (int) $data['stats']['total'] ?></div>
            <div class="im-stat-lbl">Usuarios listados</div>
        </div>
        <div class="im-stat">
            <div class="im-stat-num"><?= (int) $data['stats']['impersonable'] ?></div>
            <div class="im-stat-lbl">Impersonaveis</div>
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
            <h3>👥 Usuarios</h3>
            <p>Clique em <em>Perfil</em> para inspecionar permissoes sem trocar de sessao.</p>
        </div>
        <?php if (!$data['users']): ?>
            <div class="empty">
                <span class="empty-icon">🔍</span>
                <div class="empty-title">Nenhum usuario encontrado</div>
                <div class="empty-desc">Ajuste os filtros e tente novamente.</div>
            </div>
        <?php else: ?>
        <table class="tbl">
            <thead>
                <tr>
                    <th>Usuario</th>
                    <th>Role</th>
                    <th>Tipo</th>
                    <th>Grupos</th>
                    <th>Ultimo acesso</th>
                    <th style="text-align:right;">Acoes</th>
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

        html += section('Identificacao', kv([
            ['Username', u.username],
            ['Nome', u.fullname || '-'],
            ['Role', u.role_name + ' (' + u.role_type_label + ')'],
            ['Origem', u.provisioned ? 'Provisionado (SSO/LDAP)' : 'Interno'],
            ['Idioma / Tema', u.lang + ' / ' + u.theme],
            ['Timezone', u.timezone],
            ['Autologin', u.autologin ? 'Sim' : 'Nao'],
            ['Autologout', u.autologout],
            ['Refresh', u.refresh],
            ['Linhas por pagina', u.rows_per_page],
            ['URL inicial', u.url || '-'],
            ['Status', u.disabled ? 'DESABILITADO' : (u.gui_disabled ? 'GUI desabilitada' : 'Ativo')]
        ]));

        if (u.attempt_failed > 0) {
            html += section('Tentativas de login falhas', kv([
                ['Falhas', u.attempt_failed],
                ['Ultimo IP', u.attempt_ip || '-'],
                ['Quando', u.attempt_clock]
            ]));
        }

        html += section('Grupos de usuario', table(
            ['Grupo', 'Usuarios', 'GUI access', 'Debug'],
            p.groups.map(function (g) { return [g.name, g.users_status, g.gui_access, g.debug_mode]; })
        ));

        html += section('Permissoes efetivas em host groups', table(
            ['Host group', 'Permissao'],
            p.permissions.map(function (x) { return [x.name, x.permission]; })
        ));

        html += section('Medias / notificacoes', table(
            ['Tipo', 'Enviar para', 'Media', 'Media type', 'Periodo'],
            p.medias.map(function (m) { return [m.media_type, m.sendto, m.active, m.mt_status, m.period]; })
        ));

        html += section('Sessoes ativas', table(
            ['Session (prefixo)', 'Ultimo acesso'],
            p.sessions.map(function (s) { return [s.sessionid, s.lastaccess]; })
        ));

        html += section('UI liberada pela role', chips(p.role_rules.ui_allowed, 'badge-ok'));
        html += section('UI negada pela role', chips(p.role_rules.ui_denied, 'badge-err'));
        html += section('Acoes liberadas', chips(p.role_rules.actions_allowed, 'badge-info'));

        html += section('Historico de impersonacao deste usuario', table(
            ['Quem impersonou', 'Inicio', 'Fim', 'Motivo', 'Somente leitura'],
            p.history.map(function (h) {
                return [h.actor_username, h.started, h.ended, h.end_reason || '-', h.readonly ? 'Sim' : 'Nao'];
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

    document.getElementById('im-modal-close').addEventListener('click', closeModal);
    document.getElementById('im-modal-dismiss').addEventListener('click', closeModal);
    modal.addEventListener('click', function (ev) { if (ev.target === modal) { closeModal(); } });
    document.addEventListener('keydown', function (ev) { if (ev.key === 'Escape') { closeModal(); } });

    document.addEventListener('click', function (ev) {
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
            'Assumir a sessao de "' + username + '"?\n\n' +
            'Voce sera deslogado da sua propria sessao ate encerrar a impersonacao ' +
            'pelo item "Sair da impersonacao" no topo do menu lateral.\n\n' +
            'Esta acao fica registrada no log de auditoria.'
        )) {
            return;
        }

        impBtn.disabled = true;
        impBtn.textContent = 'Entrando...';

        post('zbx.impersonate.start', { userid: impBtn.dataset.impersonate, submit_action: 'start' })
            .then(function (res) {
                if (res && res.error && res.error.title) {
                    showStatus(res.error.title, false);
                    impBtn.disabled = false;
                    impBtn.textContent = 'Impersonar';
                    return;
                }

                if (!res || !res.success) {
                    showStatus((res && res.error) || 'Falha ao iniciar a impersonacao.', false);
                    impBtn.disabled = false;
                    impBtn.textContent = 'Impersonar';
                    return;
                }

                showStatus('Impersonacao iniciada. Redirecionando...', true);
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
