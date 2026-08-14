<?php declare(strict_types=1);
/**
 * Impersonate - log de auditoria.
 *
 * @var CView $this
 * @var array $data
 *
 * Autor: Rafael M. A. Leao Ereno - MALE
 */

use Modules\ZbxImpersonate\Helper\ImpersonateHelper;

$e = static function ($v): string {
	return htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8');
};

$reason_badge = static function (string $reason, int $ended): array {
	if ($ended === 0) {
		return ['em andamento', 'badge-warn'];
	}

	switch ($reason) {
		case ImpersonateHelper::END_EXPIRED: return ['expirou', 'badge-info'];
		case ImpersonateHelper::END_INVALID: return ['invalidada', 'badge-err'];
	}

	return ['encerrada', 'badge-ok'];
};
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
}
* { box-sizing:border-box; }

.im-wrap { padding:16px 18px; }
.im-title { font-size:19px; font-weight:800; color:var(--c-text); margin-bottom:4px; }
.im-sub { font-size:12px; color:var(--c-muted); margin-bottom:16px; }

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
.form-input { width:280px; padding:8px 11px; border:1px solid var(--c-border); border-radius:7px;
    font-size:13px; color:var(--c-text); background:#fff; }
.form-input:focus { outline:2px solid var(--c-accent); border-color:var(--c-accent); }
select.form-input { height:auto !important; min-height:38px !important; line-height:1.4 !important;
    box-sizing:border-box !important; -webkit-appearance:menulist !important;
    appearance:menulist !important; padding:8px 11px !important; width:140px; }

.btn { display:inline-flex; align-items:center; justify-content:center; gap:6px; padding:0 18px;
    height:36px; border-radius:7px; cursor:pointer; font-size:13px; font-weight:600; border:none;
    line-height:1; white-space:nowrap; text-decoration:none; font-family:inherit; }
.btn-primary { background:var(--c-accent); color:#fff; }
.btn-primary:hover { background:var(--c-accent-hover); }
.btn-outline { background:#fff; color:var(--c-text); border:1px solid var(--c-border); }
.btn-outline:hover { border-color:var(--c-accent); color:var(--c-accent); background:var(--c-accent-light); }

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
.im-agent { font-size:10px; color:var(--c-muted); max-width:260px; display:block;
    overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }

.empty { padding:48px 20px; text-align:center; }
.empty-icon { font-size:48px; display:block; margin-bottom:14px; line-height:1; }
.empty-title { font-size:15px; font-weight:700; color:var(--c-text); margin-bottom:6px; }
.empty-desc { font-size:13px; color:var(--c-muted); }
</style>

<div class="im-wrap">
    <div class="im-title">📋 Impersonate &mdash; log de auditoria</div>
    <div class="im-sub">
        Registro proprio do modulo. O Zabbix tambem grava um evento <code>Login</code> nativo em nome do
        usuario alvo a cada impersonacao (Reports &rarr; Audit log).
    </div>

    <div class="im-stats">
        <div class="im-stat">
            <div class="im-stat-num"><?= (int) $data['stats']['total'] ?></div>
            <div class="im-stat-lbl">Registros exibidos</div>
        </div>
        <div class="im-stat">
            <div class="im-stat-num"><?= (int) $data['stats']['open'] ?></div>
            <div class="im-stat-lbl">Em andamento</div>
        </div>
        <div class="im-stat">
            <div class="im-stat-num" style="font-size:17px;"><?= $e($data['stats']['avg']) ?></div>
            <div class="im-stat-lbl">Duracao media</div>
        </div>
    </div>

    <form class="im-filter" method="get" action="zabbix.php">
        <input type="hidden" name="action" value="zbx.impersonate.log">
        <div class="form-group">
            <label class="form-label" for="im-log-search">Buscar</label>
            <input class="form-input" type="text" id="im-log-search" name="search"
                   value="<?= $e($data['search']) ?>" placeholder="quem impersonou, quem foi impersonado ou IP">
        </div>
        <div class="form-group">
            <label class="form-label" for="im-log-limit">Linhas</label>
            <select class="form-input" id="im-log-limit" name="limit">
                <?php foreach ([50, 100, 200, 500, 1000] as $option): ?>
                    <option value="<?= $option ?>"<?= (int) $data['limit'] === $option ? ' selected' : '' ?>>
                        <?= $option ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </div>
        <button type="submit" class="btn btn-primary">Filtrar</button>
        <a class="btn btn-outline" href="zabbix.php?action=zbx.impersonate.list">🎭 Voltar para Impersonate</a>
    </form>

    <div class="card">
        <div class="card-hdr">
            <h3>Historico</h3>
            <p>Ordenado do mais recente para o mais antigo.</p>
        </div>
        <?php if (!$data['rows']): ?>
            <div class="empty">
                <span class="empty-icon">🗂️</span>
                <div class="empty-title">Nenhuma impersonacao registrada</div>
                <div class="empty-desc">Assim que alguem usar o modulo, os eventos aparecem aqui.</div>
            </div>
        <?php else: ?>
        <table class="tbl">
            <thead>
                <tr>
                    <th>#</th>
                    <th>Quem impersonou</th>
                    <th>Alvo</th>
                    <th>Modo</th>
                    <th>Inicio</th>
                    <th>Fim</th>
                    <th>Duracao</th>
                    <th>Status</th>
                    <th>Origem</th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($data['rows'] as $row): ?>
                <?php
                    $started = (int) $row['started'];
                    $ended = (int) $row['ended'];
                    $duration = $ended > 0
                        ? ImpersonateHelper::formatDuration($ended - $started)
                        : ImpersonateHelper::formatDuration(time() - $started);
                    [$status_label, $status_class] = $reason_badge((string) $row['end_reason'], $ended);
                ?>
                <tr>
                    <td class="mono"><?= (int) $row['logid'] ?></td>
                    <td>
                        <strong><?= $e($row['actor_username']) ?></strong>
                        <span class="mono">#<?= (int) $row['actor_userid'] ?></span>
                    </td>
                    <td>
                        <strong><?= $e($row['target_username']) ?></strong>
                        <span class="mono">#<?= (int) $row['target_userid'] ?></span>
                    </td>
                    <td>
                        <?php if ((int) $row['readonly'] === 1): ?>
                            <span class="badge badge-ok">somente leitura</span>
                        <?php else: ?>
                            <span class="badge badge-err">leitura e escrita</span>
                        <?php endif; ?>
                    </td>
                    <td class="mono"><?= $e(ImpersonateHelper::formatTs($started)) ?></td>
                    <td class="mono"><?= $e(ImpersonateHelper::formatTs($ended)) ?></td>
                    <td class="mono"><?= $e($duration) ?></td>
                    <td><span class="badge <?= $e($status_class) ?>"><?= $e($status_label) ?></span></td>
                    <td>
                        <span class="mono"><?= $e($row['clientip']) ?></span>
                        <span class="im-agent" title="<?= $e($row['user_agent']) ?>"><?= $e($row['user_agent']) ?></span>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        <?php endif; ?>
    </div>
</div>
