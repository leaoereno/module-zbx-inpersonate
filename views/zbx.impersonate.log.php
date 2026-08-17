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
		case ImpersonateHelper::END_LOGOUT:  return ['logout', 'badge-info'];
		case ImpersonateHelper::END_STALE:   return ['fechada por inatividade', 'badge-warn'];
	}

	return ['encerrada', 'badge-ok'];
};
?>
<?= \Modules\ZbxImpersonate\Helper\ImpersonateAssets::css() ?>

<div class="im-wrap">
    <div class="im-title">📋 Impersonate &mdash; log de auditoria</div>
    <div class="im-sub">
        Registro próprio do módulo. O Zabbix também grava um evento <code>Login</code> nativo em nome do
        usuário alvo a cada impersonação (Reports &rarr; Audit log).
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
            <div class="im-stat-lbl">Duração média</div>
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
            <h3>Histórico</h3>
            <p>Ordenado do mais recente para o mais antigo.</p>
        </div>
        <?php if (!$data['rows']): ?>
            <div class="empty">
                <span class="empty-icon">🗂️</span>
                <div class="empty-title">Nenhuma impersonação registrada</div>
                <div class="empty-desc">Assim que alguém usar o módulo, os eventos aparecem aqui.</div>
            </div>
        <?php else: ?>
        <table class="tbl">
            <thead>
                <tr>
                    <th>#</th>
                    <th>Quem impersonou</th>
                    <th>Alvo</th>
                    <th>Modo</th>
                    <th>Início</th>
                    <th>Fim</th>
                    <th>Duração</th>
                    <th>Status</th>
                    <th>Motivo</th>
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
                        <?php $motivo = (string) ($row['reason'] ?? ''); ?>
                        <span class="im-agent" title="<?= $e($motivo) ?>"><?= $motivo !== '' ? $e($motivo) : '-' ?></span>
                    </td>
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
