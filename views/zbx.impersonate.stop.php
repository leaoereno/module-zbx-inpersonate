<?php declare(strict_types=1);
/**
 * Impersonate - fallback quando a sessão original já não existe mais.
 *
 * O caminho feliz do stop responde com CControllerResponseRedirect e esta view
 * nunca chega a renderizar. Ela so aparece quando a sessão do Super Admin
 * expirou/foi derrubada enquanto a impersonação estava ativa.
 *
 * @var CView $this
 * @var array $data
 *
 * Autor: Rafael M. A. Leao Ereno - MALE
 */

$e = static function ($v): string {
	return htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8');
};
?>
<?= \Modules\ZbxImpersonate\Helper\ImpersonateAssets::css() ?>

<div class="im-wrap">
    <div class="im-title">🎭 Impersonate</div>

    <div class="im-callout">
        <div class="im-callout-icon">⚠️</div>
        <div>
            <div class="im-callout-title">Impersonação encerrada, mas a sessão original não pode ser restaurada</div>
            <div>
                A sessão de <strong><?= $e($data['origin_username']) ?></strong> expirou ou foi derrubada enquanto
                você navegava como <strong><?= $e($data['target_username']) ?></strong>.
            </div>
        </div>
    </div>

    <div class="card">
        <div class="card-body">
            O estado de impersonação já foi limpo e o evento foi fechado no log de auditoria.
            Faca login novamente com a sua conta de Super Admin para continuar.
            <div style="margin-top:16px;">
                <a class="btn btn-primary" href="index.php?reconnect=1">Ir para o login</a>
            </div>
        </div>
    </div>
</div>
