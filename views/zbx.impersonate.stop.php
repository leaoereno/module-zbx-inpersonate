<?php declare(strict_types=1);
/**
 * Impersonate - view do stop.
 *
 * ATENÇÃO: a partir da 1.2.0 esta view NÃO é mais renderizada. Todos os desfechos
 * do stop respondem com CControllerResponseRedirect:
 *
 *   - restaurou    -> zbx.impersonate.list
 *   - não restaurou -> index.php?reconnect=1 (login)
 *
 * O motivo: quando não há sessão de origem para restaurar, o stop() é obrigado a
 * fazer CSessionHelper::unset(['sessionid']) — senão o Super Admin continuaria
 * logado como o usuário alvo, sem estado de impersonação, numa troca silenciosa
 * de privilégio. E renderizar um layout.htmlpage completo depois de derrubar a
 * sessão é pedir fatal no frontend.
 *
 * O arquivo é mantido porque a chave "view" da action no manifest.json precisa
 * apontar para um arquivo existente — sem ela o ZBase pula a renderização de
 * propósito e o sintoma é uma página em branco, sem nada no log.
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
