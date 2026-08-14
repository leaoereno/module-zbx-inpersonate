<?php declare(strict_types=1);
/**
 * Impersonate - fallback quando a sessao original ja nao existe mais.
 *
 * O caminho feliz do stop responde com CControllerResponseRedirect e esta view
 * nunca chega a renderizar. Ela so aparece quando a sessao do Super Admin
 * expirou/foi derrubada enquanto a impersonacao estava ativa.
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
<style>
:root {
    --c-bg:#f4f6f9; --c-card:#fff; --c-border:#dde3ec;
    --c-accent:#1565c0; --c-accent-light:#e8f0fe; --c-accent-hover:#0d47a1;
    --c-text:#1a1f36; --c-muted:#6b7a99;
    --c-warn:#bf6000; --c-warn-bg:#fff8e1; --c-warn-border:#ffe082;
    --c-shadow:0 1px 4px rgba(0,0,0,.08);
}
* { box-sizing:border-box; }
.im-wrap { padding:16px 18px; }
.im-title { font-size:19px; font-weight:800; color:var(--c-text); margin-bottom:14px; }
.card { background:var(--c-card); border:1px solid var(--c-border); border-radius:10px;
    box-shadow:var(--c-shadow); overflow:hidden; max-width:720px; }
.card-body { padding:18px; font-size:13px; color:var(--c-text); line-height:1.6; }
.im-callout { display:flex; gap:12px; align-items:flex-start; background:var(--c-warn-bg);
    border:1px solid var(--c-warn-border); border-radius:10px; padding:12px 16px; margin-bottom:16px; }
.im-callout-icon { font-size:20px; line-height:1.2; }
.im-callout-title { font-size:13px; font-weight:700; color:var(--c-warn); margin-bottom:4px; }
.btn { display:inline-flex; align-items:center; justify-content:center; gap:6px; padding:0 18px;
    height:36px; border-radius:7px; cursor:pointer; font-size:13px; font-weight:600; border:none;
    line-height:1; text-decoration:none; }
.btn-primary { background:var(--c-accent); color:#fff; }
.btn-primary:hover { background:var(--c-accent-hover); }
</style>

<div class="im-wrap">
    <div class="im-title">🎭 Impersonate</div>

    <div class="im-callout">
        <div class="im-callout-icon">⚠️</div>
        <div>
            <div class="im-callout-title">Impersonacao encerrada, mas a sessao original nao pode ser restaurada</div>
            <div>
                A sessao de <strong><?= $e($data['origin_username']) ?></strong> expirou ou foi derrubada enquanto
                voce navegava como <strong><?= $e($data['target_username']) ?></strong>.
            </div>
        </div>
    </div>

    <div class="card">
        <div class="card-body">
            O estado de impersonacao ja foi limpo e o evento foi fechado no log de auditoria.
            Faca login novamente com a sua conta de Super Admin para continuar.
            <div style="margin-top:16px;">
                <a class="btn btn-primary" href="index.php?reconnect=1">Ir para o login</a>
            </div>
        </div>
    </div>
</div>
