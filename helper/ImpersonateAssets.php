<?php declare(strict_types=1);
/**
 * Impersonate - CSS compartilhado das views.
 *
 * Existia uma copia do mesmo bloco <style> em cada view (list, log, stop) e elas
 * ja tinham divergido entre si. Aqui fica a fonte unica.
 *
 * Por que inline e nao um .css estatico: o F5 BIG-IP na frente do frontend bloqueia
 * assets estaticos servidos de dentro de modules/, entao TODO CSS/JS do modulo tem
 * que viajar no proprio HTML.
 *
 * ESCOPO: as regras sao prefixadas por .im-wrap / .modal-backdrop de proposito.
 * A versao anterior declarava as variaveis em `:root` e o reset em `*`, o que
 * vazava para o documento inteiro e podia sobrescrever variaveis do proprio Zabbix.
 *
 * Autor: Rafael M. A. Leao Ereno - MALE
 */

namespace Modules\ZbxImpersonate\Helper;

class ImpersonateAssets {

	/** Temas escuros do Zabbix 7.0. */
	private const DARK_THEMES = ['dark-theme', 'hc-dark'];

	/**
	 * Bloco <style> completo, com a paleta ajustada ao tema do usuario.
	 *
	 * O tema e lido de CWebUser em vez de detectado por CSS: o Zabbix troca de tema
	 * por folha de estilo inteira, sem classe no <body>, entao nao ha seletor que
	 * permita reagir a isso puramente em CSS.
	 */
	public static function css(): string {
		$theme = (string) (\CWebUser::$data['theme'] ?? '');
		$palette = in_array($theme, self::DARK_THEMES, true) ? self::darkPalette() : self::lightPalette();

		return '<style>'."\n".
			'.im-wrap, .modal-backdrop {'."\n".$palette."\n".'}'."\n".
			self::rules().
			'</style>';
	}

	// -----------------------------------------------------------------------

	private static function lightPalette(): string {
		return <<<'CSS'
    --c-bg:#f4f6f9; --c-card:#fff; --c-border:#dde3ec;
    --c-accent:#1565c0; --c-accent-light:#e8f0fe; --c-accent-hover:#0d47a1;
    --c-text:#1a1f36; --c-muted:#6b7a99;
    --c-success:#1b7e47; --c-success-bg:#e8f5e9;
    --c-danger:#b71c1c;  --c-danger-bg:#fff5f5; --c-danger-border:#f5c6c6;
    --c-warn:#bf6000;    --c-warn-bg:#fff8e1;    --c-warn-border:#ffe082;
    --c-input-bg:#fff; --c-row-hover:#fafbff; --c-row-line:#f1f5f9;
    --c-chip-bg:#f1f5f9; --c-chip-fg:#64748b;
    --c-shadow:0 1px 4px rgba(0,0,0,.08);
    --c-shadow-md:0 4px 6px rgba(0,0,0,.05),0 2px 4px rgba(0,0,0,.04);
CSS;
	}

	private static function darkPalette(): string {
		return <<<'CSS'
    --c-bg:#16181c; --c-card:#1f2227; --c-border:#333941;
    --c-accent:#5b9dd9; --c-accent-light:#1d2b3a; --c-accent-hover:#7db3e3;
    --c-text:#dbdee2; --c-muted:#8f98a3;
    --c-success:#5cc98a; --c-success-bg:#16301f;
    --c-danger:#f27979;  --c-danger-bg:#331a1a; --c-danger-border:#5c2b2b;
    --c-warn:#e6a13c;    --c-warn-bg:#33280f;    --c-warn-border:#5c4413;
    --c-input-bg:#0f1114; --c-row-hover:#24282e; --c-row-line:#2a2f36;
    --c-chip-bg:#2a2f36; --c-chip-fg:#a5aeb9;
    --c-shadow:0 1px 4px rgba(0,0,0,.5);
    --c-shadow-md:0 4px 6px rgba(0,0,0,.45),0 2px 4px rgba(0,0,0,.4);
CSS;
	}

	private static function rules(): string {
		return <<<'CSS'
.im-wrap *, .modal-backdrop * { box-sizing:border-box; }

.im-wrap { padding:16px 18px; }
.im-title { font-size:19px; font-weight:800; color:var(--c-text); margin-bottom:4px; }
.im-sub { font-size:12px; color:var(--c-muted); margin-bottom:16px; }
.im-build { display:inline-block; margin-left:8px; padding:2px 8px; border-radius:10px;
    background:var(--c-chip-bg); color:var(--c-chip-fg); font-size:10px; font-weight:700;
    font-family:'JetBrains Mono','Courier New',monospace; letter-spacing:.3px; }

.im-callout { display:flex; gap:12px; align-items:flex-start; background:var(--c-warn-bg);
    border:1px solid var(--c-warn-border); border-radius:10px; padding:12px 16px; margin-bottom:16px; }
.im-callout-danger { background:var(--c-danger-bg); border-color:var(--c-danger-border); }
.im-callout-icon { font-size:20px; line-height:1.2; }
.im-callout-title { font-size:13px; font-weight:700; color:var(--c-warn); margin-bottom:4px; }
.im-callout-body { font-size:12px; color:var(--c-text); line-height:1.55; }
.im-callout-body code { background:var(--c-chip-bg); color:var(--c-chip-fg); padding:1px 5px;
    border-radius:4px; font-family:'JetBrains Mono','Courier New',monospace; font-size:11px; }

.im-stats { display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:10px; margin-bottom:16px; }
.im-stat { background:var(--c-card); border:1px solid var(--c-border); border-radius:10px;
    box-shadow:var(--c-shadow); padding:12px 16px; }
.im-stat-num { font-size:22px; font-weight:800; color:var(--c-text); line-height:1.1; }
.im-stat-lbl { font-size:10px; font-weight:700; color:var(--c-muted);
    text-transform:uppercase; letter-spacing:.6px; margin-top:4px; }

.im-filter { display:flex; gap:10px; align-items:flex-end; flex-wrap:wrap; margin-bottom:14px; }
.im-wrap .form-group { margin-bottom:0; }
.im-wrap .form-label { font-size:11px; font-weight:700; color:var(--c-muted);
    text-transform:uppercase; letter-spacing:.4px; margin-bottom:5px; display:block; }
.im-wrap .form-hint { font-size:11px; color:var(--c-muted); }
.im-wrap .form-input { width:260px; padding:8px 11px; border:1px solid var(--c-border); border-radius:7px;
    font-size:13px; color:var(--c-text); background:var(--c-input-bg); }
.im-wrap .form-input:focus { outline:2px solid var(--c-accent); border-color:var(--c-accent); }
.im-wrap select.form-input { height:auto !important; min-height:38px !important; line-height:1.4 !important;
    box-sizing:border-box !important; -webkit-appearance:menulist !important;
    appearance:menulist !important; padding:8px 11px !important; width:200px; }
.im-wrap select.form-input option { font-size:13px; padding:6px; line-height:1.4; }

.im-wrap .btn, .modal-backdrop .btn { display:inline-flex; align-items:center; justify-content:center;
    gap:6px; padding:0 18px; height:36px; border-radius:7px; cursor:pointer; font-size:13px;
    font-weight:600; border:none; line-height:1; white-space:nowrap; transition:all .15s;
    font-family:inherit; text-decoration:none; }
.im-wrap .btn-primary, .modal-backdrop .btn-primary { background:var(--c-accent); color:#fff; }
.im-wrap .btn-primary:hover { background:var(--c-accent-hover); }
.im-wrap .btn-primary:disabled { background:var(--c-muted); cursor:not-allowed; }
.im-wrap .btn-outline, .modal-backdrop .btn-outline { background:var(--c-card); color:var(--c-text);
    border:1px solid var(--c-border); }
.im-wrap .btn-outline:hover { border-color:var(--c-accent); color:var(--c-accent); background:var(--c-accent-light); }
.im-wrap .btn-danger-outline { background:var(--c-card); color:var(--c-danger); border:1px solid var(--c-danger-border); }
.im-wrap .btn-danger-outline:hover { background:var(--c-danger-bg); }
.im-wrap .btn-danger-outline:disabled { color:var(--c-muted); border-color:var(--c-border);
    cursor:not-allowed; background:var(--c-bg); }
.im-wrap .btn-sm { height:30px; padding:0 12px; font-size:12px; }

.im-wrap .badge, .modal-backdrop .badge { display:inline-flex; align-items:center; gap:3px;
    padding:3px 9px; border-radius:20px; font-size:11px; font-weight:600; white-space:nowrap; }
.im-wrap .badge-ok, .modal-backdrop .badge-ok { background:var(--c-success-bg); color:var(--c-success); }
.im-wrap .badge-warn, .modal-backdrop .badge-warn { background:var(--c-warn-bg); color:var(--c-warn); }
.im-wrap .badge-err, .modal-backdrop .badge-err { background:var(--c-danger-bg); color:var(--c-danger); }
.im-wrap .badge-info, .modal-backdrop .badge-info { background:var(--c-accent-light); color:var(--c-accent); }
.im-wrap .badge-gray, .modal-backdrop .badge-gray { background:var(--c-chip-bg); color:var(--c-chip-fg); }

.im-wrap .card { background:var(--c-card); border:1px solid var(--c-border); border-radius:10px;
    box-shadow:var(--c-shadow); overflow:hidden; }
.im-wrap .card-hdr { padding:14px 18px; border-bottom:1px solid var(--c-border); background:var(--c-bg); }
.im-wrap .card-hdr h3 { font-size:15px; font-weight:700; color:var(--c-text); margin:0; }
.im-wrap .card-hdr p { font-size:12px; color:var(--c-muted); margin:4px 0 0; }
.im-wrap .card-body { padding:18px; font-size:13px; color:var(--c-text); line-height:1.6; }

.im-wrap .tbl, .modal-backdrop .tbl { width:100%; border-collapse:collapse; font-size:13px; }
.im-wrap .tbl th, .modal-backdrop .tbl th { background:var(--c-bg); font-weight:600; padding:10px 14px;
    text-align:left; border-bottom:2px solid var(--c-border); color:var(--c-muted);
    font-size:11px; text-transform:uppercase; letter-spacing:.5px; white-space:nowrap; }
.im-wrap .tbl td, .modal-backdrop .tbl td { padding:10px 14px; border-bottom:1px solid var(--c-row-line);
    vertical-align:middle; color:var(--c-text); }
.im-wrap .tbl tr:last-child td, .modal-backdrop .tbl tr:last-child td { border-bottom:none; }
.im-wrap .tbl tr:hover td, .modal-backdrop .tbl tr:hover td { background:var(--c-row-hover); }
.im-wrap .tbl .mono, .modal-backdrop .tbl .mono { font-family:'JetBrains Mono','Courier New',monospace;
    font-size:11px; color:var(--c-muted); }

.im-user { font-weight:700; color:var(--c-text); }
.im-fullname { font-size:11px; color:var(--c-muted); }
.im-groups { font-size:11px; color:var(--c-muted); max-width:260px; }
.im-actions { display:flex; gap:6px; justify-content:flex-end; }
.im-block { font-size:11px; color:var(--c-muted); font-style:italic; }
.im-agent { font-size:10px; color:var(--c-muted); max-width:260px; display:block;
    overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }

.im-wrap .empty { padding:48px 20px; text-align:center; }
.im-wrap .empty-icon { font-size:48px; display:block; margin-bottom:14px; line-height:1; }
.im-wrap .empty-title { font-size:15px; font-weight:700; color:var(--c-text); margin-bottom:6px; }
.im-wrap .empty-desc { font-size:13px; color:var(--c-muted); }

.modal-backdrop { display:none; position:fixed; inset:0; background:rgba(0,0,0,.45);
    z-index:9000; align-items:center; justify-content:center; }
.modal-backdrop.open { display:flex; }
.modal-box { background:var(--c-card); border-radius:10px; box-shadow:0 8px 32px rgba(0,0,0,.35);
    width:840px; max-width:96vw; max-height:88vh; display:flex; flex-direction:column; }
.modal-hdr { padding:14px 18px; border-bottom:1px solid var(--c-border);
    display:flex; align-items:center; justify-content:space-between; }
.modal-hdr h3 { margin:0; font-size:15px; font-weight:700; color:var(--c-text); }
.modal-body { padding:18px; flex:1; overflow-y:auto; white-space:normal;
    word-wrap:break-word; overflow-wrap:break-word; color:var(--c-text); }
.modal-footer { padding:12px 18px; border-top:1px solid var(--c-border);
    display:flex; gap:8px; justify-content:flex-end; }
.modal-close { background:none; border:none; font-size:20px; cursor:pointer;
    color:var(--c-muted); line-height:1; }

.im-sec { margin-bottom:18px; }
.im-sec-title { font-size:11px; font-weight:700; color:var(--c-muted); text-transform:uppercase;
    letter-spacing:.6px; margin-bottom:8px; padding-bottom:5px; border-bottom:1px solid var(--c-border); }
.im-kv { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:8px 16px; }
.im-kv div { font-size:12px; color:var(--c-text); }
.im-kv span { color:var(--c-muted); display:block; font-size:10px; text-transform:uppercase;
    letter-spacing:.4px; font-weight:700; }
.im-chiplist { display:flex; flex-wrap:wrap; gap:5px; }

.status-msg { font-size:12px; font-weight:600; padding:8px 12px; border-radius:7px;
    margin-bottom:12px; display:none; }
.status-msg.ok { display:block; background:var(--c-success-bg); color:var(--c-success); }
.status-msg.err { display:block; background:var(--c-danger-bg); color:var(--c-danger); }

.im-reason { width:100%; min-height:64px; padding:8px 11px; border:1px solid var(--c-border);
    border-radius:7px; font-size:13px; font-family:inherit; color:var(--c-text);
    background:var(--c-input-bg); resize:vertical; }
.im-reason:focus { outline:2px solid var(--c-accent); border-color:var(--c-accent); }
CSS;
	}
}
