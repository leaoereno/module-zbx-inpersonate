#!/usr/bin/env bash
#
# Impersonate - instalacao / atualizacao do modulo no frontend Zabbix 7.0.
#
# Uso:
#   ./install.sh                  # instala/atualiza em /usr/share/zabbix/modules/<nome-da-pasta>
#   ZBXDIR=/caminho ./install.sh  # sobrescreve o diretorio de modulos
#   MODULE=outro-nome ./install.sh  # sobrescreve o nome da pasta de destino
#
# Se o script ja estiver rodando de dentro do destino (deploy via git clone/pull),
# a copia e pulada - mas dono, permissao e restart do PHP-FPM continuam sendo feitos.
#
# Autor: Rafael M. A. Leao Ereno - MALE

set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# O nome da pasta vem do proprio local do script: assim funciona tanto para
# module-zbx-inpersonate (nome do repo) quanto para qualquer clone renomeado,
# e o SRC == DEST do deploy por git continua sendo detectado corretamente.
MODULE="${MODULE:-$(basename "${SRC}")}"
ZBXDIR="${ZBXDIR:-/usr/share/zabbix/modules}"
DEST="${ZBXDIR}/${MODULE}"

log()  { printf '\033[0;36m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[0;32m OK\033[0m %s\n' "$*"; }
warn() { printf '\033[0;33m  !\033[0m %s\n' "$*"; }
die()  { printf '\033[0;31mERR\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Rode como root (o destino fica em ${ZBXDIR})."

# ---------------------------------------------------------------------------
# 1. Dono do processo web (AlmaLinux/RHEL: apache | Debian/Ubuntu: www-data)
# ---------------------------------------------------------------------------
if id -u apache >/dev/null 2>&1; then
    WEBUSER="apache"
elif id -u www-data >/dev/null 2>&1; then
    WEBUSER="www-data"
else
    die "Nao encontrei o usuario do webserver (apache/www-data)."
fi
log "Usuario do webserver: ${WEBUSER}"

# ---------------------------------------------------------------------------
# 2. Copia (pulada quando SRC == DEST, caso do deploy por git)
# ---------------------------------------------------------------------------
if [[ "${SRC}" == "${DEST}" ]]; then
    log "SRC == DEST, deploy via git detectado - pulando copia."
else
    [[ -d "${ZBXDIR}" ]] || die "Diretorio de modulos nao existe: ${ZBXDIR}"
    log "Copiando ${SRC} -> ${DEST}"
    mkdir -p "${DEST}"
    cp -a "${SRC}/manifest.json" "${SRC}/Module.php" "${DEST}/"
    for dir in actions views helper sql; do
        [[ -d "${SRC}/${dir}" ]] && cp -a "${SRC}/${dir}" "${DEST}/"
    done
    cp -a "${SRC}/install.sh" "${DEST}/" 2>/dev/null || true
    cp -a "${SRC}/README.md" "${DEST}/" 2>/dev/null || true
    ok "Arquivos copiados."
fi

# ---------------------------------------------------------------------------
# 3. Sanidade: manifest e sintaxe PHP
# ---------------------------------------------------------------------------
log "Validando manifest.json"
if command -v python3 >/dev/null 2>&1; then
    python3 -c "import json; json.load(open('${DEST}/manifest.json'))" || die "manifest.json invalido."
    ok "manifest.json valido."
elif command -v php >/dev/null 2>&1; then
    php -r 'exit(json_decode(file_get_contents($argv[1]), true) === null ? 1 : 0);' "${DEST}/manifest.json" \
        || die "manifest.json invalido."
    ok "manifest.json valido."
else
    warn "Sem python3 nem php - pulando validacao do manifest.json."
fi

if ! grep -q 'Rafael M. A. Leão Ereno - MALE' "${DEST}/manifest.json"; then
    warn "Campo author fora do padrao canonico no manifest.json."
fi

if command -v php >/dev/null 2>&1; then
    log "php -l em todos os arquivos"
    fail=0
    while IFS= read -r -d '' f; do
        php -l "$f" >/dev/null || { warn "Erro de sintaxe: $f"; fail=1; }
    done < <(find "${DEST}" -name '*.php' -print0)
    [[ $fail -eq 0 ]] || die "Corrija os erros de sintaxe antes de continuar."
    ok "Sintaxe PHP OK."
else
    warn "CLI do php nao encontrada - pulando php -l."
fi

# ---------------------------------------------------------------------------
# 4. Dono e permissao
# ---------------------------------------------------------------------------
# .git fica de fora: dar dono apache ao .git e exatamente o que dispara o
# "detected dubious ownership" no proximo git pull rodado como root.
log "Ajustando dono/permissao (preservando .git)"
for item in manifest.json Module.php README.md install.sh actions views helper sql; do
    [[ -e "${DEST}/${item}" ]] && chown -R "${WEBUSER}:${WEBUSER}" "${DEST}/${item}"
done
chown "${WEBUSER}:${WEBUSER}" "${DEST}"
find "${DEST}" -path "${DEST}/.git" -prune -o -type d -exec chmod 755 {} +
find "${DEST}" -path "${DEST}/.git" -prune -o -type f -exec chmod 644 {} +
chmod 755 "${DEST}/install.sh" 2>/dev/null || true
ok "Permissoes ajustadas."

# ---------------------------------------------------------------------------
# 5. PHP-FPM (nome real do unit varia - nunca chutar php8.x-fpm)
# ---------------------------------------------------------------------------
FPM_UNIT="$(systemctl list-units --type=service --all --no-legend 2>/dev/null \
    | awk '{print $1}' | grep -E '^php[0-9.]*-fpm\.service$' | head -n1 || true)"

if [[ -n "${FPM_UNIT}" ]]; then
    log "Reiniciando ${FPM_UNIT}"
    # Sem "|| warn" o set -e abortaria antes de imprimir os proximos passos.
    if systemctl restart "${FPM_UNIT}"; then
        ok "${FPM_UNIT} reiniciado (OPcache limpo)."
    else
        warn "Falha ao reiniciar ${FPM_UNIT} - limpe o OPcache manualmente."
    fi
else
    warn "Unit do PHP-FPM nao encontrada. Reinicie manualmente e limpe o OPcache."
fi

if systemctl is-active --quiet httpd 2>/dev/null; then
    log "Recarregando httpd"
    systemctl reload httpd || warn "Falha no reload do httpd."
fi

cat <<EOF

------------------------------------------------------------------
Modulo instalado em: ${DEST}

Proximos passos:
  1. Zabbix UI -> Administration -> General -> Modules -> Scan directory
  2. Habilitar o modulo "Impersonate"
  3. Users -> Impersonate (o item so aparece para Super Admin)

ATRAS DE LOAD BALANCER (F5): repita este script em CADA frontend
(lnxdczbxfront01, lnxdczbxfront02, ...). O LB pode servir codigo
antigo de um no que nao foi atualizado.

A role do usuario ALVO tambem precisa enxergar o modulo
(Users -> User roles -> <role> -> Access to modules), senao o guard de
somente-leitura e o botao de sair nao existiriam durante a impersonacao
-- e o modulo recusa impersonar nesse caso.

Diagnostico de permissoes e auditoria (somente SELECTs):
  mysql -u zabbix -p zabbix < ${DEST}/sql/role_rule.sql
------------------------------------------------------------------
EOF
