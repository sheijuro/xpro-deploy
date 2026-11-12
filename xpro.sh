#!/bin/bash
###############################################################################
# xpro.sh — 3x-ui (MHSanaei) за Nginx stream/SNI на Debian, с CLI-меню
#
# Архитектура (весь внешний трафик — только 443/tcp, только IPv4):
#   Интернет ──443──> nginx stream (ssl_preread, SNI-роутинг, proxy_protocol)
#       ├─ SNI = домен Reality-inbound'а ──> 127.0.0.1:<порт>   (Xray, Reality)
#       └─ всё остальное ──> 127.0.0.1:7443 (nginx https, основной домен):
#             /<секрет>/         → панель 3x-ui          (127.0.0.1)
#             /<секрет>/         → подписка / JSON        (127.0.0.1)
#             /<секрет>/         → дашборд Fail2ban       (127.0.0.1:63034)
#             /<путь inbound'а>  → gRPC/XHTTP inbounds    (127.0.0.1, TLS снимает nginx)
#             /                  → сайт-заглушка
#   Reality target (свой же сайт) ─> 127.0.0.1:9443 (nginx https без proxy_protocol)
#
#   Конфигурация nginx всегда пересобирается из базы x-ui.db, поэтому остаётся
#   согласованной с панелью после добавления/изменения подключений.
#
# Запуск:  sudo bash xpro.sh
###############################################################################

[[ $EUID -ne 0 ]] && { echo "Запустите от root: sudo bash $0"; exit 1; }

# UTF-8 локаль нужна для кириллицы в case-шаблонах и для эмодзи (C.UTF-8 есть в Debian всегда)
export LC_ALL=C.UTF-8
set -uo pipefail

# ─── Константы ───────────────────────────────────────────────────────────────
XPRO_VERSION="1.1.0"     # номер версии: показывается в шапке меню, совпадает с тегом релиза на GitHub
XUIDB="/etc/x-ui/x-ui.db"
XUI_DIR="/usr/local/x-ui"
STATE_DIR="/etc/xpro"
STATE_FILE="${STATE_DIR}/state.env"
SUMMARY_FILE="/root/xpro-summary.txt"
WWW_PORT=7443            # nginx https c proxy_protocol (приём из stream)
TARGET_PORT=9443         # nginx https без proxy_protocol (Reality target)
PUBLISH_PANEL=y          # панель всегда публикуется через nginx по секретному пути
FINGERPRINT="firefox"    # uTLS-отпечаток во всех Reality-настройках

# Fail2ban и дашборд статистики (дашборд слушает только loopback, наружу — через nginx на 443)
DASH_PORT=63034
DASH_ROOT="/var/www/f2b"
DASH_NGINX_CONF="/etc/nginx/conf.d/f2b-dash.conf"
DASH_HTPASSWD="/etc/nginx/.htpasswd-f2b"
DASH_GEN="/usr/local/bin/f2b-dash.sh"
DASH_CRON="/etc/cron.d/f2b-dash"
F2B_JAIL_LOCAL="/etc/fail2ban/jail.local"

# GeoIP-защита админ-панелей (панель 3x-ui и дашборд; VPN и подписки не затрагиваются)
GEOIP_ALLOW_COUNTRY="RU"
GEOIP_DB="/usr/share/GeoIP/dbip-country-lite.mmdb"
GEOIP_CONF="/etc/nginx/conf.d/xpro-geoip.conf"
GEOIP_UPDATER="/usr/local/bin/xpro-geoip-update.sh"
GEOIP_CRON="/etc/cron.d/xpro-geoip"
WHITELIST_FILE="${STATE_DIR}/whitelist.txt"

# Значения по умолчанию; реальные приходят из state.env
F2B_PATH=""              # секретный путь дашборда (пусто = дашборд не установлен)
GEOIP_ENABLED="n"

# Сайты-заглушки: открытые (MIT) шаблоны Start Bootstrap, в каждом архиве есть готовая папка dist/
FAKE_SITES=(
    "https://github.com/StartBootstrap/startbootstrap-clean-blog/archive/refs/heads/master.tar.gz"
    "https://github.com/StartBootstrap/startbootstrap-freelancer/archive/refs/heads/master.tar.gz"
    "https://github.com/StartBootstrap/startbootstrap-agency/archive/refs/heads/master.tar.gz"
    "https://github.com/StartBootstrap/startbootstrap-creative/archive/refs/heads/master.tar.gz"
    "https://github.com/StartBootstrap/startbootstrap-grayscale/archive/refs/heads/master.tar.gz"
    "https://github.com/StartBootstrap/startbootstrap-resume/archive/refs/heads/master.tar.gz"
    "https://github.com/StartBootstrap/startbootstrap-landing-page/archive/refs/heads/master.tar.gz"
    "https://github.com/StartBootstrap/startbootstrap-stylish-portfolio/archive/refs/heads/master.tar.gz"
    "https://github.com/StartBootstrap/startbootstrap-new-age/archive/refs/heads/master.tar.gz"
    "https://github.com/StartBootstrap/startbootstrap-one-page-wonder/archive/refs/heads/master.tar.gz"
)

# ─── Вывод ───────────────────────────────────────────────────────────────────
msg_ok()  { echo -e "\e[1;32m[OK]\e[0m $*"; }
msg_inf() { echo -e "\e[1;34m[..]\e[0m $*"; }
msg_wrn() { echo -e "\e[1;33m[!!]\e[0m $*"; }
die()     { echo -e "\e[1;31m[ОШИБКА]\e[0m $*" >&2; exit 1; }

# ─── Ввод ────────────────────────────────────────────────────────────────────
# ask VAR "вопрос" ["значение по умолчанию"]
ask() {
    local __var="$1" __prompt="$2" __def="${3:-}" __ans
    if [[ -n "$__def" ]]; then
        read -rp "$__prompt [$__def]: " __ans
    else
        read -rp "$__prompt: " __ans
    fi
    __ans="${__ans:-$__def}"
    __ans="${__ans#"${__ans%%[![:space:]]*}"}"      # обрезаем пробелы по краям
    __ans="${__ans%"${__ans##*[![:space:]]}"}"
    printf -v "$__var" '%s' "$__ans"
}

# confirm "вопрос" [y|n] — возвращает 0 при "да"
confirm() {
    local ans def="${2:-n}"
    read -rp "$1 (y/n) [$def]: " ans
    ans="${ans:-$def}"
    [[ "$ans" =~ ^[YyДд] ]]
}

pause() { echo; read -rp "Нажмите Enter для возврата в меню..." _; }

# sq "строка" — экранирование одинарных кавычек для SQL
sq() { printf '%s' "${1//\'/\'\'}"; }

# ─── Генераторы ──────────────────────────────────────────────────────────────
gen_random_string() { head -c 4096 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c "$1"; }
gen_group_id()      { head -c 4096 /dev/urandom | tr -dc 'a-z0-9'    | head -c 16; }

# ─── Состояние установки (домены, пути, порты) ───────────────────────────────
STATE_VARS=(MAIN_DOMAIN REALITY_DOMAIN PANEL_PORT PANEL_PATH SUB_PORT SUB_PATH JSON_PATH PROJECT_NAME F2B_PATH GEOIP_ENABLED)

save_state() {
    local v
    mkdir -p "$STATE_DIR"
    for v in "${STATE_VARS[@]}"; do printf '%s=%q\n' "$v" "${!v}"; done > "$STATE_FILE"
    chmod 600 "$STATE_FILE"
}

load_state() {
    [[ -f "$STATE_FILE" ]] || return 1
    # shellcheck disable=SC1090
    . "$STATE_FILE"
}

# Пункты меню 2 и 3 работают только с установкой, сделанной этим скриптом
require_install() {
    if ! load_state || [[ ! -f "$XUIDB" ]]; then
        msg_wrn "Установка этого скрипта не найдена (${STATE_FILE}). Сначала выполните пункт [1]."
        return 1
    fi
    detect_schema
    init_used
}

# ─── Чтение inbounds из базы ─────────────────────────────────────────────────
# Все подключения на 127.0.0.1 в виде JSON-массива (sqlite3 -json на пустой выборке молчит)
inbounds_json() {
    local out
    out=$(sqlite3 -json "$XUIDB" \
        "SELECT id, remark, port, protocol, settings, stream_settings FROM inbounds WHERE listen='127.0.0.1' ORDER BY id;" 2>/dev/null)
    echo "${out:-[]}"
}

# Строки: тип<TAB>порт<TAB>значение  (reality→SNI, grpc→serviceName, xhttp→path)
inbound_routes() {
    inbounds_json | jq -r '.[]
        | ((.stream_settings | fromjson?) // {}) as $s
        | if   $s.security == "reality" then ["reality", .port, ($s.realitySettings.serverNames[0] // "")]
          elif $s.network  == "grpc"    then ["grpc",    .port, ($s.grpcSettings.serviceName // "")]
          elif $s.network  == "xhttp"   then ["xhttp",   .port, ($s.xhttpSettings.path // "")]
          else empty end
        | @tsv'
}

list_inbounds() {
    printf '  %-4s %-28s %-7s %-12s %-6s %s\n' "ID" "Название" "Порт" "Протокол" "Сеть" "Защита"
    inbounds_json | jq -r '.[]
        | ((.stream_settings | fromjson?) // {}) as $s
        | [.id, .remark, .port, .protocol, ($s.network // "?"),
           (if $s.security == "reality" then "Reality, SNI " + ($s.realitySettings.serverNames[0] // "?")
            else "TLS через nginx" end)]
        | @tsv' \
    | while IFS=$'\t' read -r id remark port proto net sec; do
        printf '  %-4s %-28s %-7s %-12s %-6s %s\n' "$id" "$remark" "$port" "$proto" "$net" "$sec"
      done
}

# ─── Занятые порты и SNI ─────────────────────────────────────────────────────
USED_PORTS=(); USED_SNI=()

init_used() {
    USED_PORTS=(22 80 443 "$WWW_PORT" "$TARGET_PORT" "$DASH_PORT")
    USED_SNI=()
    [[ -n "${PANEL_PORT:-}" ]] && USED_PORTS+=("$PANEL_PORT")
    [[ -n "${SUB_PORT:-}"   ]] && USED_PORTS+=("$SUB_PORT")
    [[ -f "$XUIDB" ]] || return 0
    local kind port val
    while IFS=$'\t' read -r kind port val; do
        [[ -n "$port" ]] && USED_PORTS+=("$port")
        [[ "$kind" == reality && -n "$val" ]] && USED_SNI+=("$val")
    done < <(inbound_routes)
}

port_is_listening() { ss -Hltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$1\$"; }

port_is_free() {
    local p
    for p in "${USED_PORTS[@]}"; do [[ "$p" == "$1" ]] && return 1; done
    port_is_listening "$1" && return 1
    return 0
}

gen_free_port() {
    local p
    while true; do
        p=$(( (RANDOM << 15 | RANDOM) % 50000 + 10000 ))
        port_is_free "$p" && { echo "$p"; return; }
    done
}

# ask_port VAR "вопрос" — ручной ввод или пустая строка = случайный порт
ask_port() {
    local __var="$1" __p
    while true; do
        read -rp "$2 (Enter = случайный): " __p
        [[ -z "$__p" ]] && __p=$(gen_free_port)
        if [[ ! "$__p" =~ ^[0-9]+$ ]] || (( __p < 1 || __p > 65535 )); then
            msg_wrn "Порт должен быть числом 1-65535."; continue
        fi
        if ! port_is_free "$__p"; then
            msg_wrn "Порт $__p занят или зарезервирован, выберите другой."; continue
        fi
        USED_PORTS+=("$__p")
        printf -v "$__var" '%s' "$__p"
        return
    done
}

# ─── Домены ──────────────────────────────────────────────────────────────────
DOMAIN_RE='^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'

ask_domain() {
    local __var="$1" __d
    while true; do
        ask __d "$2" "${3:-}"
        __d="${__d,,}"
        [[ "$__d" =~ $DOMAIN_RE ]] && { printf -v "$__var" '%s' "$__d"; return; }
        msg_wrn "Некорректное доменное имя."
    done
}

sni_in_use() {
    local s
    [[ "$1" == "$MAIN_DOMAIN" ]] && return 0
    for s in "${USED_SNI[@]}"; do [[ "$s" == "$1" ]] && return 0; done
    return 1
}

# ask_sni VAR — уникальный SNI-домен для Reality-подключения
ask_sni() {
    local __v="$1" __s __def=""
    sni_in_use "$REALITY_DOMAIN" || __def="$REALITY_DOMAIN"
    while true; do
        ask_domain __s "  SNI-домен этого подключения (свой поддомен, A-запись на этот сервер)" "$__def"
        sni_in_use "$__s" || break
        msg_wrn "Домен $__s уже занят (основным доменом или другим подключением)."
    done
    USED_SNI+=("$__s")
    printf -v "$__v" '%s' "$__s"
}

# ─── Страна → флаг ───────────────────────────────────────────────────────────
# Флаг — два "regional indicator" символа (U+1F1E6..U+1F1FF), в UTF-8: F0 9F 87 A6..BF.
flag_from_iso() {
    local code="${1^^}" i n b out=""
    for i in 0 1; do
        n=$(printf '%d' "'${code:i:1}")
        b=$(printf '%02X' $(( n - 65 + 0xA6 )))
        out+=$(printf "\\xF0\\x9F\\x87\\x$b")
    done
    printf '%s' "$out"
}

# resolve_country "ввод" → COUNTRY_CODE, COUNTRY_NAME
resolve_country() {
    COUNTRY_CODE=""; COUNTRY_NAME="$1"
    case "$1" in
        [Ff][Ii]|[Фф]инляндия|[Ff]inland)                 COUNTRY_CODE=FI; COUNTRY_NAME="Финляндия" ;;
        [Dd][Ee]|[Гг]ермания|[Gg]ermany)                  COUNTRY_CODE=DE; COUNTRY_NAME="Германия" ;;
        [Nn][Ll]|[Нн]идерланды|[Гг]олландия|[Nn]etherlands) COUNTRY_CODE=NL; COUNTRY_NAME="Нидерланды" ;;
        [Ff][Rr]|[Фф]ранция|[Ff]rance)                    COUNTRY_CODE=FR; COUNTRY_NAME="Франция" ;;
        [Gg][Bb]|[Uu][Kk]|[Вв]еликобритания|[Аа]нглия|[Bb]ritain) COUNTRY_CODE=GB; COUNTRY_NAME="Великобритания" ;;
        [Uu][Ss]|США|[Сс]ша|[Аа]мерика|[Uu][Ss][Aa])      COUNTRY_CODE=US; COUNTRY_NAME="США" ;;
        [Cc][Aa]|[Кк]анада|[Cc]anada)                     COUNTRY_CODE=CA; COUNTRY_NAME="Канада" ;;
        [Ss][Ee]|[Шш]веция|[Ss]weden)                     COUNTRY_CODE=SE; COUNTRY_NAME="Швеция" ;;
        [Nn][Oo]|[Нн]орвегия|[Nn]orway)                   COUNTRY_CODE=NO; COUNTRY_NAME="Норвегия" ;;
        [Dd][Kk]|[Дд]ания|[Dd]enmark)                     COUNTRY_CODE=DK; COUNTRY_NAME="Дания" ;;
        [Ee][Ee]|[Ээ]стония|[Ee]stonia)                   COUNTRY_CODE=EE; COUNTRY_NAME="Эстония" ;;
        [Ll][Vv]|[Лл]атвия|[Ll]atvia)                     COUNTRY_CODE=LV; COUNTRY_NAME="Латвия" ;;
        [Ll][Tt]|[Лл]итва|[Ll]ithuania)                   COUNTRY_CODE=LT; COUNTRY_NAME="Литва" ;;
        [Pp][Ll]|[Пп]ольша|[Pp]oland)                     COUNTRY_CODE=PL; COUNTRY_NAME="Польша" ;;
        [Cc][Zz]|[Чч]ехия|[Cc]zechia)                     COUNTRY_CODE=CZ; COUNTRY_NAME="Чехия" ;;
        [Aa][Tt]|[Аа]встрия|[Aa]ustria)                   COUNTRY_CODE=AT; COUNTRY_NAME="Австрия" ;;
        [Cc][Hh]|[Шш]вейцария|[Ss]witzerland)             COUNTRY_CODE=CH; COUNTRY_NAME="Швейцария" ;;
        [Ii][Tt]|[Ии]талия|[Ii]taly)                      COUNTRY_CODE=IT; COUNTRY_NAME="Италия" ;;
        [Ee][Ss]|[Ии]спания|[Ss]pain)                     COUNTRY_CODE=ES; COUNTRY_NAME="Испания" ;;
        [Pp][Tt]|[Пп]ортугалия|[Pp]ortugal)               COUNTRY_CODE=PT; COUNTRY_NAME="Португалия" ;;
        [Ii][Ee]|[Ии]рландия|[Ii]reland)                  COUNTRY_CODE=IE; COUNTRY_NAME="Ирландия" ;;
        [Bb][Ee]|[Бб]ельгия|[Bb]elgium)                   COUNTRY_CODE=BE; COUNTRY_NAME="Бельгия" ;;
        [Rr][Oo]|[Рр]умыния|[Rr]omania)                   COUNTRY_CODE=RO; COUNTRY_NAME="Румыния" ;;
        [Bb][Gg]|[Бб]олгария|[Bb]ulgaria)                 COUNTRY_CODE=BG; COUNTRY_NAME="Болгария" ;;
        [Mm][Dd]|[Мм]олдова|[Mm]oldova)                   COUNTRY_CODE=MD; COUNTRY_NAME="Молдова" ;;
        [Rr][Ss]|[Сс]ербия|[Ss]erbia)                     COUNTRY_CODE=RS; COUNTRY_NAME="Сербия" ;;
        [Tt][Rr]|[Тт]урция|[Tt]urkey)                     COUNTRY_CODE=TR; COUNTRY_NAME="Турция" ;;
        [Aa][Ee]|ОАЭ|[Ээ]мираты|[Uu][Aa][Ee])             COUNTRY_CODE=AE; COUNTRY_NAME="ОАЭ" ;;
        [Kk][Zz]|[Кк]азахстан|[Kk]azakhstan)              COUNTRY_CODE=KZ; COUNTRY_NAME="Казахстан" ;;
        [Aa][Mm]|[Аа]рмения|[Aa]rmenia)                   COUNTRY_CODE=AM; COUNTRY_NAME="Армения" ;;
        [Gg][Ee]|[Гг]рузия|[Gg]eorgia)                    COUNTRY_CODE=GE; COUNTRY_NAME="Грузия" ;;
        [Rr][Uu]|[Рр]оссия|[Rr]ussia)                     COUNTRY_CODE=RU; COUNTRY_NAME="Россия" ;;
        [Jj][Pp]|[Яя]пония|[Jj]apan)                      COUNTRY_CODE=JP; COUNTRY_NAME="Япония" ;;
        [Kk][Rr]|[Кк]орея|[Kk]orea)                       COUNTRY_CODE=KR; COUNTRY_NAME="Южная Корея" ;;
        [Ss][Gg]|[Сс]ингапур|[Ss]ingapore)                COUNTRY_CODE=SG; COUNTRY_NAME="Сингапур" ;;
        [Hh][Kk]|[Гг]онконг|[Hh]ong[Kk]ong)               COUNTRY_CODE=HK; COUNTRY_NAME="Гонконг" ;;
        [Ii][Nn]|[Ии]ндия|[Ii]ndia)                       COUNTRY_CODE=IN; COUNTRY_NAME="Индия" ;;
        [Aa][Uu]|[Аа]встралия|[Aa]ustralia)               COUNTRY_CODE=AU; COUNTRY_NAME="Австралия" ;;
        [Ii][Ll]|[Ии]зраиль|[Ii]srael)                    COUNTRY_CODE=IL; COUNTRY_NAME="Израиль" ;;
        [A-Za-z][A-Za-z])                                 COUNTRY_CODE="${1^^}"; COUNTRY_NAME="${1^^}" ;;  # любой ISO-код
    esac
}

# make_remark "ввод страны" → "🇫🇮 Финляндия" (только флаг и страна, без суффиксов)
make_remark() {
    resolve_country "$1"
    if [[ -n "$COUNTRY_CODE" ]]; then
        printf '%s %s' "$(flag_from_iso "$COUNTRY_CODE")" "$COUNTRY_NAME"
    else
        printf '🌐 %s' "$COUNTRY_NAME"
    fi
}

###############################################################################
# КОНСТРУКТОР ПОДКЛЮЧЕНИЙ
###############################################################################
# Два класса подключений:
#   reality — nginx stream отдаёт TLS как есть в Xray по SNI (нужен свой домен);
#   nginx   — TLS снимает nginx на основном домене и проксирует по пути (gRPC/XHTTP).
# Shadowsocks не умеет Reality в панели, а "голый" TCP нельзя развести по SNI на 443,
# поэтому для него доступны только варианты через nginx.

# choose_variant → V_PROTO (vless|trojan|shadowsocks), V_NET (tcp|grpc|xhttp), V_SEC (reality|nginx)
choose_variant() {
    local p t
    echo "  Протокол:"
    echo "    1) VLESS"
    echo "    2) Trojan"
    echo "    3) Shadowsocks (2022-blake3-aes-256-gcm)"
    while true; do ask p "  Выбор" "1"; [[ "$p" =~ ^[123]$ ]] && break; msg_wrn "Введите 1, 2 или 3."; done
    case "$p" in 1) V_PROTO=vless ;; 2) V_PROTO=trojan ;; 3) V_PROTO=shadowsocks ;; esac

    echo "  Транспорт и защита:"
    if [[ $V_PROTO == shadowsocks ]]; then
        echo "    1) gRPC  + TLS (через nginx, основной домен)"
        echo "    2) XHTTP + TLS (через nginx, основной домен)"
        while true; do ask t "  Выбор" "1"; [[ "$t" =~ ^[12]$ ]] && break; msg_wrn "Введите 1 или 2."; done
        V_SEC=nginx
        case "$t" in 1) V_NET=grpc ;; 2) V_NET=xhttp ;; esac
    else
        echo "    1) TCP   + Reality"
        echo "    2) gRPC  + Reality"
        echo "    3) XHTTP + Reality"
        echo "    4) gRPC  + TLS (через nginx, основной домен)"
        echo "    5) XHTTP + TLS (через nginx, основной домен)"
        while true; do ask t "  Выбор" "1"; [[ "$t" =~ ^[1-5]$ ]] && break; msg_wrn "Введите число 1-5."; done
        case "$t" in
            1) V_NET=tcp;   V_SEC=reality ;;
            2) V_NET=grpc;  V_SEC=reality ;;
            3) V_NET=xhttp; V_SEC=reality ;;
            4) V_NET=grpc;  V_SEC=nginx ;;
            5) V_NET=xhttp; V_SEC=nginx ;;
        esac
    fi
}

# build_settings PROTO → JSON поля settings (клиентов добавляют в панели)
build_settings() {
    case "$1" in
        vless)       echo '{"clients":[],"decryption":"none","fallbacks":[]}' ;;
        trojan)      echo '{"clients":[],"fallbacks":[]}' ;;
        shadowsocks) jq -cn --arg pw "$(openssl rand -base64 32)" \
                        '{method:"2022-blake3-aes-256-gcm", password:$pw, network:"tcp,udp", clients:[], ivCheck:false}' ;;
    esac
}

find_xray() {
    XRAY_BIN=$(ls "$XUI_DIR"/bin/xray-linux-* 2>/dev/null | head -1)
    [[ -x "$XRAY_BIN" ]] || die "Не найден бинарник xray в $XUI_DIR/bin"
}

# gen_reality SNI → JSON realitySettings с новыми ключами x25519 и shortIds
gen_reality() {
    local keys priv pub sids
    # Формат вывода `xray x25519` менялся ("Private key:/Public key:" → "PrivateKey:/Password:")
    keys=$("$XRAY_BIN" x25519) || die "xray x25519 завершился с ошибкой"
    priv=$(awk '/^Private ?[Kk]ey/{print $NF; exit}'           <<<"$keys")
    pub=$(awk  '/^(Password|Public ?[Kk]ey)/{print $NF; exit}' <<<"$keys")
    [[ -n "$priv" && -n "$pub" ]] || die "Не удалось разобрать ключи x25519: $keys"
    sids=$(jq -cn '$ARGS.positional' --args \
        "$(openssl rand -hex 8)" "$(openssl rand -hex 8)" "$(openssl rand -hex 4)" "$(openssl rand -hex 2)")

    # Reality "ворует" TLS у собственного nginx (127.0.0.1:9443) с настоящим сертификатом домена
    jq -cn --arg sni "$1" --arg priv "$priv" --arg pub "$pub" --arg fp "$FINGERPRINT" \
        --arg target "127.0.0.1:${TARGET_PORT}" --argjson sids "$sids" '{
            show:false, xver:0, target:$target, serverNames:[$sni], privateKey:$priv,
            minClient:"", maxClient:"", maxTimediff:0, shortIds:$sids,
            settings:{publicKey:$pub, fingerprint:$fp, serverName:"", spiderX:"/"}}'
}

# build_stream NET SEC SNI [старый realitySettings] → STREAM_JSON
build_stream() {
    local net="$1" sec="$2" sni="$3" r="${4:-}" pp=false secname=none path
    path=$(gen_random_string 12)
    if [[ $sec == reality ]]; then
        if [[ -n "$r" ]]; then
            # Сохраняем прежние ключи, чтобы у клиентов менялся только транспорт
            r=$(jq -c --arg sni "$sni" --arg fp "$FINGERPRINT" '.serverNames=[$sni] | .settings.fingerprint=$fp' <<<"$r")
        else
            r=$(gen_reality "$sni")
        fi
        pp=true; secname=reality      # nginx stream шлёт PROXY protocol → inbound обязан его принимать
    else
        r=null                        # трафик приходит от nginx http, PROXY protocol не используется
    fi

    STREAM_JSON=$(jq -cn --arg net "$net" --arg sec "$secname" --argjson r "$r" --argjson pp "$pp" \
        --arg path "$path" --arg host "$MAIN_DOMAIN" '
        {network:$net, security:$sec}
        + (if $sec == "reality" then {realitySettings:$r} else {} end)
        + (if   $net == "tcp"  then {tcpSettings:{acceptProxyProtocol:$pp, header:{type:"none"}}}
           elif $net == "grpc" then {grpcSettings:{serviceName:$path, authority:(if $sec=="reality" then "" else $host end), multiMode:false}}
           else {xhttpSettings:{path:("/"+$path), host:(if $sec=="reality" then "" else $host end), mode:"auto"}} end)
        + (if $pp and $net != "tcp" then {sockopt:{acceptProxyProtocol:true}} else {} end)')
    jq -e . <<<"$STREAM_JSON" >/dev/null || die "Сформирован некорректный JSON stream_settings"
}

# Структура БД зависит от версии панели — проверяем фактическую схему
detect_schema() {
    HAS_HOSTS=n; HAS_GROUP_ID=n
    [[ -n "$(sqlite3 "$XUIDB" "SELECT name FROM sqlite_master WHERE type='table' AND name='hosts';")" ]] && HAS_HOSTS=y
    sqlite3 "$XUIDB" "PRAGMA table_info(hosts);" | grep -qw group_id && HAS_GROUP_ID=y
    return 0
}

# Внешний адрес для ссылок/подписки: всегда <домен>:443, а не 127.0.0.1:<порт>.
# Старые панели (без таблицы hosts) берут его из externalProxy в stream_settings.
add_external_proxy() {    # SEC SNI
    [[ $HAS_HOSTS == y ]] && return 0
    local dest="$MAIN_DOMAIN" force="tls"
    [[ "$1" == reality ]] && { dest="$2"; force="same"; }
    STREAM_JSON=$(jq -c --arg d "$dest" --arg f "$force" \
        '. + {externalProxy:[{forceTls:$f, dest:$d, port:443, remark:""}]}' <<<"$STREAM_JSON")
}

# Новые панели: запись в таблице hosts
set_host() {              # INBOUND_ID SEC SNI
    [[ $HAS_HOSTS == y ]] || return 0
    local id="$1" addr="$MAIN_DOMAIN" sec="tls" fp="$FINGERPRINT" alpn='["h2"]' gid_col="" gid_val=""
    [[ "$2" == reality ]] && { addr="$3"; sec="same"; fp=""; alpn='[]'; }
    [[ $HAS_GROUP_ID == y ]] && { gid_col='group_id,'; gid_val="'$(gen_group_id)',"; }
    sqlite3 "$XUIDB" "DELETE FROM hosts WHERE inbound_id=${id};
        INSERT INTO hosts (inbound_id, ${gid_col} sort_order, remark, address, port, security, fingerprint, alpn)
        VALUES (${id}, ${gid_val} 0, '', '${addr}', 443, '${sec}', '${fp}', '${alpn}');" \
        || msg_wrn "Не удалось записать host для inbound #${id} — задайте внешний адрес ${addr}:443 в панели вручную."
}

# db_add_inbound REMARK PORT PROTO NET SEC SNI
db_add_inbound() {
    local remark="$1" port="$2" proto="$3" net="$4" sec="$5" sni="$6"
    local settings sniffing tag id
    settings=$(build_settings "$proto")
    build_stream "$net" "$sec" "$sni"
    add_external_proxy "$sec" "$sni"
    sniffing='{"enabled":true,"destOverride":["http","tls","quic"],"metadataOnly":false,"routeOnly":false}'
    tag="inbound-127.0.0.1:${port}"

    # listen = 127.0.0.1 — inbound недоступен извне даже при выключенном фаерволе
    sqlite3 "$XUIDB" "INSERT INTO inbounds
        (user_id, up, down, total, remark, enable, expiry_time, listen, port, protocol,
         settings, stream_settings, tag, sniffing)
        VALUES (1, 0, 0, 0, '$(sq "$remark")', 1, 0, '127.0.0.1', ${port}, '${proto}',
         '$(sq "$settings")', '$(sq "$STREAM_JSON")', '${tag}', '${sniffing}');" \
        || die "Ошибка добавления подключения на порт ${port}"

    id=$(sqlite3 "$XUIDB" "SELECT id FROM inbounds WHERE tag='${tag}';")
    set_host "$id" "$sec" "$sni"
    msg_ok "Подключение: ${remark} → 127.0.0.1:${port} (${proto}, ${net}, ${sec})"
}

# ─── Интерактивный сбор параметров одного подключения ────────────────────────
P_REMARK=(); P_PORT=(); P_PROTO=(); P_NET=(); P_SEC=(); P_SNI=()

collect_one_inbound() {
    local country remark port sni=""
    ask country "  Страна (название или ISO-код: Финляндия, Germany, NL ...)"
    [[ -z "$country" ]] && country="XX"
    remark=$(make_remark "$country")

    ask_port port "  Локальный порт подключения, напр. 440, 444, 445"
    choose_variant
    if [[ $V_SEC == reality ]]; then
        echo "  Reality: nginx различает подключения на 443 только по SNI — нужен отдельный (под)домен."
        ask_sni sni
    fi

    P_REMARK+=("$remark"); P_PORT+=("$port"); P_PROTO+=("$V_PROTO")
    P_NET+=("$V_NET"); P_SEC+=("$V_SEC"); P_SNI+=("$sni")
    msg_ok "Принято: ${remark} | 127.0.0.1:${port} | ${V_PROTO} ${V_NET} ${V_SEC}${sni:+ | SNI ${sni}}"
}

collect_inbounds_loop() {
    P_REMARK=(); P_PORT=(); P_PROTO=(); P_NET=(); P_SEC=(); P_SNI=()
    while confirm "Хотите добавить ноду/подключение?" y; do
        collect_one_inbound
    done
}

###############################################################################
# СЕРТИФИКАТЫ
###############################################################################
# Сертификаты выпускаются в режиме standalone: на несколько секунд нужен свободный порт 80,
# поэтому nginx останавливается (его запускает apply_nginx / вызывающий код).
issue_cert() {
    local d="$1"
    [[ -f "/etc/letsencrypt/live/${d}/fullchain.pem" ]] && { msg_ok "Сертификат для $d уже есть."; return 0; }
    systemctl stop nginx 2>/dev/null || true
    fuser -k 80/tcp 2>/dev/null || true
    certbot certonly --standalone --non-interactive --agree-tos \
        --register-unsafely-without-email -d "$d"
}

setup_renewal_hooks() {
    # Хуки подхватывает штатный certbot.timer
    mkdir -p /etc/letsencrypt/renewal-hooks/{pre,post}
    printf '#!/bin/sh\nsystemctl stop nginx\n'  > /etc/letsencrypt/renewal-hooks/pre/stop-nginx.sh
    printf '#!/bin/sh\nsystemctl start nginx\n' > /etc/letsencrypt/renewal-hooks/post/start-nginx.sh
    chmod +x /etc/letsencrypt/renewal-hooks/pre/stop-nginx.sh /etc/letsencrypt/renewal-hooks/post/start-nginx.sh
}

###############################################################################
# NGINX
###############################################################################
# Длинные доменные имена не помещаются в хеш nginx по умолчанию (32/64 байта).
# Директиву нельзя задавать дважды: правим существующую, а если её нет — добавляем свою.
fix_http_hash_size() {
    local files
    files=$(grep -rlsE '^\s*server_names_hash_bucket_size' /etc/nginx/nginx.conf /etc/nginx/conf.d/ 2>/dev/null)
    if [[ -n "$files" ]]; then
        # shellcheck disable=SC2086
        sed -i -E 's/^(\s*)server_names_hash_bucket_size.*/\1server_names_hash_bucket_size 128;/' $files
    else
        echo 'server_names_hash_bucket_size 128;' > /etc/nginx/conf.d/xpro-hash.conf
    fi
}

# Разовая подготовка nginx.conf (блок stream, модуль, хеши)
setup_nginx_base() {
    mkdir -p /etc/nginx/stream-enabled /etc/nginx/conf.d
    grep -q 'stream-enabled' /etc/nginx/nginx.conf \
        || printf '\nstream {\n    include /etc/nginx/stream-enabled/*.conf;\n}\n' >> /etc/nginx/nginx.conf
    if ! ls /etc/nginx/modules-enabled/*stream* &>/dev/null \
       && ! grep -q 'ngx_stream_module' /etc/nginx/nginx.conf \
       && [[ -f /usr/lib/nginx/modules/ngx_stream_module.so ]]; then
        sed -i '1i load_module /usr/lib/nginx/modules/ngx_stream_module.so;' /etc/nginx/nginx.conf
    fi
    fix_http_hash_size
    rm -f /etc/nginx/sites-enabled/default
}

# Блок location для gRPC/XHTTP-подключения за nginx (h2c к Xray на loopback)
h2_location() {           # PATH PORT
    cat <<EOF

    location /$1 {
        grpc_pass grpc://127.0.0.1:$2;
        grpc_set_header Host            \$host;
        grpc_set_header X-Real-IP       \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        grpc_socket_keepalive on;
        grpc_read_timeout     1h;
        grpc_send_timeout     1h;
        client_body_timeout   1h;
        client_max_body_size  0;
    }
EOF
}

# write_vhost DOMAIN DEFAULT_SUFFIX EXTRA_LOCATIONS — дописывает server{} в $NGX_CONF
write_vhost() {
    cat >> "$NGX_CONF" <<EOF

server {
    listen 127.0.0.1:${WWW_PORT} ssl${H2_LISTEN} proxy_protocol$2;
    listen 127.0.0.1:${TARGET_PORT} ssl${H2_LISTEN}$2;
    ${H2_ON}
    server_name $1;
    server_tokens off;

    ssl_certificate     /etc/letsencrypt/live/$1/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$1/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    # Реальный IP клиента из PROXY protocol
    set_real_ip_from 127.0.0.1;
    real_ip_header   proxy_protocol;
    # Слушаем 7443/9443, а снаружи 443 — редиректы без порта
    absolute_redirect off;

    root  /var/www/html;
    index index.html;
$3
    location / { try_files \$uri \$uri/ =404; }
}
EOF
}

# Полная пересборка конфигурации nginx из state.env + x-ui.db
apply_nginx() {
    msg_inf "Сборка конфигурации Nginx..."
    mkdir -p /etc/nginx/stream-enabled

    # nginx >= 1.25.1: "http2 on;", старше (Debian 12) — "listen ... http2"
    local ngx_ver
    H2_LISTEN=""; H2_ON=""
    ngx_ver=$(nginx -v 2>&1 | grep -oP '[0-9]+\.[0-9]+\.[0-9]+' || echo 0)
    if [[ "$(printf '%s\n' 1.25.1 "$ngx_ver" | sort -V | head -1)" == "1.25.1" ]]; then
        H2_ON="http2 on;"
    else
        H2_LISTEN=" http2"
    fi

    # ── Разбор подключений из базы ──
    local kind port val map_lines="" upstreams="" h2_locations="" seen_sni=" " sni_domains=()
    while IFS=$'\t' read -r kind port val; do
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        case "$kind" in
            reality)
                if [[ ! "$val" =~ $DOMAIN_RE ]]; then
                    msg_wrn "Порт ${port}: некорректный SNI '${val}' — пропущено."; continue; fi
                if [[ "$val" == "$MAIN_DOMAIN" || "$seen_sni" == *" $val "* ]]; then
                    msg_wrn "Порт ${port}: SNI ${val} уже занят — подключение не будет доступно снаружи."; continue; fi
                if [[ ! -f "/etc/letsencrypt/live/${val}/fullchain.pem" ]]; then
                    msg_wrn "Порт ${port}: нет сертификата для ${val} — пропущено."; continue; fi
                seen_sni+="$val "
                map_lines+="    ${val}    inb_${port};"$'\n'
                upstreams+="upstream inb_${port} { server 127.0.0.1:${port}; }"$'\n'
                [[ "$val" != "$REALITY_DOMAIN" ]] && sni_domains+=("$val")
                ;;
            grpc|xhttp)
                val="${val#/}"
                if [[ ! "$val" =~ ^[A-Za-z0-9/_-]+$ ]]; then
                    msg_wrn "Порт ${port}: путь '${val}' не подходит для nginx — пропущено."; continue; fi
                h2_locations+=$(h2_location "$val" "$port")$'\n'
                ;;
        esac
    done < <(inbound_routes)

    # ── stream: SNI-роутинг на 443 (только IPv4) ──
    cat > /etc/nginx/stream-enabled/stream.conf <<EOF
# Сгенерировано xpro.sh. Маршрутизация по SNI без расшифровки TLS.
map_hash_bucket_size 128;

map \$ssl_preread_server_name \$sni_backend {
    hostnames;
${map_lines}    default    www;    # основной домен, неизвестный SNI, сканеры → обычный сайт
}

upstream www { server 127.0.0.1:${WWW_PORT}; }
${upstreams}
server {
    listen 443;
    ssl_preread    on;
    proxy_protocol on;            # реальный IP клиента → Xray / nginx http
    proxy_connect_timeout 5s;
    proxy_pass     \$sni_backend;
}
EOF

    # ── http: vhost на каждый домен ──
    NGX_CONF=/etc/nginx/sites-available/xpro.conf
    cat > "$NGX_CONF" <<EOF
# Сгенерировано xpro.sh
server {
    listen 80 default_server;
    server_name _;
    return 301 https://\$host\$request_uri;
}
EOF

    # Основной домен: панель, подписка, JSON-подписка, gRPC/XHTTP-подключения
    # GeoIP-защита. ВАЖНО: проверка вставляется ТОЛЬКО внутрь location панели и дашборда.
    # Ни server{}, ни stream{}, ни подписки, ни gRPC/XHTTP-подключения её не получают —
    # VPN и подписки остаются доступны из любой страны.
    local geo_guard=""
    if [[ $GEOIP_ENABLED == y && -f "$GEOIP_CONF" ]]; then
        geo_guard='if ($xpro_admin_allowed = 0) { return 444; }   # GeoIP: только разрешённая страна и whitelist'
    fi

    local main_locations=""
    if [[ $PUBLISH_PANEL == y ]]; then
        main_locations+="
    # Панель 3x-ui (reverse proxy)
    location /${PANEL_PATH}/ {
        ${geo_guard}
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \"upgrade\";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_pass http://127.0.0.1:${PANEL_PORT};
    }
"
    fi
    local p
    for p in "$SUB_PATH" "$JSON_PATH"; do
        main_locations+="
    # Подписка 3x-ui
    location /${p}/ {
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_pass http://127.0.0.1:${SUB_PORT};
    }
"
    done
    # Дашборд Fail2ban: секретный путь → внутренний сервер на 127.0.0.1.
    # Слэш в конце proxy_pass срезает префикс пути, сайт дашборда живёт в корне внутреннего сервера.
    if [[ -n "$F2B_PATH" && -f "$DASH_NGINX_CONF" ]]; then
        main_locations+="
    # Дашборд Fail2ban (reverse proxy)
    location = /${F2B_PATH} {
        ${geo_guard}
        return 301 /${F2B_PATH}/;
    }
    location /${F2B_PATH}/ {
        ${geo_guard}
        access_log off;
        proxy_pass http://127.0.0.1:${DASH_PORT}/;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
"
    fi
    main_locations+="$h2_locations"

    # Резервный домен — default_server: на чужой SNI отдаём его сертификат, как обычный сайт
    write_vhost "$REALITY_DOMAIN" " default_server" ""
    write_vhost "$MAIN_DOMAIN"    ""                "$main_locations"
    local d
    for d in "${sni_domains[@]}"; do write_vhost "$d" "" ""; done

    ln -sf "$NGX_CONF" /etc/nginx/sites-enabled/xpro.conf

    nginx -t || die "Проверка конфигурации nginx не пройдена (см. вывод выше)."
    systemctl enable nginx >/dev/null 2>&1
    systemctl restart nginx || die "nginx не запустился: journalctl -u nginx -n 50"
    msg_ok "Nginx перезапущен."
}

# ─── Сайт-заглушка ───────────────────────────────────────────────────────────
write_fallback_site() {
    cat > /var/www/html/index.html <<'EOF'
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Welcome</title>
<style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:15vh auto;padding:0 1rem;color:#333}
h1{font-weight:600}p{line-height:1.6;color:#666}</style></head>
<body><h1>It works</h1><p>This site is under construction. Please check back later.</p></body></html>
EOF
}

# Случайный готовый шаблон (блог, портфолио, лендинг) → /var/www/html
install_fake_site() {
    local url tmp src
    url="${FAKE_SITES[RANDOM % ${#FAKE_SITES[@]}]}"
    tmp=$(mktemp -d)
    mkdir -p /var/www/html
    rm -rf /var/www/html/*

    msg_inf "Сайт-заглушка: $(basename "$(dirname "$(dirname "$(dirname "$(dirname "$url")")")")")"
    if wget -q --show-progress -T 30 -O "$tmp/site.tar.gz" "$url" && tar -xzf "$tmp/site.tar.gz" -C "$tmp"; then
        src=$(find "$tmp" -maxdepth 2 -type d -name dist | head -1)
        if [[ -n "$src" && -f "$src/index.html" ]]; then
            cp -a "$src"/. /var/www/html/
            msg_ok "Шаблон сайта установлен."
        fi
    fi
    if [[ ! -f /var/www/html/index.html ]]; then
        msg_wrn "Не удалось скачать шаблон — ставлю простую страницу."
        write_fallback_site
    fi
    rm -rf "$tmp"
    chown -R www-data:www-data /var/www/html 2>/dev/null || true
}

###############################################################################
# GEOIP И WHITELIST (только для панели 3x-ui и дашборда)
###############################################################################
IP_RE='^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$'

server_ips() { ip -o -4 addr show scope global 2>/dev/null | awk '{split($4,a,"/"); print a[1]}'; }

# IP текущей SSH-сессии администратора. sudo обычно вычищает SSH_CLIENT из окружения,
# поэтому есть запасной способ — вывод `who -m`.
admin_ip() {
    local ip="${SSH_CLIENT:-${SSH_CONNECTION:-}}"
    ip="${ip%% *}"
    [[ -z "$ip" ]] && ip=$(who -m 2>/dev/null | sed -nE 's/.*\(([0-9.]+)\).*/\1/p')
    [[ "$ip" =~ $IP_RE ]] && echo "$ip"
    return 0
}

whitelist_list() {
    [[ -f "$WHITELIST_FILE" ]] && grep -E "$IP_RE" "$WHITELIST_FILE" | sort -u
    return 0
}

whitelist_add() {
    if [[ ! "$1" =~ $IP_RE ]]; then
        msg_wrn "Некорректный IPv4-адрес или подсеть: $1"; return 1
    fi
    mkdir -p "$STATE_DIR"
    echo "$1" >> "$WHITELIST_FILE"
    sort -u -o "$WHITELIST_FILE" "$WHITELIST_FILE"
    chmod 600 "$WHITELIST_FILE"
    msg_ok "В whitelist добавлен: $1"
}

# Интерактивный ввод whitelist: текущий IP администратора + адреса зарубежных серверов
whitelist_ask() {
    local cip ip
    cip=$(admin_ip)
    if [[ "$cip" =~ $IP_RE ]]; then
        confirm "Добавить в whitelist ваш текущий IP (${cip}), чтобы не потерять доступ к панели?" y \
            && whitelist_add "$cip"
    fi
    echo "IP-адреса или подсети зарубежных серверов для whitelist (по одному, Enter — закончить):"
    while true; do
        ask ip "  IP"
        [[ -z "$ip" ]] && break
        whitelist_add "$ip"
    done
}

# Бесплатная база DB-IP Country Lite (CC BY 4.0), выпускается раз в месяц
geoip_download_db() {
    local ym tmp
    tmp=$(mktemp -d)
    for ym in "$(date +%Y-%m)" "$(date -d "$(date +%Y-%m-15) -1 month" +%Y-%m)"; do
        if wget -q --show-progress -T 60 -O "$tmp/db.mmdb.gz" "https://download.db-ip.com/free/dbip-country-lite-${ym}.mmdb.gz" \
           && gunzip -f "$tmp/db.mmdb.gz" \
           && [[ $(stat -c %s "$tmp/db.mmdb" 2>/dev/null || echo 0) -gt 500000 ]]; then
            mkdir -p "$(dirname "$GEOIP_DB")"
            install -m 644 "$tmp/db.mmdb" "$GEOIP_DB"
            rm -rf "$tmp"
            msg_ok "База GeoIP обновлена (DB-IP Country Lite ${ym})."
            return 0
        fi
    done
    rm -rf "$tmp"
    return 1
}

# Переменные nginx (контекст http). Сами по себе ничего не блокируют:
# блокировка включается только строкой "if" внутри location панели и дашборда.
geoip_write_conf() {
    local ip
    {
        echo "# Сгенерировано xpro.sh — GeoIP для админ-панелей."
        echo "# Используется ТОЛЬКО в location панели 3x-ui и дашборда Fail2ban."
        echo "geoip2 ${GEOIP_DB} {"
        echo "    auto_reload 60m;"
        echo '    $xpro_geo_country default=XX country iso_code;'
        echo "}"
        echo
        echo "# Whitelist: localhost, адреса самого сервера и доверенные IP"
        echo 'geo $xpro_whitelisted {'
        echo "    default 0;"
        echo "    127.0.0.1 1;"
        { server_ips; whitelist_list; } | sort -u | while read -r ip; do
            [[ -n "$ip" ]] && echo "    ${ip} 1;"
        done
        echo "}"
        echo
        echo "# Доступ разрешён, если IP в whitelist ИЛИ страна — ${GEOIP_ALLOW_COUNTRY}"
        echo 'map "$xpro_whitelisted:$xpro_geo_country" $xpro_admin_allowed {'
        echo "    default 0;"
        echo '    "~^1:" 1;'
        echo "    \"0:${GEOIP_ALLOW_COUNTRY}\" 1;"
        echo "}"
    } > "$GEOIP_CONF"
}

# Подготовка GeoIP: модуль, база, переменные, автообновление. nginx применяет apply_nginx.
geoip_enable() {
    msg_inf "Настройка GeoIP-защиты админ-панелей..."
    export DEBIAN_FRONTEND=noninteractive
    if ! apt-get install -y libnginx-mod-http-geoip2 >/dev/null 2>&1; then
        msg_wrn "Не удалось установить libnginx-mod-http-geoip2 — GeoIP не включён."; return 1
    fi
    if [[ ! -s "$GEOIP_DB" ]] && ! geoip_download_db; then
        msg_wrn "Не удалось скачать базу DB-IP — GeoIP не включён."; return 1
    fi

    geoip_write_conf
    if ! nginx -t >/dev/null 2>&1; then
        nginx -t
        rm -f "$GEOIP_CONF"
        msg_wrn "Nginx не принял конфигурацию GeoIP — защита не включена."; return 1
    fi

    # Ежемесячное обновление базы (nginx перечитывает её сам: auto_reload)
    cat > "$GEOIP_UPDATER" <<EOF
#!/bin/bash
# Обновление базы DB-IP Country Lite (создано xpro.sh)
tmp=\$(mktemp -d)
for ym in "\$(date +%Y-%m)" "\$(date -d "\$(date +%Y-%m-15) -1 month" +%Y-%m)"; do
    if wget -q -T 60 -O "\$tmp/db.mmdb.gz" "https://download.db-ip.com/free/dbip-country-lite-\${ym}.mmdb.gz" \\
       && gunzip -f "\$tmp/db.mmdb.gz" && [ "\$(stat -c %s "\$tmp/db.mmdb")" -gt 500000 ]; then
        install -m 644 "\$tmp/db.mmdb" "${GEOIP_DB}"
        break
    fi
done
rm -rf "\$tmp"
EOF
    chmod 755 "$GEOIP_UPDATER"
    printf 'SHELL=/bin/bash\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n17 4 3 * * root %s >/dev/null 2>&1\n' \
        "$GEOIP_UPDATER" > "$GEOIP_CRON"
    chmod 644 "$GEOIP_CRON"

    GEOIP_ENABLED="y"
    msg_ok "GeoIP готов: панель и дашборд доступны только из ${GEOIP_ALLOW_COUNTRY} и с адресов whitelist."
}

geoip_disable() {
    GEOIP_ENABLED="n"
    save_state
    apply_nginx                       # убирает проверку из location панели и дашборда
    rm -f "$GEOIP_CONF" "$GEOIP_UPDATER" "$GEOIP_CRON"
    nginx -t >/dev/null 2>&1 && systemctl reload nginx
    msg_ok "GeoIP-защита отключена. Whitelist сохранён."
}

# Применить изменения whitelist к работающему nginx
geoip_reload() {
    [[ $GEOIP_ENABLED == y ]] || return 0
    geoip_write_conf
    if nginx -t >/dev/null 2>&1; then
        systemctl reload nginx && msg_ok "Whitelist применён."
    else
        nginx -t
        msg_wrn "Nginx не принял новый whitelist — проверьте ${WHITELIST_FILE}."
    fi
}

geoip_status() {
    if [[ $GEOIP_ENABLED == y ]]; then
        echo -e "  GeoIP-защита: \e[1;32mвключена\e[0m (разрешена страна ${GEOIP_ALLOW_COUNTRY} + whitelist)"
        [[ -f "$GEOIP_DB" ]] && echo "  База: ${GEOIP_DB} от $(date -r "$GEOIP_DB" '+%d.%m.%Y')"
    else
        echo -e "  GeoIP-защита: \e[1;33mвыключена\e[0m"
    fi
    echo "  Всегда разрешены: 127.0.0.1 и адреса сервера ($(server_ips | paste -sd' '))"
    echo "  Whitelist:"
    local list
    list=$(whitelist_list)
    if [[ -n "$list" ]]; then sed 's/^/    /' <<<"$list"; else echo "    (пусто)"; fi
}

action_geoip() {
    # Без установленной панели доступен только whitelist: защищать GeoIP пока нечего
    if [[ $INSTALLED == y ]]; then require_install || return; fi
    local c ip
    while true; do
        echo
        echo -e "\e[1;36m── GeoIP и Whitelist (панель 3x-ui и дашборд) ──\e[0m"
        geoip_status
        echo
        echo "  [1] Включить GeoIP-защиту"
        echo "  [2] Отключить GeoIP-защиту"
        echo "  [3] Добавить IP в whitelist"
        echo "  [4] Удалить IP из whitelist"
        echo "  [5] Обновить базу GeoIP"
        echo "  [0] Назад"
        read -rp "  Выберите пункт: " c
        if [[ $INSTALLED == n && "$c" =~ ^[125]$ ]]; then
            msg_wrn "GeoIP защищает панель и дашборд — сначала установите 3x-ui (пункт [1] главного меню)."
            msg_inf "Whitelist можно заполнить уже сейчас (пункты [3] и [4]): он применится при включении."
            continue
        fi
        case "$c" in
            1)  msg_wrn "Если вы сами не в ${GEOIP_ALLOW_COUNTRY} и вашего IP нет в whitelist — панель перестанет открываться."
                msg_wrn "Вернуть доступ можно будет по SSH: это меню, пункт [2]."
                whitelist_ask
                if geoip_enable; then save_state; apply_nginx; fi ;;
            2)  geoip_disable ;;
            3)  ask ip "IP или подсеть"
                [[ -n "$ip" ]] && whitelist_add "$ip" && geoip_reload ;;
            4)  ask ip "IP или подсеть для удаления"
                if [[ -n "$ip" && -f "$WHITELIST_FILE" ]] && grep -qxF "$ip" "$WHITELIST_FILE"; then
                    grep -vxF "$ip" "$WHITELIST_FILE" > "${WHITELIST_FILE}.tmp"
                    mv -f "${WHITELIST_FILE}.tmp" "$WHITELIST_FILE"
                    msg_ok "Удалён: $ip"
                    geoip_reload
                else
                    msg_wrn "Такого адреса в whitelist нет."
                fi ;;
            5)  geoip_download_db || msg_wrn "Не удалось скачать базу." ;;
            0)  return ;;
            *)  msg_wrn "Нет такого пункта." ;;
        esac
    done
}

###############################################################################
# FAIL2BAN
###############################################################################
# Принципы: логи Xray/3x-ui не подключаются; баны точечные (multiport);
# порт 443 (VPN) не банится никогда; вместо recidive — bantime.increment.
f2b_install() {
    msg_inf "Установка и настройка Fail2ban..."
    export DEBIAN_FRONTEND=noninteractive
    # python3-systemd нужен для чтения журнала systemd (Debian 12+ без auth.log)
    if ! apt-get install -y fail2ban python3-systemd >/dev/null 2>&1; then
        msg_wrn "Не удалось установить fail2ban."; return 1
    fi

    local ssh_ports banaction ssh_backend ssh_logpath="" ignoreip cip
    # Порты SSH из действующей конфигурации sshd. 443 и 80 отсеиваются принудительно:
    # 443 — VPN-порт, на нём не должно быть ни одного бана.
    ssh_ports=$(sshd -T 2>/dev/null | awk '$1=="port" && $2!=443 && $2!=80 {print $2}' | paste -sd,)
    ssh_ports="${ssh_ports:-22}"

    if command -v nft >/dev/null 2>&1 && [[ -f /etc/fail2ban/action.d/nftables-multiport.conf ]]; then
        banaction="nftables-multiport"
    else
        banaction="iptables-multiport"
    fi

    # Откуда читать события SSH: auth.log (если пишется rsyslog) или журнал systemd
    if [[ -s /var/log/auth.log ]] && systemctl is-active --quiet rsyslog 2>/dev/null; then
        ssh_backend="auto"; ssh_logpath="logpath  = /var/log/auth.log"
    else
        # Debian 12+/Ubuntu без rsyslog: auth.log нет, события лежат в journald.
        # journalmatch задан явно: юнит в Debian называется ssh.service (не sshd.service),
        # а OpenSSH 9.8+ пишет логи от процесса sshd-session. "+" здесь означает ИЛИ.
        ssh_backend="systemd"
        ssh_logpath="journalmatch = _SYSTEMD_UNIT=ssh.service + _SYSTEMD_UNIT=sshd.service + _COMM=sshd + _COMM=sshd-session"
    fi

    # Никогда не банить: localhost, сам сервер, текущий администратор, whitelist
    cip=$(admin_ip)
    ignoreip=$( { echo "127.0.0.0/8"; echo "::1"; server_ips; [[ "$cip" =~ $IP_RE ]] && echo "$cip"; whitelist_list; } \
                | awk 'NF && !seen[$0]++' | paste -sd' ')

    # Сканеры: обращения к путям, которых на сайте-заглушке быть не может
    cat > /etc/fail2ban/filter.d/nginx-scanners.conf <<'EOF'
# Managed by xpro.sh
# Сканеры уязвимостей и боты: запросы к типичным «чужим» путям. Формат лога nginx "combined".
[Definition]
_bad = (?i:\.env|\.git/|\.svn/|\.hg/|\.aws/|\.ssh/|\.ds_store|\.htaccess|\.htpasswd|wp-login\.php|wp-admin|wp-content|wp-includes|xmlrpc\.php|phpmyadmin|/pma/|myadmin|adminer|\.php\d?(?=[?/\s])|\.aspx?(?=[?/\s])|\.jsp(?=[?/\s])|/cgi-bin/|boaform|hnap1|gponform|/actuator|vendor/phpunit|eval-stdin|/shell|\.(?:bak|old|sql|sqlite|tar|tgz|gz|zip|rar|7z)(?=[?\s])|server-status|/owa/|autodiscover|/solr/|/jenkins|/manager/html|setup\.cgi|/druid/|/telescope)
failregex = ^<HOST> \S+ \S+ \[[^\]]*\] "[A-Z]{3,10} \S*%(_bad)s\S* HTTP/[\d.]+"
ignoreregex =
EOF

    # Флуд ошибками 4xx от одного IP
    cat > /etc/fail2ban/filter.d/nginx-4xx-flood.conf <<'EOF'
# Managed by xpro.sh
# Массовые ошибки 4xx от одного IP (перебор путей, мусорные запросы).
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]*\] "[^"]*" (?:400|401|403|404|405|444)\s
ignoreregex = "(?:GET|HEAD) /(?:favicon\.ico|robots\.txt|sitemap\.xml|apple-touch-icon\S*|\.well-known/)\S* HTTP/
EOF

    [[ -f "$F2B_JAIL_LOCAL" ]] && cp -a "$F2B_JAIL_LOCAL" "${F2B_JAIL_LOCAL}.bak"
    # Nginx-джейлы добавляем, только если nginx установлен: без его лога Fail2ban не запустится
    local with_nginx=n
    if command -v nginx >/dev/null 2>&1 && [[ -d /var/log/nginx ]]; then
        with_nginx=y
        [[ -f /var/log/nginx/access.log ]] || touch /var/log/nginx/access.log
    fi
    cat > "$F2B_JAIL_LOCAL" <<EOF
# Сгенерировано xpro.sh
# ВАЖНО: логи Xray / 3x-ui здесь намеренно НЕ подключены, порт 443 (VPN) не банится.

[DEFAULT]
ignoreip   = ${ignoreip}
ignoreself = true
# Точечный бан: блокируются только порты конкретного джейла, а не весь трафик
banaction  = ${banaction}
backend    = auto
usedns     = no
allowipv6  = auto
bantime    = 1h
findtime   = 10m
maxretry   = 5
# Повторные нарушители получают всё более длинный бан (вместо recidive, который банит все порты)
bantime.increment = true
bantime.maxtime   = 1w

[sshd]
enabled  = true
filter   = sshd
mode     = aggressive
port     = ${ssh_ports}
backend  = ${ssh_backend}
${ssh_logpath}
maxretry = 4
findtime = 10m
bantime  = 2h
EOF

    [[ $with_nginx == y ]] && cat >> "$F2B_JAIL_LOCAL" <<EOF

# Nginx: читается access.log сайта, бан — только на порту 80 (443 защищён от банов)
[nginx-scanners]
enabled  = true
filter   = nginx-scanners
port     = 80
logpath  = /var/log/nginx/access.log
backend  = auto
maxretry = 2
findtime = 10m
bantime  = 1d

[nginx-4xx-flood]
enabled  = true
filter   = nginx-4xx-flood
port     = 80
logpath  = /var/log/nginx/access.log
backend  = auto
maxretry = 30
findtime = 2m
bantime  = 1h
EOF

    # Страховка: ни в одном джейле не должно быть порта 443
    if grep -Eq '^port[[:space:]]*=.*\b443\b' "$F2B_JAIL_LOCAL"; then
        if [[ -f "${F2B_JAIL_LOCAL}.bak" ]]; then mv -f "${F2B_JAIL_LOCAL}.bak" "$F2B_JAIL_LOCAL"; else rm -f "$F2B_JAIL_LOCAL"; fi
        msg_wrn "В джейлах оказался порт 443 (VPN) — конфигурация Fail2ban отменена."; return 1
    fi

    if ! fail2ban-client -t >/dev/null 2>&1; then
        fail2ban-client -t
        if [[ -f "${F2B_JAIL_LOCAL}.bak" ]]; then mv -f "${F2B_JAIL_LOCAL}.bak" "$F2B_JAIL_LOCAL"; else rm -f "$F2B_JAIL_LOCAL"; fi
        msg_wrn "Конфигурация Fail2ban не прошла проверку — изменения отменены."; return 1
    fi

    systemctl enable fail2ban >/dev/null 2>&1
    if ! systemctl restart fail2ban; then
        msg_wrn "Fail2ban не запустился: journalctl -u fail2ban -n 30"; return 1
    fi
    local i
    for i in 1 2 3 4 5 6 7 8 9 10; do
        fail2ban-client ping >/dev/null 2>&1 && {
            msg_ok "Fail2ban запущен."
            echo "      SSH:       порт ${ssh_ports}, источник логов: ${ssh_backend}"
            if [[ $with_nginx == y ]]; then
                echo "      Nginx:     джейлы банят только порт 80"
            else
                echo "      Nginx:     не установлен — джейлы Nginx добавятся после установки 3x-ui"
            fi
            echo "      Порт 443:  не банится никогда (VPN)"
            echo "      ignoreip:  ${ignoreip}"
            return 0
        }
        sleep 1
    done
    msg_wrn "Fail2ban не ответил за 10 секунд: journalctl -u fail2ban -n 30"; return 1
}

###############################################################################
# ДАШБОРД FAIL2BAN (127.0.0.1:63034, наружу — https://домен/секретный-путь/)
###############################################################################
DASH_USER=""; DASH_PASS=""; DASH_PASS_GENERATED="n"

dash_ask_credentials() {
    while true; do
        ask DASH_USER "Логин дашборда Fail2ban"
        [[ "$DASH_USER" =~ ^[A-Za-z0-9._-]{1,32}$ ]] && break
        msg_wrn "Допустимы латинские буквы, цифры и символы . _ - (до 32 символов)."
    done
    DASH_PASS_GENERATED="n"
    local again
    while true; do
        read -rsp "Пароль дашборда (не короче 10 символов, Enter = сгенерировать): " DASH_PASS; echo
        if [[ -z "$DASH_PASS" ]]; then
            DASH_PASS=$(gen_random_string 20); DASH_PASS_GENERATED="y"; break
        fi
        if (( ${#DASH_PASS} < 10 )); then msg_wrn "Пароль слишком короткий."; continue; fi
        read -rsp "Повторите пароль: " again; echo
        [[ "$DASH_PASS" == "$again" ]] && break
        msg_wrn "Пароли не совпадают."
    done
}

# dash_write_htpasswd [-B|-m] — пароль идёт через stdin и не виден в списке процессов
dash_write_htpasswd() {
    printf '%s' "$DASH_PASS" | htpasswd -i "${1:--B}" -c "$DASH_HTPASSWD" "$DASH_USER" >/dev/null 2>&1 || return 1
    chown root:www-data "$DASH_HTPASSWD"
    chmod 640 "$DASH_HTPASSWD"
}

# Файлы дашборда: пароли, сайт, внутренний сервер nginx, генератор данных, cron.
# Location на основном домене добавляет apply_nginx (по F2B_PATH).
dash_install() {
    msg_inf "Установка дашборда Fail2ban..."
    export DEBIAN_FRONTEND=noninteractive
    if ! apt-get install -y apache2-utils cron curl >/dev/null 2>&1; then
        msg_wrn "Не удалось установить apache2-utils/cron."; return 1
    fi
    systemctl enable --now cron >/dev/null 2>&1

    dash_write_htpasswd -B || { msg_wrn "htpasswd не смог создать файл паролей."; return 1; }

    mkdir -p "${DASH_ROOT}/assets" "${DASH_ROOT}/api"
    dash_write_web_files
    dash_write_generator

    # Внутренний сервер: только loopback, HTTP, без сертификатов
    cat > "$DASH_NGINX_CONF" <<EOF
# Дашборд Fail2ban — создано xpro.sh.
# Слушает ТОЛЬКО 127.0.0.1 по HTTP. Снаружи: https://<основной домен>/<секретный путь>/
limit_req_zone \$binary_remote_addr zone=f2b_dash:1m rate=30r/m;

server {
    listen 127.0.0.1:${DASH_PORT};
    server_name _;

    # Реальный IP клиента передаёт основной nginx в заголовке X-Real-IP
    set_real_ip_from 127.0.0.1;
    real_ip_header   X-Real-IP;
    absolute_redirect off;

    root  ${DASH_ROOT};
    index index.html;

    # Отдельные логи: не попадают в джейлы nginx-scanners / nginx-4xx-flood
    access_log /var/log/nginx/f2b-dash.access.log;
    error_log  /var/log/nginx/f2b-dash.error.log;

    server_tokens off;
    add_header X-Frame-Options         "DENY" always;
    add_header X-Content-Type-Options  "nosniff" always;
    add_header Referrer-Policy         "no-referrer" always;
    add_header X-Robots-Tag            "noindex, nofollow" always;
    add_header Cache-Control           "no-store" always;
    add_header Content-Security-Policy "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" always;

    # Публичная часть: страница входа, стили, скрипт
    location / {
        try_files \$uri \$uri/ =404;
    }

    # Закрытая часть: данные дашборда
    location /api/ {
        limit_req zone=f2b_dash burst=10 nodelay;
        limit_req_status 429;
        auth_basic           "f2b-dash";
        auth_basic_user_file ${DASH_HTPASSWD};
        # 403 вместо 401: форму входа рисует страница, а не серое окно браузера
        error_page 401 =403 @f2b_dash_denied;
        try_files \$uri =404;
    }
    location @f2b_dash_denied {
        default_type application/json;
        return 403 '{"error":"unauthorized"}';
    }
    location ~ /\. { deny all; }
}
EOF

    # Генератор данных каждую минуту
    printf 'SHELL=/bin/bash\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n* * * * * root %s >/dev/null 2>&1\n' \
        "$DASH_GEN" > "$DASH_CRON"
    chmod 644 "$DASH_CRON"
    "$DASH_GEN" || msg_wrn "Первый запуск генератора завершился с ошибкой: проверьте ${DASH_GEN}"

    [[ "$F2B_PATH" =~ ^[A-Za-z0-9]{8,}$ ]] || F2B_PATH=$(gen_random_string 12)
    msg_ok "Дашборд подготовлен (127.0.0.1:${DASH_PORT}, данные: ${DASH_ROOT}/api/data.html)."
}

# Проверка после apply_nginx: вход с паролем; если nginx не понимает bcrypt — переходим на apr1
dash_selftest() {
    local code cfg u="${DASH_USER//\\/\\\\}" p="${DASH_PASS//\\/\\\\}"
    cfg="user = \"${u//\"/\\\"}:${p//\"/\\\"}\""
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 -K - "http://127.0.0.1:${DASH_PORT}/api/data.html" <<<"$cfg")
    if [[ "$code" == "500" ]]; then
        msg_wrn "Nginx не поддерживает bcrypt — пересоздаю файл паролей в формате apr1."
        dash_write_htpasswd -m
        code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 -K - "http://127.0.0.1:${DASH_PORT}/api/data.html" <<<"$cfg")
    fi
    if [[ "$code" == "200" ]]; then
        msg_ok "Дашборд отвечает, вход с логином и паролем работает."
    else
        msg_wrn "Дашборд вернул код '${code}' (ожидался 200): см. /var/log/nginx/f2b-dash.error.log"
    fi
    if ss -Hltn "sport = :${DASH_PORT}" 2>/dev/null | grep -vq "127.0.0.1:${DASH_PORT}"; then
        msg_wrn "Порт ${DASH_PORT} слушается не только на 127.0.0.1!"
    fi
}

dash_remove_files() {
    rm -f "$DASH_NGINX_CONF" "$DASH_HTPASSWD" "$DASH_GEN" "$DASH_CRON" /run/f2b-dash.lock \
          /var/log/nginx/f2b-dash.access.log* /var/log/nginx/f2b-dash.error.log*
    rm -rf "$DASH_ROOT"
    F2B_PATH=""
}

dash_write_web_files() {
    # ---- index.html: публичная страница входа + пустой контейнер дашборда ----
    cat > "${DASH_ROOT}/index.html" <<'EOF'
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<meta name="referrer" content="no-referrer">
<meta name="color-scheme" content="dark">
<title>Fail2ban</title>
<link rel="icon" href="data:,">
<link rel="stylesheet" href="assets/app.css">
<script src="assets/app.js" defer></script>
</head>
<body>

<main id="login-view" class="login-wrap">
  <form id="login-form" class="login-card" method="post" novalidate>
    <div class="logo" aria-hidden="true">
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3z"/><path d="m9 12 2 2 4-4"/></svg>
    </div>
    <h1>Добро пожаловать!</h1>
    <p class="sub">Панель статистики Fail2ban</p>

    <label for="username">Имя пользователя</label>
    <input id="username" name="username" type="text" autocomplete="username" autocapitalize="none" spellcheck="false" required>

    <label for="password">Пароль</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required>

    <p id="login-error" class="error" role="alert" hidden></p>
    <button id="login-btn" class="btn-primary" type="submit">Войти</button>
  </form>
</main>

<div id="app-view" hidden>
  <header class="topbar">
    <div class="brand">
      <span id="svc-dot" class="dot"></span>
      <div><h1>Fail2ban</h1><p id="host-line" class="muted">—</p></div>
    </div>
    <div class="top-actions">
      <span id="updated" class="muted"></span>
      <button id="refresh-btn" class="btn-ghost" type="button">Обновить</button>
      <button id="logout-btn" class="btn-ghost" type="button">Выйти</button>
    </div>
  </header>
  <main id="dashboard" class="container"></main>
</div>

<noscript><p class="noscript">Для входа нужен включённый JavaScript.</p></noscript>
</body>
</html>
EOF

    # ---- app.css: тёмная тема в стиле 3x-ui ----
    cat > "${DASH_ROOT}/assets/app.css" <<'EOF'
:root{
  /* OLED Black: абсолютно чёрный фон, белый текст, только тонкие рамки без заливок */
  --bg:#000000; --surface:#000000; --surface-2:transparent; --border:#262626;
  --text:#ffffff; --muted:#8c8c8c; --accent:#ffffff; --accent-hover:#d9d9d9;
  --ok:#00e676; --bad:#ff4d4f; --radius:8px;
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
}
*{box-sizing:border-box}
html,body{margin:0;min-height:100%;background:var(--bg);color:var(--text);
  font:14px/1.55 var(--mono);
  -webkit-font-smoothing:antialiased}
[hidden]{display:none!important}
.muted{color:var(--muted)}
.noscript{text-align:center;color:var(--muted);padding:24px}

/* ---------- Вход ---------- */
.login-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;
  background:var(--bg)}
.login-card{width:100%;max-width:380px;background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius);padding:32px 28px}
.logo{width:52px;height:52px;border-radius:var(--radius);background:transparent;border:1px solid var(--border);color:var(--text);
  display:grid;place-items:center;margin:0 auto 16px}
.login-card h1{margin:0;text-align:center;font-size:24px;font-weight:600}
.login-card .sub{margin:6px 0 22px;text-align:center;color:var(--muted);font-size:14px}
label{display:block;font-size:13px;color:var(--muted);margin:14px 0 6px}
input{width:100%;padding:11px 14px;border-radius:10px;border:1px solid var(--border);background:var(--bg);
  color:var(--text);font:inherit;outline:none;transition:border-color .15s,box-shadow .15s}
input:focus{border-color:var(--accent);box-shadow:0 0 0 1px var(--accent)}
.btn-primary{width:100%;margin-top:22px;padding:12px;border:0;border-radius:10px;background:var(--accent);
  color:#000;font:inherit;font-weight:600;cursor:pointer;transition:background .15s}
.btn-primary:hover{background:var(--accent-hover)}
.btn-primary:disabled{opacity:.65;cursor:progress}
.error{margin:14px 0 0;padding:10px 12px;border-radius:10px;background:transparent;border:1px solid var(--bad);color:var(--bad);font-size:14px}

/* ---------- Шапка ---------- */
.topbar{position:sticky;top:0;z-index:10;display:flex;align-items:center;justify-content:space-between;
  gap:12px 16px;flex-wrap:wrap;padding:14px 24px;background:rgba(0,0,0,.92);
  backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);border-bottom:1px solid var(--border)}
.brand{display:flex;align-items:center;gap:12px}
.brand h1{margin:0;font-size:18px;font-weight:600}
.brand p{margin:0;font-size:13px}
.dot{width:10px;height:10px;border-radius:50%;background:var(--muted);flex:none}
.dot.ok{background:var(--ok)}
.dot.bad{background:var(--bad)}
.top-actions{display:flex;align-items:center;gap:10px;flex-wrap:wrap;font-size:13px}
.btn-ghost{padding:8px 14px;border-radius:9px;border:1px solid var(--border);background:var(--surface);
  color:var(--text);font:inherit;font-size:14px;cursor:pointer;transition:border-color .15s}
.btn-ghost:hover{border-color:var(--accent)}

/* ---------- Контент ---------- */
.container{max-width:1200px;margin:0 auto;padding:24px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px 18px}
.card .label{font-size:13px;color:var(--muted)}
.card .value{font-size:28px;font-weight:600;margin-top:4px;font-variant-numeric:tabular-nums}
.card .value.small{font-size:20px;padding-top:6px}
.value.ok{color:var(--ok)} .value.bad{color:var(--bad)} .value.accent{color:var(--accent)}
.section-title{font-size:16px;font-weight:600;margin:28px 0 12px}
.jails{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:14px}
.jail{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px}
.jail header{display:flex;align-items:center;justify-content:space-between;gap:10px}
.jail h3{margin:0;font-size:16px;font-weight:600}
.jail-desc{margin:3px 0 0;font-size:12.5px;color:var(--muted)}
.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin:14px 0}
.metric{background:transparent;border:1px solid var(--border);border-radius:var(--radius);padding:10px 12px}
.metric b{display:block;font-size:20px;font-weight:600;font-variant-numeric:tabular-nums}
.metric span{font-size:12px;color:var(--muted)}
.pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}
.pill.ok{background:transparent;border:1px solid var(--ok);color:var(--ok)}
.pill.bad{background:transparent;border:1px solid var(--bad);color:var(--bad)}
.pill.muted{background:transparent;border:1px solid var(--border);color:var(--muted)}
.ips{display:flex;flex-wrap:wrap;gap:6px}
.ip{font-family:var(--mono);font-size:13px;padding:3px 10px;border-radius:6px;background:transparent;border:1px solid var(--border);color:var(--text)}
.empty{font-size:13px;color:var(--muted)}
details{margin-top:12px}
summary{cursor:pointer;color:var(--muted);font-size:13px;user-select:none}
summary:hover{color:var(--text)}
pre{margin:10px 0 0;padding:12px;background:var(--bg);border:1px solid var(--border);border-radius:10px;
  overflow-x:auto;font:12.5px/1.5 var(--mono);color:#e6e6e6;white-space:pre-wrap;word-break:break-all}
details.raw{margin-top:18px}
.table-wrap{overflow-x:auto;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius)}
table{width:100%;border-collapse:collapse;min-width:560px}
th,td{text-align:left;padding:10px 16px;border-bottom:1px solid var(--border);font-size:14px;white-space:nowrap}
th{color:var(--muted);font-weight:500;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
tbody tr:last-child td{border-bottom:0}
td.mono{font-family:var(--mono);font-size:13px}
.foot{margin:24px 0 0;font-size:12px;color:var(--muted);text-align:center}

@media (max-width:560px){
  .container{padding:16px}
  .topbar{padding:12px 16px}
  .jails{grid-template-columns:1fr}
  .metrics{grid-template-columns:repeat(2,1fr)}
  .cards{grid-template-columns:repeat(2,1fr);gap:10px}
  .card .value{font-size:24px}
  .top-actions{width:100%}
  #updated{flex:1 1 100%}
}
EOF

    # ---- app.js: вход через fetch с заголовком Authorization ----
    cat > "${DASH_ROOT}/assets/app.js" <<'EOF'
(() => {
  "use strict";

  const DATA_URL = "api/data.html";
  const REFRESH_MS = 60000;
  let token = null;   // логин:пароль в Base64; хранится только в памяти вкладки
  let timer = null;

  const $ = (id) => document.getElementById(id);

  // Base64 от UTF-8 строки (корректно и для не-латинских символов в пароле)
  function b64(str) {
    const bytes = new TextEncoder().encode(str);
    let bin = "";
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin);
  }

  function request(tok) {
    return fetch(DATA_URL + "?t=" + Date.now(), {
      headers: { "Authorization": "Basic " + tok },
      cache: "no-store",
      credentials: "omit"
    });
  }

  function showError(msg) { const e = $("login-error"); e.textContent = msg; e.hidden = false; }
  function hideError() { $("login-error").hidden = true; }

  function setBusy(busy) {
    const btn = $("login-btn");
    btn.disabled = busy;
    btn.textContent = busy ? "Проверка…" : "Войти";
  }

  function render(html) {
    const box = $("dashboard");
    // Запоминаем раскрытые блоки, чтобы автообновление их не сворачивало
    const open = new Set([...box.querySelectorAll("details[open][data-key]")].map((d) => d.dataset.key));
    box.innerHTML = html;
    box.querySelectorAll("details[data-key]").forEach((d) => { if (open.has(d.dataset.key)) d.open = true; });

    const root = box.querySelector(".data-root");
    if (root) {
      $("host-line").textContent = root.dataset.host || "";
      $("updated").textContent = "Обновлено: " + (root.dataset.updated || "—");
      $("svc-dot").className = "dot " + (root.dataset.service === "online" ? "ok" : "bad");
    }
  }

  function showApp() {
    $("login-view").hidden = true;
    $("app-view").hidden = false;
    clearInterval(timer);
    timer = setInterval(refresh, REFRESH_MS);
  }

  function logout(message) {
    token = null;
    clearInterval(timer);
    $("dashboard").innerHTML = "";
    $("app-view").hidden = true;
    $("login-view").hidden = false;
    if (message) showError(message); else hideError();
    $("password").value = "";
    $("username").focus();
  }

  async function refresh() {
    if (!token) return;
    try {
      const res = await request(token);
      if (res.ok) {
        render(await res.text());
      } else if (res.status === 401 || res.status === 403) {
        logout("Сессия завершена: пароль был изменён. Войдите снова.");
      } else {
        $("updated").textContent = "Ошибка обновления: " + res.status;
      }
    } catch (e) {
      $("updated").textContent = "Нет связи с сервером…";
    }
  }

  async function onLogin(ev) {
    ev.preventDefault();
    const user = $("username").value.trim();
    const pass = $("password").value;
    if (!user || !pass) { showError("Введите имя пользователя и пароль"); return; }

    hideError();
    setBusy(true);
    const tok = b64(user + ":" + pass);
    try {
      const res = await request(tok);
      if (res.ok) {
        token = tok;
        $("password").value = "";
        render(await res.text());
        showApp();
      } else if (res.status === 401 || res.status === 403) {
        showError("Неверное имя пользователя или пароль");
      } else if (res.status === 404) {
        showError("Данные ещё не сформированы. Подождите минуту и попробуйте снова.");
      } else if (res.status === 429) {
        showError("Слишком много попыток. Подождите немного.");
      } else {
        showError("Ошибка сервера: " + res.status);
      }
    } catch (e) {
      showError("Нет связи с сервером");
    } finally {
      setBusy(false);
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    $("login-form").addEventListener("submit", onLogin);
    $("logout-btn").addEventListener("click", () => logout());
    $("refresh-btn").addEventListener("click", refresh);
    $("username").focus();
  });
})();
EOF
    chmod 644 "${DASH_ROOT}/index.html" "${DASH_ROOT}/assets/app.css" "${DASH_ROOT}/assets/app.js"
}

# Генератор данных: cron каждую минуту собирает статистику в api/data.html
dash_write_generator() {
    cat > "$DASH_GEN" <<'GEN_EOF'
#!/usr/bin/env bash
# f2b-dash.sh — собирает статистику Fail2ban в HTML-фрагмент api/data.html.
# Запускается cron'ом каждую минуту от root. Создано xpro.sh.
set -uo pipefail
set -f    # без glob-подстановки при разборе списков IP
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

WEB_ROOT="/var/www/f2b"
JAILS=(sshd nginx-scanners nginx-4xx-flood)
F2B_LOG="/var/log/fail2ban.log"
EVENTS_MAX=30

OUT_DIR="${WEB_ROOT}/api"
OUT_FILE="${OUT_DIR}/data.html"

exec 9>/run/f2b-dash.lock
flock -n 9 || exit 0
mkdir -p "$OUT_DIR"

esc()   { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'; }
field() { sed -nE "s/.*$2:[[:space:]]*//p" <<<"$1" | head -n1; }
num()   { if [[ "$1" =~ ^[0-9]+$ ]]; then echo "$1"; else echo 0; fi; }

HOST="$(hostname -f 2>/dev/null || hostname)"
NOW="$(date '+%d.%m.%Y %H:%M:%S')"
UPTIME="$(uptime -p 2>/dev/null | sed 's/^up //')"
LOADAVG="$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null)"
F2B_VER="$(fail2ban-client --version 2>/dev/null | head -n1)"

if fail2ban-client ping >/dev/null 2>&1; then
    SVC="online";  SVC_HTML='<div class="value small ok">Работает</div>'
else
    SVC="offline"; SVC_HTML='<div class="value small bad">Остановлена</div>'
fi
GLOBAL_STATUS="$(fail2ban-client status 2>&1)"

# ---------------------------- Джейлы ----------------------------------------
sum_cur=0; sum_total=0; sum_failed=0; jails_up=0
JAIL_HTML=""
for j in "${JAILS[@]}"; do
    if out="$(fail2ban-client status "$j" 2>&1)"; then
        jails_up=$((jails_up + 1))
        cf="$(num "$(field "$out" 'Currently failed')")"
        tf="$(num "$(field "$out" 'Total failed')")"
        cb="$(num "$(field "$out" 'Currently banned')")"
        tb="$(num "$(field "$out" 'Total banned')")"
        ips="$(field "$out" 'Banned IP list')"
        pill='<span class="pill ok">Активен</span>'
        sum_cur=$((sum_cur + cb)); sum_total=$((sum_total + tb)); sum_failed=$((sum_failed + cf))
    else
        cf=0; tf=0; cb=0; tb=0; ips=""
        pill='<span class="pill bad">Не найден</span>'
        out="Джейл «${j}» не найден или fail2ban не запущен.
${out}"
    fi

    chips=""
    for ip in $ips; do chips+="<span class=\"ip\">$(esc <<<"$ip")</span>"; done
    if [[ -z "$chips" ]]; then chips='<span class="empty">Забаненных IP нет</span>'; fi

    # Пояснение под названием джейла: за что он отвечает
    case "$j" in
        sshd)            desc="Защита от подбора паролей по SSH" ;;
        nginx-scanners)  desc="Блокировка ботов и поиска уязвимостей" ;;
        nginx-4xx-flood) desc="Защита от флуда и перебора путей" ;;
        nginx-http-auth) desc="Защита от подбора паролей на сайте" ;;
        *)               desc="" ;;
    esac

    J="$(esc <<<"$j")"
    JAIL_HTML+="
    <article class=\"jail\">
      <header><div><h3>${J}</h3><p class=\"jail-desc\">${desc}</p></div>${pill}</header>
      <div class=\"metrics\">
        <div class=\"metric\"><b>${cb}</b><span>Забанено сейчас</span></div>
        <div class=\"metric\"><b>${tb}</b><span>Банов всего</span></div>
        <div class=\"metric\"><b>${cf}</b><span>Ошибок сейчас</span></div>
        <div class=\"metric\"><b>${tf}</b><span>Ошибок всего</span></div>
      </div>
      <div class=\"ips\">${chips}</div>
      <details data-key=\"jail-${J}\"><summary>Вывод fail2ban-client status ${J}</summary><pre>$(esc <<<"$out")</pre></details>
    </article>"
done

# ---------------------- Последние события из лога ---------------------------
EV_HTML=""
if [[ -r "$F2B_LOG" ]]; then
    while IFS='|' read -r ts jail act ip; do
        case "$act" in
            Unban)         label='<span class="pill muted">Разбан</span>' ;;
            "Restore Ban") label='<span class="pill bad">Восстановлен</span>' ;;
            *)             label='<span class="pill bad">Бан</span>' ;;
        esac
        EV_HTML+="<tr><td>$(esc <<<"$ts")</td><td>$(esc <<<"$jail")</td><td>${label}</td><td class=\"mono\">$(esc <<<"$ip")</td></tr>"
    done < <(grep -hE 'NOTICE +\[[^]]+\] (Restore Ban|Ban|Unban) ' "$F2B_LOG" 2>/dev/null \
             | tail -n "$EVENTS_MAX" | tac \
             | sed -nE 's/^([0-9]{4})-([0-9]{2})-([0-9]{2}) ([0-9:]+),[0-9]+ .*NOTICE +\[([^]]+)\] (Restore Ban|Ban|Unban) ([^ ]+).*/\3.\2.\1 \4|\5|\6|\7/p')
fi
if [[ -z "$EV_HTML" ]]; then
    EV_HTML='<tr><td colspan="4" class="empty">Событий пока нет</td></tr>'
fi

# ---------------------------- HTML-фрагмент ---------------------------------
tmp="$(mktemp "${OUT_DIR}/.data.XXXXXX")" || exit 1
trap 'rm -f "$tmp"' EXIT

H="$(esc <<<"$HOST")"
cat >"$tmp" <<HTML
<div class="data-root" data-host="${H}" data-updated="$(esc <<<"$NOW")" data-service="${SVC}">
  <div class="cards">
    <div class="card"><div class="label">Служба fail2ban</div>${SVC_HTML}</div>
    <div class="card"><div class="label">Джейлов активно</div><div class="value">${jails_up}/${#JAILS[@]}</div></div>
    <div class="card"><div class="label">Забанено сейчас</div><div class="value accent">${sum_cur}</div></div>
    <div class="card"><div class="label">Банов всего</div><div class="value">${sum_total}</div></div>
    <div class="card"><div class="label">Ошибок сейчас</div><div class="value">${sum_failed}</div></div>
  </div>

  <h2 class="section-title">Джейлы</h2>
  <div class="jails">${JAIL_HTML}
  </div>

  <h2 class="section-title">Последние события</h2>
  <div class="table-wrap"><table>
    <thead><tr><th>Время</th><th>Джейл</th><th>Действие</th><th>IP-адрес</th></tr></thead>
    <tbody>${EV_HTML}</tbody>
  </table></div>

  <details class="raw" data-key="global"><summary>Вывод fail2ban-client status</summary><pre>$(esc <<<"$GLOBAL_STATUS")</pre></details>
  <p class="foot">${H} · аптайм: $(esc <<<"${UPTIME:-н/д}") · нагрузка: $(esc <<<"${LOADAVG:-н/д}") · $(esc <<<"${F2B_VER:-fail2ban}")</p>
</div>
HTML

chmod 644 "$tmp"
mv -f "$tmp" "$OUT_FILE"     # атомарная замена: страница никогда не получит половину файла
trap - EXIT
GEN_EOF
    chmod 755 "$DASH_GEN"
}

# ─── Меню [4]: Fail2ban и дашборд ────────────────────────────────────────────
f2b_status() {
    if command -v fail2ban-client >/dev/null 2>&1 && fail2ban-client ping >/dev/null 2>&1; then
        echo -e "  Fail2ban: \e[1;32mработает\e[0m ($(fail2ban-client status 2>/dev/null | sed -nE 's/.*Jail list:[[:space:]]*//p'))"
    elif command -v fail2ban-client >/dev/null 2>&1; then
        echo -e "  Fail2ban: \e[1;33mустановлен, не запущен\e[0m"
    else
        echo -e "  Fail2ban: \e[1;33mне установлен\e[0m"
    fi
    if [[ -n "$F2B_PATH" ]]; then
        echo -e "  Дашборд:  \e[1;34mhttps://${MAIN_DOMAIN}/${F2B_PATH}/\e[0m (логин: $(cut -d: -f1 "$DASH_HTPASSWD" 2>/dev/null | head -1))"
    else
        echo -e "  Дашборд:  \e[1;33mне установлен\e[0m"
    fi
}

# Дописывает актуальные доступы дашборда в файл сводки (его читает пункт меню [7])
summary_append_dash() {
    {
        echo
        echo "Дашборд Fail2ban — обновлено $(date '+%d.%m.%Y %H:%M')"
        echo "  Ссылка:  https://${MAIN_DOMAIN}/${F2B_PATH}/"
        echo "  Логин:   ${DASH_USER}"
        echo "  Пароль:  ${DASH_PASS}"
    } >> "$SUMMARY_FILE"
    chmod 600 "$SUMMARY_FILE"
}

f2b_dash_setup() {
    dash_ask_credentials
    f2b_install || msg_wrn "Fail2ban не настроен — дашборд будет без данных."
    if dash_install; then
        save_state
        apply_nginx
        dash_selftest
        summary_append_dash
        echo
        echo "  Дашборд: https://${MAIN_DOMAIN}/${F2B_PATH}/"
        echo "  Логин:   ${DASH_USER}"
        echo "  Пароль:  ${DASH_PASS}"
    fi
    DASH_PASS=""
}

action_f2b() {
    # Без установленной панели доступен только сам Fail2ban (защита SSH);
    # дашборду нужен основной домен и Nginx от установки 3x-ui.
    if [[ $INSTALLED == y ]]; then require_install || return; fi
    local c
    while true; do
        echo
        echo -e "\e[1;36m── Fail2ban и дашборд ──\e[0m"
        f2b_status
        echo
        echo "  [1] Установить / обновить Fail2ban и дашборд"
        echo "  [2] Сменить логин и пароль дашборда"
        echo "  [3] Удалить дашборд (Fail2ban остаётся)"
        echo "  [4] Удалить Fail2ban и дашборд"
        echo "  [5] Установить / обновить только Fail2ban (без дашборда)"
        echo "  [0] Назад"
        read -rp "  Выберите пункт: " c
        if [[ $INSTALLED == n && "$c" =~ ^[123]$ ]]; then
            msg_wrn "Дашборду нужна установленная 3x-ui (пункт [1] главного меню)."
            msg_inf "Сам Fail2ban можно поставить уже сейчас — пункт [5]."
            continue
        fi
        case "$c" in
            1)  f2b_dash_setup ;;
            5)  f2b_install ;;
            2)  if [[ -z "$F2B_PATH" ]]; then msg_wrn "Дашборд не установлен."; continue; fi
                dash_ask_credentials
                if dash_write_htpasswd -B; then
                    dash_selftest
                    summary_append_dash
                    echo "  Логин: ${DASH_USER}   Пароль: ${DASH_PASS}"
                else
                    msg_wrn "Не удалось обновить файл паролей."
                fi
                DASH_PASS="" ;;
            3)  confirm "Удалить дашборд Fail2ban?" n || continue
                dash_remove_files; save_state; apply_nginx
                msg_ok "Дашборд удалён." ;;
            4)  confirm "Удалить Fail2ban вместе с дашбордом?" n || continue
                if [[ $INSTALLED == y ]]; then dash_remove_files; save_state; apply_nginx; fi
                systemctl stop fail2ban 2>/dev/null
                apt-get purge -y fail2ban >/dev/null 2>&1
                rm -rf /etc/fail2ban
                msg_ok "Fail2ban и дашборд удалены." ;;
            0)  return ;;
            *)  msg_wrn "Нет такого пункта." ;;
        esac
    done
}

###############################################################################
# [1] УСТАНОВКА С НУЛЯ
###############################################################################
check_os() {
    local id ver
    id=$(. /etc/os-release 2>/dev/null; echo "${ID:-}")
    ver=$(. /etc/os-release 2>/dev/null; echo "${VERSION_ID:-}")
    # Поддерживаются системы с apt и свежей glibc (её требует бинарник 3x-ui)
    case "${id}:${ver}" in
        debian:12|debian:13)                      return 0 ;;
        ubuntu:22.04|ubuntu:24.04|ubuntu:26.04)   return 0 ;;
    esac
    msg_wrn "Скрипт рассчитан на Debian 12/13 и Ubuntu 22.04/24.04/26.04, обнаружено: ${id} ${ver}."
    confirm "Продолжить на свой риск?" n || return 1
}

collect_install_settings() {
    echo; msg_inf "── Проект ──"
    # Необязательно: пустое значение оставляет имя подписки по умолчанию
    ask PROJECT_NAME "Название вашего VPN-проекта, видно клиентам в приложении (Enter — пропустить)"

    echo; msg_inf "── Панель 3x-ui ──"
    while true; do
        ask PANEL_USER "Логин панели"
        [[ "$PANEL_USER" =~ ^[A-Za-z0-9_.-]{3,}$ ]] && break
        msg_wrn "Логин: минимум 3 символа, латиница/цифры/._-"
    done
    PANEL_PASS_GENERATED=n
    while true; do
        read -rsp "Пароль панели (Enter = сгенерировать): " PANEL_PASS; echo
        if [[ -z "$PANEL_PASS" ]]; then
            PANEL_PASS=$(gen_random_string 20); PANEL_PASS_GENERATED=y; break
        fi
        local again
        read -rsp "Повторите пароль: " again; echo
        [[ "$PANEL_PASS" == "$again" ]] && break
        msg_wrn "Пароли не совпадают."
    done

    echo; msg_inf "── Домены (A-записи должны указывать на этот сервер) ──"
    ask_domain MAIN_DOMAIN "Основной домен (панель, подписка, сайт-заглушка)"
    while true; do
        ask_domain REALITY_DOMAIN "Резервный домен (SNI/target для Reality)"
        [[ "$REALITY_DOMAIN" != "$MAIN_DOMAIN" ]] && break
        msg_wrn "Домены должны различаться."
    done

    # Внутренние порты и секретные пути: наружу видны только https://домен/путь/
    # Старая база (если есть) будет удалена, поэтому её порты и SNI занятыми не считаем
    USED_PORTS=(22 80 443 "$WWW_PORT" "$TARGET_PORT" "$DASH_PORT"); USED_SNI=()
    F2B_PATH=""; GEOIP_ENABLED="n"
    PANEL_PORT=$(gen_free_port); USED_PORTS+=("$PANEL_PORT")
    SUB_PORT=$(gen_free_port);   USED_PORTS+=("$SUB_PORT")
    PANEL_PATH=$(gen_random_string 14)
    SUB_PATH=$(gen_random_string 12)
    JSON_PATH=$(gen_random_string 12)

    echo; msg_inf "── Подключения (inbounds) ──"
    collect_inbounds_loop

    echo; msg_inf "── Защита ──"
    # Fail2ban можно поставить с дашбордом, без него или не ставить вовсе
    local f2b_choice
    INSTALL_F2B=n; INSTALL_DASH=n
    echo "  Fail2ban:"
    echo "    1) Установить Fail2ban и веб-дашборд статистики"
    echo "    2) Установить только Fail2ban (без дашборда)"
    echo "    3) Не устанавливать"
    while true; do
        ask f2b_choice "  Выбор" "1"
        [[ "$f2b_choice" =~ ^[123]$ ]] && break
        msg_wrn "Введите 1, 2 или 3."
    done
    case "$f2b_choice" in
        1) INSTALL_F2B=y; INSTALL_DASH=y; dash_ask_credentials ;;
        2) INSTALL_F2B=y ;;
    esac

    INSTALL_GEOIP=n
    if confirm "Включить защиту GeoIP для админ-панелей?" n; then
        INSTALL_GEOIP=y
        msg_wrn "Панель и дашборд будут открываться только из ${GEOIP_ALLOW_COUNTRY} и с адресов whitelist."
        msg_wrn "VPN-подключения и подписки это не затрагивает — они доступны из любой страны."
        whitelist_ask
    fi
}

install_packages() {
    msg_inf "Установка пакетов..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y || die "apt-get update не выполнен"
    apt-get install -y curl wget tar jq sqlite3 openssl ca-certificates tzdata ufw \
        nginx-full libnginx-mod-stream certbot psmisc iproute2 \
        || die "Не удалось установить пакеты"
}

get_server_ip() {
    IP4=$(ip route get 8.8.8.8 2>/dev/null | grep -Po 'src \K\S+')
    [[ "$IP4" =~ ^[0-9.]+$ ]] || IP4=$(curl -4s --max-time 10 ipv4.icanhazip.com | tr -d '[:space:]')
}

check_dns() {
    local d a bad=n
    for d in "$@"; do
        a=$(getent ahostsv4 "$d" 2>/dev/null | awk 'NR==1{print $1}')
        if [[ "$a" != "$IP4" ]]; then
            msg_wrn "$d → ${a:-не резолвится}, ожидался $IP4"
            bad=y
        fi
    done
    if [[ $bad == y ]]; then
        confirm "DNS не совпадает с IP сервера (за NAT это нормально). Продолжить?" n || die "Отменено."
    fi
}

# UFW: только SSH, 80, 443. Панель, подписка и inbounds — на loopback за nginx.
# Старые правила сбрасываются (ufw сам делает их бэкап в /etc/ufw).
setup_firewall() {
    msg_inf "Настройка UFW..."
    local ssh_ports p
    ssh_ports=$(sshd -T 2>/dev/null | awk '$1=="port"{print $2}')
    [[ -z "$ssh_ports" ]] && ssh_ports=22

    # Только IPv4: ufw не создаёт правила (v6) и блокирует весь входящий IPv6
    sed -i -E 's/^IPV6=.*/IPV6=no/' /etc/default/ufw

    ufw --force reset >/dev/null
    ufw default deny incoming  >/dev/null
    ufw default allow outgoing >/dev/null
    for p in $ssh_ports; do
        ufw allow "${p}/tcp" >/dev/null
        [[ "$p" != "22" ]] && msg_wrn "SSH слушает нестандартный порт ${p} — он оставлен открытым."
    done
    ufw allow 80/tcp  >/dev/null
    ufw allow 443/tcp >/dev/null
    ufw --force enable >/dev/null
    msg_ok "UFW: открыты только SSH(${ssh_ports//$'\n'/,}), 80, 443."
}

_arch() {
    case "$(uname -m)" in
        x86_64|x64|amd64)        echo 'amd64' ;;
        i*86|x86)                echo '386'   ;;
        armv8*|arm64|aarch64)    echo 'arm64' ;;
        armv7*|arm)              echo 'armv7' ;;
        armv6*)                  echo 'armv6' ;;
        armv5*)                  echo 'armv5' ;;
        s390x)                   echo 's390x' ;;
        *) die "Неподдерживаемая архитектура CPU: $(uname -m)" ;;
    esac
}

install_panel() {
    local arch tag url
    arch=$(_arch)

    tag=$(curl -Ls "https://api.github.com/repos/MHSanaei/3x-ui/releases/latest" \
          | grep -m1 '"tag_name":' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')
    [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+ ]] || die "Не удалось получить версию 3x-ui с GitHub."

    msg_inf "Установка 3x-ui ${tag} (${arch})..."
    url="https://github.com/MHSanaei/3x-ui/releases/download/${tag}/x-ui-linux-${arch}.tar.gz"
    wget -q --show-progress -O /tmp/x-ui.tar.gz "$url" || die "Не удалось скачать $url"
    tar -xzf /tmp/x-ui.tar.gz -C /usr/local/ || die "Ошибка распаковки архива"
    rm -f /tmp/x-ui.tar.gz

    chmod +x "$XUI_DIR/x-ui" "$XUI_DIR"/bin/xray-linux-* 2>/dev/null
    # В архивах для armv5/6/7 бинарник xray переименовывается (как в официальном install.sh)
    if [[ "$arch" =~ ^armv[567]$ && -f "$XUI_DIR/bin/xray-linux-${arch}" ]]; then
        mv "$XUI_DIR/bin/xray-linux-${arch}" "$XUI_DIR/bin/xray-linux-arm"
    fi

    # Штатная утилита управления `x-ui` — не критична
    if wget -q --show-progress -O /usr/bin/x-ui https://raw.githubusercontent.com/MHSanaei/3x-ui/main/x-ui.sh; then
        chmod +x /usr/bin/x-ui
    else
        msg_wrn "Не удалось скачать x-ui.sh (штатное меню панели), продолжаю без него."
    fi

    # systemd unit: в новых релизах — x-ui.service.debian, в старых — x-ui.service
    if   [[ -f "$XUI_DIR/x-ui.service.debian" ]]; then cp -f "$XUI_DIR/x-ui.service.debian" /etc/systemd/system/x-ui.service
    elif [[ -f "$XUI_DIR/x-ui.service" ]];        then cp -f "$XUI_DIR/x-ui.service"        /etc/systemd/system/x-ui.service
    else die "В архиве не найден systemd unit x-ui."; fi
    systemctl daemon-reload
    systemctl enable x-ui >/dev/null 2>&1
    # Панель запускается только после полной настройки, чтобы ни секунды не слушать 0.0.0.0
}

# set_setting KEY VALUE — запись в таблицу settings (key/value)
set_setting() {
    sqlite3 "$XUIDB" "DELETE FROM settings WHERE key='$1'; INSERT INTO settings (key,value) VALUES ('$1','$(sq "$2")');" \
        || die "Ошибка записи настройки $1"
}

configure_panel() {
    msg_inf "Настройка панели..."
    # Логин/пароль/порт/путь пишем штатным CLI: он создаёт БД и хеширует пароль так,
    # как этого ждёт текущая версия панели. Прямой INSERT пароля в users сломал бы вход.
    "$XUI_DIR/x-ui" setting -username "$PANEL_USER" -password "$PANEL_PASS" \
        -port "$PANEL_PORT" -webBasePath "$PANEL_PATH" >/dev/null \
        || die "x-ui setting завершился с ошибкой"
    "$XUI_DIR/x-ui" migrate >/dev/null 2>&1 || true
    [[ -f "$XUIDB" ]] || die "База $XUIDB не создана."

    # Панель — только loopback, без собственного TLS: HTTPS и чистый URL даёт nginx
    set_setting webListen   "127.0.0.1"
    set_setting webDomain   ""
    set_setting webCertFile ""
    set_setting webKeyFile  ""

    # Подписка — loopback, наружу https://домен/секрет/ без портов
    set_setting subEnable     "true"
    set_setting subListen     "127.0.0.1"
    set_setting subPort       "$SUB_PORT"
    set_setting subDomain     ""
    set_setting subCertFile   ""
    set_setting subKeyFile    ""
    set_setting subPath       "/${SUB_PATH}/"
    set_setting subURI        "https://${MAIN_DOMAIN}/${SUB_PATH}/"
    set_setting subJsonEnable "true"
    set_setting subJsonPath   "/${JSON_PATH}/"
    set_setting subJsonURI    "https://${MAIN_DOMAIN}/${JSON_PATH}/"
    set_setting subTitle      "$PROJECT_NAME"      # имя подписки в клиентских приложениях
    # В названии ссылки — только примечание inbound'а ("🇫🇮 Финляндия"), без email и прочего
    set_setting remarkTemplate '{{INBOUND}}'
}

tune_system() {
    cat > /etc/sysctl.d/99-xpro.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr

# Сервер работает только по IPv4: IPv6 полностью отключён на уровне ядра
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
    sysctl --system >/dev/null 2>&1 || true
}

restart_xui() {
    systemctl restart x-ui || die "x-ui не запустился: journalctl -u x-ui -n 50"
    sleep 2
    systemctl is-active --quiet x-ui || die "x-ui не активен: journalctl -u x-ui -n 50"
    msg_ok "x-ui перезапущен."
}

show_results() {
    {
        echo "══════════════════════════ Установка завершена ══════════════════════════"
        [[ -n "$PROJECT_NAME" ]] && echo "Проект: ${PROJECT_NAME}"
        echo
        echo "┌─ Панель 3x-ui"
        echo "│  Ссылка:  https://${MAIN_DOMAIN}/${PANEL_PATH}/"
        echo "│  Логин:   ${PANEL_USER}"
        echo "│  Пароль:  ${PANEL_PASS}"
        if [[ -n "$F2B_PATH" ]]; then
            echo "├─ Дашборд Fail2ban"
            echo "│  Ссылка:  https://${MAIN_DOMAIN}/${F2B_PATH}/"
            echo "│  Логин:   ${DASH_USER}"
            echo "│  Пароль:  ${DASH_PASS}"
        fi
        echo "├─ Подписка"
        echo "│  Ссылка:  https://${MAIN_DOMAIN}/${SUB_PATH}/<subId>"
        echo "│  JSON:    https://${MAIN_DOMAIN}/${JSON_PATH}/<subId>"
        echo "└─ Защита"
        if [[ $GEOIP_ENABLED == y ]]; then
            echo "   GeoIP:    включён — панель и дашборд только из ${GEOIP_ALLOW_COUNTRY} и whitelist"
        else
            echo "   GeoIP:    выключен"
        fi
        if command -v fail2ban-client >/dev/null 2>&1 && fail2ban-client ping >/dev/null 2>&1; then
            echo "   Fail2ban: работает"
        else
            echo "   Fail2ban: не установлен"
        fi
        echo "   VPN и подписки доступны из любой страны, наружу открыты только SSH, 80 и 443."
        echo
        echo "Подключения:"
        list_inbounds
        echo
        echo "Клиентов добавьте в панели (для VLESS TCP+Reality выберите flow xtls-rprx-vision)."
        echo "══════════════════════════════════════════════════════════════════"
    } | tee "$SUMMARY_FILE"
    chmod 600 "$SUMMARY_FILE"
    msg_ok "Сводка сохранена в ${SUMMARY_FILE}"
}

action_install() {
    check_os || return

    if [[ -f "$XUIDB" || -d "$XUI_DIR" ]]; then
        msg_wrn "Обнаружена существующая установка 3x-ui."
        confirm "УДАЛИТЬ её вместе с базой (все подключения и клиенты будут потеряны) и поставить заново?" n || return
        # Останавливаем сразу, чтобы порты старых подключений можно было выбрать снова
        systemctl stop x-ui 2>/dev/null || true
    fi

    collect_install_settings

    # Домены, которым нужен сертификат: резервный, основной и SNI всех Reality-подключений
    local domains=("$REALITY_DOMAIN" "$MAIN_DOMAIN") s i
    for s in "${P_SNI[@]}"; do
        [[ -n "$s" && "$s" != "$REALITY_DOMAIN" ]] && domains+=("$s")
    done

    echo
    if ! confirm "Начать установку? (доменов: ${#domains[@]}, подключений: ${#P_PORT[@]})" y; then
        # Отмена: возвращаем к работе прежнюю установку, если она была
        [[ -f "$XUIDB" ]] && systemctl start x-ui 2>/dev/null
        return
    fi

    install_packages
    get_server_ip
    check_dns "${domains[@]}"
    setup_firewall

    msg_inf "Выпуск сертификатов Let's Encrypt..."
    for s in "${domains[@]}"; do
        issue_cert "$s" || die "Не удалось выпустить сертификат для $s (проверьте DNS и порт 80)."
    done
    setup_renewal_hooks

    # Удаление прежней установки (подтверждено выше), база сохраняется в /root
    systemctl stop x-ui 2>/dev/null || true
    [[ -f "$XUIDB" ]] && cp -a "$XUIDB" "/root/x-ui.db.bak.$(date +%s)" && msg_inf "Бэкап старой базы сохранён в /root/."
    rm -rf "$XUI_DIR" /etc/x-ui /etc/systemd/system/x-ui.service

    install_panel
    configure_panel
    save_state
    detect_schema
    find_xray

    for i in "${!P_PORT[@]}"; do
        db_add_inbound "${P_REMARK[$i]}" "${P_PORT[$i]}" "${P_PROTO[$i]}" "${P_NET[$i]}" "${P_SEC[$i]}" "${P_SNI[$i]}"
    done

    setup_nginx_base
    install_fake_site

    # Защита: готовим файлы до сборки конфигурации nginx, чтобы apply_nginx
    # сразу добавил location дашборда и GeoIP-проверку в панель и дашборд.
    [[ $INSTALL_GEOIP == y ]] && geoip_enable
    if [[ $INSTALL_F2B == y ]]; then
        f2b_install || msg_wrn "Fail2ban не настроен."
        [[ $INSTALL_DASH == y ]] && dash_install
    fi
    save_state

    apply_nginx
    [[ -n "$F2B_PATH" ]] && dash_selftest
    tune_system
    restart_xui
    show_results
    DASH_PASS=""
}

###############################################################################
# [2] ДОБАВИТЬ ПОДКЛЮЧЕНИЕ
###############################################################################
action_add() {
    require_install || return
    find_xray

    echo "Текущие подключения:"; list_inbounds; echo
    P_REMARK=(); P_PORT=(); P_PROTO=(); P_NET=(); P_SEC=(); P_SNI=()
    collect_one_inbound

    local sni="${P_SNI[0]}"
    if [[ -n "$sni" ]]; then
        msg_inf "Выпуск сертификата для ${sni} (nginx остановится на несколько секунд)..."
        if ! issue_cert "$sni"; then
            systemctl start nginx 2>/dev/null || true
            msg_wrn "Не удалось выпустить сертификат для ${sni} (проверьте DNS и порт 80). Подключение не добавлено."
            return
        fi
    fi

    db_add_inbound "${P_REMARK[0]}" "${P_PORT[0]}" "${P_PROTO[0]}" "${P_NET[0]}" "${P_SEC[0]}" "$sni"
    apply_nginx
    restart_xui
    msg_ok "Готово. Добавьте клиентов в панели: https://${MAIN_DOMAIN}/${PANEL_PATH}/"
}

###############################################################################
# [3] ИЗМЕНИТЬ ПОДКЛЮЧЕНИЕ (протокол / транспорт)
###############################################################################
action_modify() {
    require_install || return
    find_xray

    echo "Подключения:"; list_inbounds; echo
    local id row old_proto old_stream old_sni old_reality settings sni=""
    ask id "ID подключения для изменения"
    [[ "$id" =~ ^[0-9]+$ ]] || { msg_wrn "Некорректный ID."; return; }
    row=$(inbounds_json | jq -c --argjson id "$id" '.[] | select(.id == $id)')
    [[ -n "$row" ]] || { msg_wrn "Подключение #${id} не найдено."; return; }

    old_proto=$(jq -r '.protocol' <<<"$row")
    old_stream=$(jq -r '.stream_settings' <<<"$row")
    old_sni=$(jq -r '.realitySettings.serverNames[0] // empty' <<<"$old_stream" 2>/dev/null)
    old_reality=$(jq -c '.realitySettings // empty' <<<"$old_stream" 2>/dev/null)

    choose_variant

    # Смена протокола делает прежних клиентов недействительными (UUID ≠ пароль Trojan/SS)
    if [[ "$V_PROTO" != "$old_proto" ]]; then
        msg_wrn "Протокол меняется (${old_proto} → ${V_PROTO}): клиенты этого подключения будут удалены."
        confirm "Продолжить?" n || return
        settings=$(build_settings "$V_PROTO")
    else
        settings=$(jq -r '.settings' <<<"$row")
    fi

    if [[ $V_SEC == reality ]]; then
        if [[ -n "$old_sni" ]]; then
            sni="$old_sni"                      # домен и ключи Reality остаются прежними
        else
            ask_sni sni
            old_reality=""
            msg_inf "Выпуск сертификата для ${sni} (nginx остановится на несколько секунд)..."
            if ! issue_cert "$sni"; then
                systemctl start nginx 2>/dev/null || true
                msg_wrn "Не удалось выпустить сертификат для ${sni}. Подключение не изменено."
                return
            fi
        fi
    else
        old_reality=""
    fi

    build_stream "$V_NET" "$V_SEC" "$sni" "$old_reality"
    add_external_proxy "$V_SEC" "$sni"

    sqlite3 "$XUIDB" "UPDATE inbounds SET protocol='${V_PROTO}', settings='$(sq "$settings")',
        stream_settings='$(sq "$STREAM_JSON")' WHERE id=${id};" || die "Ошибка обновления подключения #${id}"
    if [[ "$V_PROTO" != "$old_proto" ]]; then
        sqlite3 "$XUIDB" "DELETE FROM client_traffics WHERE inbound_id=${id};" 2>/dev/null || true
    fi
    set_host "$id" "$V_SEC" "$sni"

    apply_nginx
    restart_xui
    msg_ok "Подключение #${id} изменено: ${V_PROTO}, ${V_NET}, ${V_SEC}. Клиентам нужно обновить подписку."
}

###############################################################################
# [4] ПОЛНОЕ УДАЛЕНИЕ
###############################################################################
action_uninstall() {
    msg_wrn "Будут удалены: 3x-ui с базой (все подключения и клиенты), nginx со всеми конфигами,"
    msg_wrn "сайт-заглушка, Fail2ban с дашбордом и GeoIP-защита."
    confirm "Продолжить удаление?" n || return

    systemctl stop x-ui 2>/dev/null || true
    systemctl disable x-ui 2>/dev/null || true
    rm -rf "$XUI_DIR" /etc/x-ui /usr/bin/x-ui /etc/systemd/system/x-ui.service
    systemctl daemon-reload

    systemctl stop nginx 2>/dev/null || true
    apt-get purge -y 'nginx*' 'libnginx-mod-*' >/dev/null 2>&1 || true
    rm -rf /etc/nginx /var/www/html

    # Fail2ban, дашборд, GeoIP (конфиги nginx уже удалены вместе с /etc/nginx)
    systemctl stop fail2ban 2>/dev/null || true
    apt-get purge -y fail2ban >/dev/null 2>&1 || true
    rm -rf /etc/fail2ban "$DASH_ROOT"
    rm -f "$DASH_GEN" "$DASH_CRON" "$GEOIP_UPDATER" "$GEOIP_CRON" "$GEOIP_DB" /run/f2b-dash.lock

    rm -rf "$STATE_DIR"
    rm -f /etc/letsencrypt/renewal-hooks/pre/stop-nginx.sh \
          /etc/letsencrypt/renewal-hooks/post/start-nginx.sh \
          /etc/sysctl.d/99-xpro.conf "$SUMMARY_FILE"
    sysctl --system >/dev/null 2>&1 || true
    # Возвращаем IPv6, отключённый при установке (без этого он остался бы выключенным до перезагрузки)
    sysctl -qw net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.default.disable_ipv6=0 \
               net.ipv6.conf.lo.disable_ipv6=0 2>/dev/null || true

    # У Let's Encrypt лимит выпусков на домен, поэтому сертификаты по умолчанию остаются
    if confirm "Удалить также certbot и все сертификаты Let's Encrypt (/etc/letsencrypt)?" n; then
        apt-get purge -y certbot >/dev/null 2>&1 || true
        rm -rf /etc/letsencrypt /var/lib/letsencrypt /var/log/letsencrypt
    fi
    if confirm "Сбросить и выключить UFW (сервер останется без фаервола)?" n; then
        ufw --force reset >/dev/null 2>&1 || true
        ufw disable >/dev/null 2>&1 || true
    fi
    apt-get autoremove -y >/dev/null 2>&1 || true
    msg_ok "3x-ui и nginx удалены."

    if confirm "Удалить и сам скрипт ($0) вместе с командой xpro?" n; then
        rm -f -- "$0" "$XPRO_BIN"
        msg_ok "Скрипт удалён."
        exit 0
    fi
}

###############################################################################
# ГЛАВНОЕ МЕНЮ
###############################################################################
# ─── [7] Показать доступы ────────────────────────────────────────────────────
# Сводка лежит в /root/xpro-summary.txt (права 600). Сначала показываем её
# с закрытыми паролями, открытым текстом — только по явному подтверждению.
action_access() {
    if [[ ! -s "$SUMMARY_FILE" ]]; then
        msg_wrn "Файл ${SUMMARY_FILE} не найден (он создаётся при установке и мог быть удалён)."
        if load_state 2>/dev/null; then
            echo "  Панель:   https://${MAIN_DOMAIN}/${PANEL_PATH}/"
            [[ -n "$F2B_PATH" ]] && echo "  Дашборд:  https://${MAIN_DOMAIN}/${F2B_PATH}/"
            echo "  Подписка: https://${MAIN_DOMAIN}/${SUB_PATH}/<subId>"
            echo "  Пароли нигде больше не хранятся: дашборд — пункт [4], панель — команда x-ui."
        fi
        return
    fi

    sed -E 's/(Пароль:[[:space:]]*).*/\1********/' "$SUMMARY_FILE"
    echo
    if confirm "Отобразить пароли открытым текстом?" n; then
        echo
        cat "$SUMMARY_FILE"
    fi
}

# ─── Рамка шапки меню ────────────────────────────────────────────────────────
# Ширина считается программно (в символах, локаль UTF-8), поэтому рамка всегда ровная.
BOX_W=64

box_border() {    # $1 — левый угол, $2 — правый угол
    local line
    printf -v line '%*s' "$BOX_W" ''
    echo -e "\e[1;36m${1}${line// /═}${2}\e[0m"
}

box_line() {      # $1 — текст (по центру), $2 — ANSI-стиль текста
    local t="$1" l r
    l=$(( (BOX_W - ${#t}) / 2 ))
    r=$(( BOX_W - ${#t} - l ))
    printf '\e[1;36m║\e[0m%*s\e[%sm%s\e[0m%*s\e[1;36m║\e[0m\n' "$l" '' "${2:-0}" "$t" "$r" ''
}

show_menu() {
    local status="не установлен"
    systemctl is-active --quiet x-ui 2>/dev/null && status="работает"
    [[ "$status" == "не установлен" && -f "$XUIDB" ]] && status="установлен, остановлен"

    clear 2>/dev/null || true
    box_border "╔" "╗"
    box_line ""
    box_line "xpro v${XPRO_VERSION} — Secure VPN Deploy" "1;37"
    box_line "3x-ui · Nginx SNI · Reality · Fail2ban · GeoIP · 443" "0;36"
    box_line ""
    box_border "╚" "╝"
    # Сообщение об установке команды xpro показываем один раз (clear стирает вывод до меню)
    if [[ -n "$XPRO_NOTE" ]]; then
        echo -e "  \e[1;32m${XPRO_NOTE}\e[0m"
        XPRO_NOTE=""
    fi
    echo -e "  Состояние 3x-ui: \e[1;33m${status}\e[0m"
    if load_state 2>/dev/null; then
        echo -e "  Панель:  \e[1;34mhttps://${MAIN_DOMAIN}/${PANEL_PATH}/\e[0m"
        [[ -n "$F2B_PATH" ]] && echo -e "  Дашборд: \e[1;34mhttps://${MAIN_DOMAIN}/${F2B_PATH}/\e[0m"
        [[ $GEOIP_ENABLED == y ]] && echo -e "  GeoIP:   \e[1;32mвключён\e[0m (панель и дашборд — только ${GEOIP_ALLOW_COUNTRY} и whitelist)"
    fi
    echo
    # Пункты про саму панель (2, 3, 7) без установленной 3x-ui не показываем.
    # Fail2ban и GeoIP видны всегда: часть их функций работает и без панели.
    INSTALLED=n
    [[ -f "$STATE_FILE" && -f "$XUIDB" ]] && INSTALLED=y

    echo -e "  \e[1;32m[1]\e[0m Установить 3x-ui с нуля (Nginx, SSL, UFW, БД)"
    if [[ $INSTALLED == y ]]; then
        echo -e "  \e[1;32m[2]\e[0m Добавить новое подключение (inbound)"
        echo -e "  \e[1;32m[3]\e[0m Изменить существующее подключение (смена протокола/транспорта)"
    fi
    echo -e "  \e[1;32m[4]\e[0m Управление Fail2ban и дашбордом (установить / удалить / сменить пароль)"
    echo -e "  \e[1;32m[5]\e[0m Управление GeoIP и Whitelist (включить / отключить / добавить IP)"
    echo -e "  \e[1;31m[6]\e[0m Полное удаление всего"
    if [[ $INSTALLED == y ]]; then
        echo -e "  \e[1;32m[7]\e[0m Показать доступы (панель, дашборд, подписки)"
    fi
    echo -e "  \e[1;37m[0]\e[0m Выход"
    echo
}

# Глобальная команда xpro: скрипт копирует себя в /usr/local/bin/xpro при первом запуске
# и при каждом запуске более новой (изменённой) версии файла.
XPRO_BIN="/usr/local/bin/xpro"
XPRO_NOTE=""

install_xpro() {
    local self
    self=$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null)
    # Запуск не из файла (например, bash <(curl ...)) — копировать нечего
    [[ -n "$self" && -f "$self" ]] || return 0
    [[ "$self" == "$XPRO_BIN" ]] && return 0
    cmp -s "$self" "$XPRO_BIN" 2>/dev/null && return 0

    local what="установлена"
    [[ -f "$XPRO_BIN" ]] && what="обновлена"
    if install -m 755 "$self" "$XPRO_BIN"; then
        XPRO_NOTE="Команда xpro ${what}: теперь меню можно вызывать из любого места — sudo xpro"
        msg_ok "$XPRO_NOTE"
    else
        msg_wrn "Не удалось скопировать скрипт в ${XPRO_BIN}."
    fi
}

main_menu() {
    local choice
    while true; do
        show_menu
        read -rp "  Выберите пункт: " choice
        echo
        # Скрытые пункты нельзя вызвать и вводом номера вручную
        if [[ $INSTALLED == n && "$choice" =~ ^[237]$ ]]; then choice="скрыт"; fi
        case "$choice" in
            1) action_install;   pause ;;
            2) action_add;       pause ;;
            3) action_modify;    pause ;;
            4) action_f2b ;;
            5) action_geoip ;;
            6) action_uninstall; pause ;;
            7) action_access;    pause ;;
            0) exit 0 ;;
            *) msg_wrn "Нет такого пункта."; sleep 1 ;;
        esac
    done
}

install_xpro
main_menu
