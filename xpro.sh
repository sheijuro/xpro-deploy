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

[[ $EUID -ne 0 ]] && { echo "Run as root / Запустите от root: sudo bash $0"; exit 1; }

# UTF-8 локаль нужна для кириллицы в case-шаблонах и для эмодзи (C.UTF-8 есть в Debian всегда)
export LC_ALL=C.UTF-8
set -uo pipefail

# ─── Константы ───────────────────────────────────────────────────────────────
XPRO_VERSION="1.3.2"     # номер версии: показывается в шапке меню, совпадает с тегом релиза на GitHub
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
# Язык интерфейса: ru | en. Выбор сохраняется в файле и переживает переустановку.
XLANG="ru"
LANG_FILE="/etc/xpro-lang"

# L "русский" "english" — строка на текущем языке (если перевода нет, остаётся русский)
L() { if [[ $XLANG == en && -n "${2:-}" ]]; then printf '%s' "$2"; else printf '%s' "$1"; fi; }

# say "русский" "english" — echo -e на текущем языке
say() { echo -e "$(L "$@")"; }

# Все сообщения принимают два аргумента: русский текст и английский
msg_ok()  { echo -e "\e[1;32m[OK]\e[0m $(L "$@")"; }
msg_inf() { echo -e "\e[1;34m[..]\e[0m $(L "$@")"; }
msg_wrn() { echo -e "\e[1;33m[!!]\e[0m $(L "$@")"; }
die()     { echo -e "\e[1;31m[$(L "ОШИБКА" "ERROR")]\e[0m $(L "$@")" >&2; exit 1; }

load_lang() {
    [[ -f "$LANG_FILE" ]] || return 1
    XLANG=$(tr -dc 'a-z' < "$LANG_FILE")
    [[ "$XLANG" == en ]] || XLANG="ru"
}

choose_lang() {
    local c
    echo
    echo "  Язык / Language:"
    echo "    1) Русский"
    echo "    2) English"
    read -rp "  [1]: " c
    case "$c" in 2) XLANG="en" ;; *) XLANG="ru" ;; esac
    echo "$XLANG" > "$LANG_FILE" 2>/dev/null
}

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

# Двуязычные варианты: askl VAR "рус" "eng" [по умолчанию], confirml "рус" "eng" [y|n]
askl()     { ask "$1" "$(L "$2" "$3")" "${4:-}"; }
confirml() { confirm "$(L "$1" "$2")" "${3:-n}"; }

pause() { echo; read -rp "$(L "Нажмите Enter для возврата в меню..." "Press Enter to return to the menu...")" _; }

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
        msg_wrn "Установка этого скрипта не найдена (${STATE_FILE}). Сначала выполните пункт [1]." \
                "No installation made by this script was found (${STATE_FILE}). Run item [1] first."
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

# Все подключения из базы, включая созданные вручную в веб-панели (для показа и выбора)
all_inbounds_json() {
    local out
    out=$(sqlite3 -json "$XUIDB" \
        "SELECT id, remark, listen, port, protocol, stream_settings FROM inbounds ORDER BY id;" 2>/dev/null)
    echo "${out:-[]}"
}

# Строки: тип<TAB>порт<TAB>значение.
#   reality — подключение, которое nginx stream находит по SNI (Reality или собственный TLS), значение = SNI;
#   ws / grpc / xhttp — подключение за nginx http на основном домене, значение = путь.
inbound_routes() {
    inbounds_json | jq -r '.[]
        | ((.stream_settings | fromjson?) // {}) as $s
        | if   $s.security == "reality" then ["reality", .port, ($s.realitySettings.serverNames[0] // "")]
          elif $s.security == "tls"     then ["reality", .port, ($s.tlsSettings.serverName // "")]
          elif $s.network  == "ws"      then ["ws",      .port, ($s.wsSettings.path // "")]
          elif $s.network  == "grpc"    then ["grpc",    .port, ($s.grpcSettings.serviceName // "")]
          elif $s.network  == "xhttp"   then ["xhttp",   .port, ($s.xhttpSettings.path // "")]
          else empty end
        | @tsv'
}

list_inbounds() {
    printf '  %-4s %-28s %-7s %-12s %-6s %s\n' "ID" "$(L "Название" "Name")" "$(L "Порт" "Port")" \
        "$(L "Протокол" "Protocol")" "$(L "Сеть" "Net")" "$(L "Защита" "Security")"
    # Подключение, созданное в панели не на 127.0.0.1, через Nginx не идёт и снаружи закрыто фаерволом —
    # оно помечается, чтобы было видно, почему оно не работает.
    all_inbounds_json | jq -r --arg via "$(L "TLS через nginx" "TLS via nginx")" \
        --arg ext "$(L "[не на 127.0.0.1 — снаружи недоступно]" "[not on 127.0.0.1 — unreachable from outside]")" '.[]
        | ((.stream_settings | fromjson?) // {}) as $s
        | [.id, .remark, .port, .protocol, ($s.network // "?"),
           (if   $s.security == "reality" then "Reality, SNI " + ($s.realitySettings.serverNames[0] // "?")
            elif $s.security == "tls"     then "TLS, SNI " + ($s.tlsSettings.serverName // "?")
            else $via end) + (if .listen != "127.0.0.1" then " " + $ext else "" end)]
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

# Здесь и ниже вместо "grep -q" стоит "grep ... >/dev/null": grep -q выходит на первом совпадении,
# команда слева получает SIGPIPE, и при включённом pipefail весь конвейер считается неудачным.
port_is_listening() { ss -Hltn 2>/dev/null | awk '{print $4}' | grep -E "[:.]$1\$" >/dev/null; }

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
        read -rp "$2 $(L "(Enter = случайный)" "(Enter = random)"): " __p
        [[ -z "$__p" ]] && __p=$(gen_free_port)
        if [[ ! "$__p" =~ ^[0-9]+$ ]] || (( __p < 1 || __p > 65535 )); then
            msg_wrn "Порт должен быть числом 1-65535." "The port must be a number 1-65535."; continue
        fi
        if ! port_is_free "$__p"; then
            msg_wrn "Порт $__p занят или зарезервирован, выберите другой." \
                    "Port $__p is busy or reserved, choose another one."; continue
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
        msg_wrn "Некорректное доменное имя." "Invalid domain name."
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
        ask_domain __s "$(L "  SNI-домен этого подключения (свой поддомен, A-запись на этот сервер)" \
                             "  SNI domain for this connection (its own subdomain, A record to this server)")" "$__def"
        sni_in_use "$__s" || break
        msg_wrn "Домен $__s уже занят (основным доменом или другим подключением)." \
                "Domain $__s is already in use (by the main domain or another connection)."
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
# Английское название страны по ISO-коду (для интерфейса на английском)
country_en() {
    case "$1" in
        FI) echo "Finland" ;;      DE) echo "Germany" ;;       NL) echo "Netherlands" ;;  FR) echo "France" ;;
        GB) echo "United Kingdom" ;; US) echo "USA" ;;         CA) echo "Canada" ;;       SE) echo "Sweden" ;;
        NO) echo "Norway" ;;       DK) echo "Denmark" ;;       EE) echo "Estonia" ;;      LV) echo "Latvia" ;;
        LT) echo "Lithuania" ;;    PL) echo "Poland" ;;        CZ) echo "Czechia" ;;      AT) echo "Austria" ;;
        CH) echo "Switzerland" ;;  IT) echo "Italy" ;;         ES) echo "Spain" ;;        PT) echo "Portugal" ;;
        IE) echo "Ireland" ;;      BE) echo "Belgium" ;;       RO) echo "Romania" ;;      BG) echo "Bulgaria" ;;
        MD) echo "Moldova" ;;      RS) echo "Serbia" ;;        TR) echo "Turkey" ;;       AE) echo "UAE" ;;
        KZ) echo "Kazakhstan" ;;   AM) echo "Armenia" ;;       GE) echo "Georgia" ;;      RU) echo "Russia" ;;
        JP) echo "Japan" ;;        KR) echo "South Korea" ;;   SG) echo "Singapore" ;;    HK) echo "Hong Kong" ;;
        IN) echo "India" ;;        AU) echo "Australia" ;;     IL) echo "Israel" ;;       *)  echo "$1" ;;
    esac
}

make_remark() {
    resolve_country "$1"
    [[ $XLANG == en && -n "$COUNTRY_CODE" ]] && COUNTRY_NAME=$(country_en "$COUNTRY_CODE")
    if [[ -n "$COUNTRY_CODE" ]]; then
        printf '%s %s' "$(flag_from_iso "$COUNTRY_CODE")" "$COUNTRY_NAME"
    else
        printf '🌐 %s' "$COUNTRY_NAME"
    fi
}

###############################################################################
# КОНСТРУКТОР ПОДКЛЮЧЕНИЙ
###############################################################################
# Три класса подключений (V_SEC):
#   reality — nginx stream отдаёт TLS как есть в Xray по SNI, Xray маскируется под свой же сайт;
#   tls     — то же, но Xray сам снимает TLS сертификатом своего домена (классический TCP+TLS);
#   nginx   — TLS снимает nginx на основном домене и проксирует по пути (WebSocket/gRPC/XHTTP).
# Классам reality и tls нужен отдельный домен на каждое подключение, классу nginx — нет.
# Shadowsocks не умеет Reality в панели, а "голый" TCP нельзя развести по SNI на 443,
# поэтому для него доступны только варианты через nginx.

# needs_sni SEC — нужен ли подключению собственный домен (маршрутизация по SNI)
needs_sni() { [[ "$1" == reality || "$1" == tls ]]; }

# choose_variant → V_PROTO (vless|trojan|shadowsocks), V_NET (tcp|ws|grpc|xhttp), V_SEC (reality|tls|nginx)
choose_variant() {
    local p t via own
    via=$(L "через nginx, основной домен" "via nginx, main domain")
    own=$(L "свой домен и сертификат" "own domain and certificate")

    say "  Протокол:" "  Protocol:"
    echo "    1) VLESS"
    echo "    2) Trojan"
    echo "    3) Shadowsocks (2022-blake3-aes-256-gcm)"
    while true; do
        askl p "  Выбор" "  Choice" "1"
        [[ "$p" =~ ^[123]$ ]] && break
        msg_wrn "Введите 1, 2 или 3." "Enter 1, 2 or 3."
    done
    case "$p" in 1) V_PROTO=vless ;; 2) V_PROTO=trojan ;; 3) V_PROTO=shadowsocks ;; esac

    say "  Транспорт и защита:" "  Transport and security:"
    if [[ $V_PROTO == shadowsocks ]]; then
        echo "    1) WebSocket + TLS (${via})"
        echo "    2) gRPC      + TLS (${via})"
        echo "    3) XHTTP     + TLS (${via})"
        while true; do
            askl t "  Выбор" "  Choice" "1"
            [[ "$t" =~ ^[123]$ ]] && break
            msg_wrn "Введите 1, 2 или 3." "Enter 1, 2 or 3."
        done
        V_SEC=nginx
        case "$t" in 1) V_NET=ws ;; 2) V_NET=grpc ;; 3) V_NET=xhttp ;; esac
    else
        echo "    1) TCP       + Reality"
        echo "    2) gRPC      + Reality"
        echo "    3) XHTTP     + Reality"
        echo "    4) TCP       + TLS (${own})"
        echo "    5) WebSocket + TLS (${via})"
        echo "    6) gRPC      + TLS (${via})"
        echo "    7) XHTTP     + TLS (${via})"
        while true; do
            askl t "  Выбор" "  Choice" "1"
            [[ "$t" =~ ^[1-7]$ ]] && break
            msg_wrn "Введите число 1-7." "Enter a number 1-7."
        done
        case "$t" in
            1) V_NET=tcp;   V_SEC=reality ;;
            2) V_NET=grpc;  V_SEC=reality ;;
            3) V_NET=xhttp; V_SEC=reality ;;
            4) V_NET=tcp;   V_SEC=tls ;;
            5) V_NET=ws;    V_SEC=nginx ;;
            6) V_NET=grpc;  V_SEC=nginx ;;
            7) V_NET=xhttp; V_SEC=nginx ;;
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
    [[ -x "$XRAY_BIN" ]] || die "Не найден бинарник xray в $XUI_DIR/bin" "xray binary not found in $XUI_DIR/bin"
}

# gen_reality SNI → JSON realitySettings с новыми ключами x25519 и shortIds
gen_reality() {
    local keys priv pub sids
    # Формат вывода `xray x25519` менялся ("Private key:/Public key:" → "PrivateKey:/Password:")
    keys=$("$XRAY_BIN" x25519) || die "xray x25519 завершился с ошибкой" "xray x25519 failed"
    priv=$(awk '/^Private ?[Kk]ey/{print $NF; exit}'           <<<"$keys")
    pub=$(awk  '/^(Password|Public ?[Kk]ey)/{print $NF; exit}' <<<"$keys")
    [[ -n "$priv" && -n "$pub" ]] || die "Не удалось разобрать ключи x25519: $keys" "Failed to parse x25519 keys: $keys"
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
    local net="$1" sec="$2" sni="$3" r="${4:-}" pp=false secname=none tls=null path
    path=$(gen_random_string 12)
    if [[ $sec == reality ]]; then
        if [[ -n "$r" ]]; then
            # Сохраняем прежние ключи, чтобы у клиентов менялся только транспорт
            r=$(jq -c --arg sni "$sni" --arg fp "$FINGERPRINT" '.serverNames=[$sni] | .settings.fingerprint=$fp' <<<"$r")
        else
            r=$(gen_reality "$sni")
        fi
        pp=true; secname=reality      # nginx stream шлёт PROXY protocol → inbound обязан его принимать
    elif [[ $sec == tls ]]; then
        # Xray сам снимает TLS сертификатом Let's Encrypt своего домена (файлы он перечитывает сам)
        r=null; pp=true; secname=tls
        tls=$(jq -cn --arg sni "$sni" --arg fp "$FINGERPRINT" '{
            serverName:$sni, minVersion:"1.2", maxVersion:"1.3", cipherSuites:"",
            rejectUnknownSni:false, disableSystemRoot:false, enableSessionResumption:false,
            certificates:[{certificateFile:("/etc/letsencrypt/live/"+$sni+"/fullchain.pem"),
                           keyFile:("/etc/letsencrypt/live/"+$sni+"/privkey.pem"),
                           ocspStapling:3600, oneTimeLoading:false, usage:"encipherment", buildChain:false}],
            alpn:["h2","http/1.1"],
            settings:{allowInsecure:false, fingerprint:$fp, echConfigList:""}}')
    else
        r=null                        # трафик приходит от nginx http, PROXY protocol не используется
    fi

    STREAM_JSON=$(jq -cn --arg net "$net" --arg sec "$secname" --argjson r "$r" --argjson tls "$tls" \
        --argjson pp "$pp" --arg path "$path" --arg host "$MAIN_DOMAIN" '
        {network:$net, security:$sec}
        + (if $sec == "reality" then {realitySettings:$r} elif $sec == "tls" then {tlsSettings:$tls} else {} end)
        + (if   $net == "tcp"  then {tcpSettings:{acceptProxyProtocol:$pp, header:{type:"none"}}}
           elif $net == "ws"   then {wsSettings:{acceptProxyProtocol:false, path:("/"+$path), host:$host, headers:{}}}
           elif $net == "grpc" then {grpcSettings:{serviceName:$path, authority:(if $sec=="reality" then "" else $host end), multiMode:false}}
           else {xhttpSettings:{path:("/"+$path), host:(if $sec=="reality" then "" else $host end), mode:"auto"}} end)
        + (if $pp and $net != "tcp" then {sockopt:{acceptProxyProtocol:true}} else {} end)')
    jq -e . <<<"$STREAM_JSON" >/dev/null || die "Сформирован некорректный JSON stream_settings" "Generated stream_settings JSON is invalid"
}

# Структура БД зависит от версии панели — проверяем фактическую схему
detect_schema() {
    HAS_HOSTS=n; HAS_GROUP_ID=n
    [[ -n "$(sqlite3 "$XUIDB" "SELECT name FROM sqlite_master WHERE type='table' AND name='hosts';")" ]] && HAS_HOSTS=y
    sqlite3 "$XUIDB" "PRAGMA table_info(hosts);" | grep -w group_id >/dev/null && HAS_GROUP_ID=y
    return 0
}

# Внешний адрес для ссылок/подписки: всегда <домен>:443, а не 127.0.0.1:<порт>.
# Старые панели (без таблицы hosts) берут его из externalProxy в stream_settings.
add_external_proxy() {    # SEC SNI
    [[ $HAS_HOSTS == y ]] && return 0
    local dest="$MAIN_DOMAIN" force="tls"
    needs_sni "$1" && { dest="$2"; force="same"; }
    STREAM_JSON=$(jq -c --arg d "$dest" --arg f "$force" \
        '. + {externalProxy:[{forceTls:$f, dest:$d, port:443, remark:""}]}' <<<"$STREAM_JSON")
}

# Новые панели: запись в таблице hosts
set_host() {              # INBOUND_ID SEC SNI
    [[ $HAS_HOSTS == y ]] || return 0
    local id="$1" addr="$MAIN_DOMAIN" sec="tls" fp="$FINGERPRINT" alpn='["h2"]' gid_col="" gid_val=""
    needs_sni "$2" && { addr="$3"; sec="same"; fp=""; alpn='[]'; }
    [[ "$2" == nginx ]] && alpn='["h2","http/1.1"]'    # WebSocket идёт по HTTP/1.1, gRPC и XHTTP — по h2
    [[ $HAS_GROUP_ID == y ]] && { gid_col='group_id,'; gid_val="'$(gen_group_id)',"; }
    sqlite3 "$XUIDB" "DELETE FROM hosts WHERE inbound_id=${id};
        INSERT INTO hosts (inbound_id, ${gid_col} sort_order, remark, address, port, security, fingerprint, alpn)
        VALUES (${id}, ${gid_val} 0, '', '${addr}', 443, '${sec}', '${fp}', '${alpn}');" \
        || msg_wrn "Не удалось записать host для inbound #${id} — задайте внешний адрес ${addr}:443 в панели вручную." \
                   "Failed to write the host for inbound #${id} — set the external address ${addr}:443 in the panel manually."
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
        || die "Ошибка добавления подключения на порт ${port}" "Failed to add the connection on port ${port}"

    id=$(sqlite3 "$XUIDB" "SELECT id FROM inbounds WHERE tag='${tag}';")
    set_host "$id" "$sec" "$sni"
    msg_ok "Подключение: ${remark} → 127.0.0.1:${port} (${proto}, ${net}, ${sec})" \
           "Connection: ${remark} → 127.0.0.1:${port} (${proto}, ${net}, ${sec})"
}

# ─── Интерактивный сбор параметров одного подключения ────────────────────────
P_REMARK=(); P_PORT=(); P_PROTO=(); P_NET=(); P_SEC=(); P_SNI=()

collect_one_inbound() {
    local country remark port sni=""
    askl country "  Страна (название или ISO-код: Финляндия, Germany, NL ...)" \
                 "  Country (name or ISO code: Finland, Germany, NL ...)"
    [[ -z "$country" ]] && country="XX"
    remark=$(make_remark "$country")

    ask_port port "$(L "  Локальный порт подключения, напр. 440, 444, 445" "  Local port of the connection, e.g. 440, 444, 445")"
    choose_variant
    if needs_sni "$V_SEC"; then
        say "  Nginx различает такие подключения на 443 только по SNI — нужен отдельный (под)домен." \
            "  Nginx tells such connections apart on 443 only by SNI — a separate (sub)domain is required."
        ask_sni sni
    fi

    P_REMARK+=("$remark"); P_PORT+=("$port"); P_PROTO+=("$V_PROTO")
    P_NET+=("$V_NET"); P_SEC+=("$V_SEC"); P_SNI+=("$sni")
    msg_ok "Принято: ${remark} | 127.0.0.1:${port} | ${V_PROTO} ${V_NET} ${V_SEC}${sni:+ | SNI ${sni}}" \
           "Accepted: ${remark} | 127.0.0.1:${port} | ${V_PROTO} ${V_NET} ${V_SEC}${sni:+ | SNI ${sni}}"
}

collect_inbounds_loop() {
    P_REMARK=(); P_PORT=(); P_PROTO=(); P_NET=(); P_SEC=(); P_SNI=()
    while confirml "Хотите добавить ноду/подключение?" "Add a node/connection?" y; do
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
    [[ -f "/etc/letsencrypt/live/${d}/fullchain.pem" ]] && { msg_ok "Сертификат для $d уже есть." "A certificate for $d already exists."; return 0; }
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

# Блок location для WebSocket-подключения за nginx (HTTP/1.1 Upgrade к Xray на loopback)
ws_location() {           # PATH PORT
    cat <<EOF

    location /$1 {
        proxy_pass http://127.0.0.1:$2;
        proxy_http_version 1.1;
        proxy_set_header Upgrade         \$http_upgrade;
        proxy_set_header Connection      "upgrade";
        proxy_set_header Host            \$host;
        proxy_set_header X-Real-IP       \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_read_timeout 1h;
        proxy_send_timeout 1h;
        proxy_buffering    off;
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
    msg_inf "Сборка конфигурации Nginx..." "Building Nginx configuration..."
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
                    msg_wrn "Порт ${port}: некорректный SNI '${val}' — пропущено." "Port ${port}: invalid SNI '${val}' — skipped."; continue; fi
                if [[ "$val" == "$MAIN_DOMAIN" || "$seen_sni" == *" $val "* ]]; then
                    msg_wrn "Порт ${port}: SNI ${val} уже занят — подключение не будет доступно снаружи." "Port ${port}: SNI ${val} is already in use — the connection will not be reachable from outside."; continue; fi
                if [[ ! -f "/etc/letsencrypt/live/${val}/fullchain.pem" ]]; then
                    msg_wrn "Порт ${port}: нет сертификата для ${val} — пропущено." "Port ${port}: no certificate for ${val} — skipped."; continue; fi
                seen_sni+="$val "
                map_lines+="    ${val}    inb_${port};"$'\n'
                upstreams+="upstream inb_${port} { server 127.0.0.1:${port}; }"$'\n'
                [[ "$val" != "$REALITY_DOMAIN" ]] && sni_domains+=("$val")
                ;;
            grpc|xhttp)
                val="${val#/}"
                if [[ ! "$val" =~ ^[A-Za-z0-9/_-]+$ ]]; then
                    msg_wrn "Порт ${port}: путь '${val}' не подходит для nginx — пропущено." "Port ${port}: path '${val}' is not suitable for nginx — skipped."; continue; fi
                h2_locations+=$(h2_location "$val" "$port")$'\n'
                ;;
            ws)
                val="${val#/}"
                if [[ ! "$val" =~ ^[A-Za-z0-9/_-]+$ ]]; then
                    msg_wrn "Порт ${port}: путь '${val}' не подходит для nginx — пропущено." "Port ${port}: path '${val}' is not suitable for nginx — skipped."; continue; fi
                h2_locations+=$(ws_location "$val" "$port")$'\n'
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

    nginx -t || die "Проверка конфигурации nginx не пройдена (см. вывод выше)." "nginx configuration check failed (see the output above)."
    systemctl enable nginx >/dev/null 2>&1
    systemctl restart nginx || die "nginx не запустился: journalctl -u nginx -n 50" "nginx did not start: journalctl -u nginx -n 50"
    msg_ok "Nginx перезапущен." "Nginx restarted."
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
    local url tmp src site_name prev="" tries=0
    # Какой шаблон стоит сейчас — чтобы при смене заглушки не выпал тот же самый.
    # Отметка лежит вне папки сайта, иначе её можно было бы скачать по ссылке.
    [[ -f "${STATE_DIR}/site" ]] && prev=$(cat "${STATE_DIR}/site" 2>/dev/null)
    while true; do
        url="${FAKE_SITES[RANDOM % ${#FAKE_SITES[@]}]}"
        site_name=$(basename "$(dirname "$(dirname "$(dirname "$(dirname "$url")")")")")
        tries=$((tries + 1))
        [[ "$site_name" != "$prev" || $tries -ge 10 ]] && break
    done
    tmp=$(mktemp -d)
    mkdir -p /var/www/html
    rm -rf /var/www/html/*

    msg_inf "Сайт-заглушка: ${site_name}" "Decoy site: ${site_name}"
    if wget -q --show-progress -T 30 -O "$tmp/site.tar.gz" "$url" && tar -xzf "$tmp/site.tar.gz" -C "$tmp"; then
        src=$(find "$tmp" -maxdepth 2 -type d -name dist | head -1)
        if [[ -n "$src" && -f "$src/index.html" ]]; then
            cp -a "$src"/. /var/www/html/
            # Убираем узнаваемую подпись шаблона: на каждом сервере — своё случайное название сайта
            local brands=("Northwind Studio" "Aurora Labs" "Bluepeak" "Vertex Digital" "Lumen Works"
                          "Nordic Cloud" "Stonebridge" "Pixelcraft" "Greyline Media" "Summit Systems"
                          "Harbor & Co" "Silverpine" "Atlas Creative" "Echo Valley" "Brightwave")
            local brand="${brands[RANDOM % ${#brands[@]}]}"
            find /var/www/html -maxdepth 1 -name '*.html' -exec sed -i "s/Start Bootstrap/${brand}/g" {} +
            mkdir -p "$STATE_DIR"
            echo "$site_name" > "${STATE_DIR}/site"
            msg_ok "Шаблон сайта установлен, название сайта: ${brand}" "Site template installed, site name: ${brand}"
        fi
    fi
    if [[ ! -f /var/www/html/index.html ]]; then
        msg_wrn "Не удалось скачать шаблон — ставлю простую страницу." "Failed to download the template — installing a simple page."
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
        msg_wrn "Некорректный IPv4-адрес или подсеть: $1" "Invalid IPv4 address or subnet: $1"; return 1
    fi
    mkdir -p "$STATE_DIR"
    echo "$1" >> "$WHITELIST_FILE"
    sort -u -o "$WHITELIST_FILE" "$WHITELIST_FILE"
    chmod 600 "$WHITELIST_FILE"
    msg_ok "В whitelist добавлен: $1" "Added to the whitelist: $1"
}

# Интерактивный ввод whitelist: текущий IP администратора + адреса зарубежных серверов
whitelist_ask() {
    local cip ip
    cip=$(admin_ip)
    if [[ "$cip" =~ $IP_RE ]]; then
        confirml "Добавить в whitelist ваш текущий IP (${cip}), чтобы не потерять доступ к панели?" "Add your current IP (${cip}) to the whitelist so you do not lose access to the panel?" y \
            && whitelist_add "$cip"
    fi
    say "IP-адреса или подсети зарубежных серверов для whitelist (по одному, Enter — закончить):" "IP addresses or subnets of foreign servers for the whitelist (one per line, Enter — finish):"
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
            msg_ok "База GeoIP обновлена (DB-IP Country Lite ${ym})." "GeoIP database updated (DB-IP Country Lite ${ym})."
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
    msg_inf "Настройка GeoIP-защиты админ-панелей..." "Setting up GeoIP protection for the admin panels..."
    export DEBIAN_FRONTEND=noninteractive
    if ! apt-get install -y libnginx-mod-http-geoip2 >/dev/null 2>&1; then
        msg_wrn "Не удалось установить libnginx-mod-http-geoip2 — GeoIP не включён." "Failed to install libnginx-mod-http-geoip2 — GeoIP is not enabled."; return 1
    fi
    if [[ ! -s "$GEOIP_DB" ]] && ! geoip_download_db; then
        msg_wrn "Не удалось скачать базу DB-IP — GeoIP не включён." "Failed to download the DB-IP database — GeoIP is not enabled."; return 1
    fi

    geoip_write_conf
    if ! nginx -t >/dev/null 2>&1; then
        nginx -t
        rm -f "$GEOIP_CONF"
        msg_wrn "Nginx не принял конфигурацию GeoIP — защита не включена." "Nginx rejected the GeoIP configuration — protection is not enabled."; return 1
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
    msg_ok "GeoIP готов: панель и дашборд доступны только из ${GEOIP_ALLOW_COUNTRY} и с адресов whitelist." "GeoIP is ready: the panel and dashboard are reachable only from ${GEOIP_ALLOW_COUNTRY} and whitelisted addresses."
}

geoip_disable() {
    GEOIP_ENABLED="n"
    save_state
    apply_nginx                       # убирает проверку из location панели и дашборда
    rm -f "$GEOIP_CONF" "$GEOIP_UPDATER" "$GEOIP_CRON"
    nginx -t >/dev/null 2>&1 && systemctl reload nginx
    msg_ok "GeoIP-защита отключена. Whitelist сохранён." "GeoIP protection disabled. The whitelist is kept."
}

# Применить изменения whitelist к работающему nginx
geoip_reload() {
    [[ $GEOIP_ENABLED == y ]] || return 0
    geoip_write_conf
    if nginx -t >/dev/null 2>&1; then
        systemctl reload nginx && msg_ok "Whitelist применён." "Whitelist applied."
    else
        nginx -t
        msg_wrn "Nginx не принял новый whitelist — проверьте ${WHITELIST_FILE}." "Nginx rejected the new whitelist — check ${WHITELIST_FILE}."
    fi
}

geoip_status() {
    if [[ $GEOIP_ENABLED == y ]]; then
        say "  GeoIP-защита: \e[1;32mвключена\e[0m (разрешена страна ${GEOIP_ALLOW_COUNTRY} + whitelist)" "  GeoIP protection: \e[1;32menabled\e[0m (allowed country ${GEOIP_ALLOW_COUNTRY} + whitelist)"
        [[ -f "$GEOIP_DB" ]] && say "  База: ${GEOIP_DB} от $(date -r "$GEOIP_DB" '+%d.%m.%Y')" \
                                    "  Database: ${GEOIP_DB}, dated $(date -r "$GEOIP_DB" '+%d.%m.%Y')"
    else
        say "  GeoIP-защита: \e[1;33mвыключена\e[0m" "  GeoIP protection: \e[1;33mdisabled\e[0m"
    fi
    say "  Всегда разрешены: 127.0.0.1 и адреса сервера ($(server_ips | paste -sd' '))" "  Always allowed: 127.0.0.1 and the server addresses ($(server_ips | paste -sd' '))"
    echo "  Whitelist:"
    local list
    list=$(whitelist_list)
    if [[ -n "$list" ]]; then sed 's/^/    /' <<<"$list"; else say "    (пусто)" "    (empty)"; fi
}

action_geoip() {
    # Без установленной панели доступен только whitelist: защищать GeoIP пока нечего
    if [[ $INSTALLED == y ]]; then require_install || return; fi
    local c ip
    while true; do
        echo
        say "\e[1;36m── GeoIP и Whitelist (панель 3x-ui и дашборд) ──\e[0m" "\e[1;36m── GeoIP and Whitelist (3x-ui panel and dashboard) ──\e[0m"
        geoip_status
        echo
        say "  [1] Включить GeoIP-защиту" "  [1] Enable GeoIP protection"
        say "  [2] Отключить GeoIP-защиту" "  [2] Disable GeoIP protection"
        say "  [3] Добавить IP в whitelist" "  [3] Add an IP to the whitelist"
        say "  [4] Удалить IP из whitelist" "  [4] Remove an IP from the whitelist"
        say "  [5] Обновить базу GeoIP" "  [5] Update the GeoIP database"
        say "  [0] Назад" "  [0] Back"
        read -rp "$(L "  Выберите пункт: " "  Choose an item: ")" c
        if [[ $INSTALLED == n && "$c" =~ ^[125]$ ]]; then
            msg_wrn "GeoIP защищает панель и дашборд — сначала установите 3x-ui (пункт [1] главного меню)." "GeoIP protects the panel and dashboard — install 3x-ui first (item [1] of the main menu)."
            msg_inf "Whitelist можно заполнить уже сейчас (пункты [3] и [4]): он применится при включении." "The whitelist can be filled right now (items [3] and [4]): it is applied when GeoIP is enabled."
            continue
        fi
        case "$c" in
            1)  msg_wrn "Если вы сами не в ${GEOIP_ALLOW_COUNTRY} и вашего IP нет в whitelist — панель перестанет открываться." "If you are not in ${GEOIP_ALLOW_COUNTRY} yourself and your IP is not whitelisted, the panel will stop opening."
                msg_wrn "Вернуть доступ можно будет по SSH: это меню, пункт [2]." "Access can be restored over SSH: this menu, item [2]."
                whitelist_ask
                if geoip_enable; then save_state; apply_nginx; fi ;;
            2)  geoip_disable ;;
            3)  askl ip "IP или подсеть" "IP or subnet"
                [[ -n "$ip" ]] && whitelist_add "$ip" && geoip_reload ;;
            4)  askl ip "IP или подсеть для удаления" "IP or subnet to remove"
                if [[ -n "$ip" && -f "$WHITELIST_FILE" ]] && grep -qxF "$ip" "$WHITELIST_FILE"; then
                    grep -vxF "$ip" "$WHITELIST_FILE" > "${WHITELIST_FILE}.tmp"
                    mv -f "${WHITELIST_FILE}.tmp" "$WHITELIST_FILE"
                    msg_ok "Удалён: $ip" "Removed: $ip"
                    geoip_reload
                else
                    msg_wrn "Такого адреса в whitelist нет." "No such address in the whitelist."
                fi ;;
            5)  geoip_download_db || msg_wrn "Не удалось скачать базу." "Failed to download the database." ;;
            0)  return ;;
            *)  msg_wrn "Нет такого пункта." "No such item." ;;
        esac
    done
}

###############################################################################
# FAIL2BAN
###############################################################################
# Принципы: логи Xray/3x-ui не подключаются; баны точечные (multiport);
# порт 443 (VPN) не банится никогда; вместо recidive — bantime.increment.
f2b_install() {
    msg_inf "Установка и настройка Fail2ban..." "Installing and configuring Fail2ban..."
    export DEBIAN_FRONTEND=noninteractive
    # python3-systemd нужен для чтения журнала systemd (Debian 12+ без auth.log)
    if ! apt-get install -y fail2ban python3-systemd >/dev/null 2>&1; then
        msg_wrn "Не удалось установить fail2ban." "Failed to install fail2ban."; return 1
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
        msg_wrn "В джейлах оказался порт 443 (VPN) — конфигурация Fail2ban отменена." "Port 443 (VPN) ended up in the jails — Fail2ban configuration cancelled."; return 1
    fi

    if ! fail2ban-client -t >/dev/null 2>&1; then
        fail2ban-client -t
        if [[ -f "${F2B_JAIL_LOCAL}.bak" ]]; then mv -f "${F2B_JAIL_LOCAL}.bak" "$F2B_JAIL_LOCAL"; else rm -f "$F2B_JAIL_LOCAL"; fi
        msg_wrn "Конфигурация Fail2ban не прошла проверку — изменения отменены." "Fail2ban configuration failed validation — changes reverted."; return 1
    fi

    systemctl enable fail2ban >/dev/null 2>&1
    if ! systemctl restart fail2ban; then
        msg_wrn "Fail2ban не запустился: journalctl -u fail2ban -n 30" "Fail2ban did not start: journalctl -u fail2ban -n 30"; return 1
    fi
    local i
    for i in 1 2 3 4 5 6 7 8 9 10; do
        fail2ban-client ping >/dev/null 2>&1 && {
            msg_ok "Fail2ban запущен." "Fail2ban is running."
            say "      SSH:       порт ${ssh_ports}, источник логов: ${ssh_backend}" "      SSH:       port ${ssh_ports}, log source: ${ssh_backend}"
            if [[ $with_nginx == y ]]; then
                say "      Nginx:     джейлы банят только порт 80" "      Nginx:     jails ban port 80 only"
            else
                say "      Nginx:     не установлен — джейлы Nginx добавятся после установки 3x-ui" "      Nginx:     not installed — Nginx jails are added after 3x-ui is installed"
            fi
            say "      Порт 443:  не банится никогда (VPN)" "      Port 443:  never banned (VPN)"
            echo "      ignoreip:  ${ignoreip}"
            return 0
        }
        sleep 1
    done
    msg_wrn "Fail2ban не ответил за 10 секунд: journalctl -u fail2ban -n 30" "Fail2ban did not respond within 10 seconds: journalctl -u fail2ban -n 30"; return 1
}

###############################################################################
# ДАШБОРД FAIL2BAN (127.0.0.1:63034, наружу — https://домен/секретный-путь/)
###############################################################################
DASH_USER=""; DASH_PASS=""; DASH_PASS_GENERATED="n"

dash_ask_credentials() {
    while true; do
        askl DASH_USER "Логин дашборда Fail2ban" "Fail2ban dashboard login"
        [[ "$DASH_USER" =~ ^[A-Za-z0-9._-]{1,32}$ ]] && break
        msg_wrn "Допустимы латинские буквы, цифры и символы . _ - (до 32 символов)." "Latin letters, digits and . _ - are allowed (up to 32 characters)."
    done
    DASH_PASS_GENERATED="n"
    local again
    while true; do
        read -rsp "$(L "Пароль дашборда (не короче 10 символов, Enter = сгенерировать): " "Dashboard password (at least 10 characters, Enter = generate): ")" DASH_PASS; echo
        if [[ -z "$DASH_PASS" ]]; then
            DASH_PASS=$(gen_random_string 20); DASH_PASS_GENERATED="y"; break
        fi
        if (( ${#DASH_PASS} < 10 )); then msg_wrn "Пароль слишком короткий." "The password is too short."; continue; fi
        read -rsp "$(L "Повторите пароль: " "Repeat the password: ")" again; echo
        [[ "$DASH_PASS" == "$again" ]] && break
        msg_wrn "Пароли не совпадают." "Passwords do not match."
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
    msg_inf "Установка дашборда Fail2ban..." "Installing the Fail2ban dashboard..."
    export DEBIAN_FRONTEND=noninteractive
    if ! apt-get install -y apache2-utils cron curl >/dev/null 2>&1; then
        msg_wrn "Не удалось установить apache2-utils/cron." "Failed to install apache2-utils/cron."; return 1
    fi
    systemctl enable --now cron >/dev/null 2>&1

    dash_write_htpasswd -B || { msg_wrn "htpasswd не смог создать файл паролей." "htpasswd could not create the password file."; return 1; }

    mkdir -p "${DASH_ROOT}/assets" "${DASH_ROOT}/api"
    dash_write_web_files
    dash_write_generator
    dash_localize

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
    "$DASH_GEN" || msg_wrn "Первый запуск генератора завершился с ошибкой: проверьте ${DASH_GEN}" "The first run of the generator failed: check ${DASH_GEN}"

    [[ "$F2B_PATH" =~ ^[A-Za-z0-9]{8,}$ ]] || F2B_PATH=$(gen_random_string 12)
    msg_ok "Дашборд подготовлен (127.0.0.1:${DASH_PORT}, данные: ${DASH_ROOT}/api/data.html)." "Dashboard prepared (127.0.0.1:${DASH_PORT}, data: ${DASH_ROOT}/api/data.html)."
}

# Проверка после apply_nginx: вход с паролем; если nginx не понимает bcrypt — переходим на apr1
dash_selftest() {
    local code cfg u="${DASH_USER//\\/\\\\}" p="${DASH_PASS//\\/\\\\}"
    cfg="user = \"${u//\"/\\\"}:${p//\"/\\\"}\""
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 -K - "http://127.0.0.1:${DASH_PORT}/api/data.html" <<<"$cfg")
    if [[ "$code" == "500" ]]; then
        msg_wrn "Nginx не поддерживает bcrypt — пересоздаю файл паролей в формате apr1." "Nginx does not support bcrypt — recreating the password file in apr1 format."
        dash_write_htpasswd -m
        code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 -K - "http://127.0.0.1:${DASH_PORT}/api/data.html" <<<"$cfg")
    fi
    if [[ "$code" == "200" ]]; then
        msg_ok "Дашборд отвечает, вход с логином и паролем работает." "The dashboard responds, login with the username and password works."
    else
        msg_wrn "Дашборд вернул код '${code}' (ожидался 200): см. /var/log/nginx/f2b-dash.error.log" "The dashboard returned code '${code}' (expected 200): see /var/log/nginx/f2b-dash.error.log"
    fi
    if ss -Hltn "sport = :${DASH_PORT}" 2>/dev/null | grep -vq "127.0.0.1:${DASH_PORT}"; then
        msg_wrn "Порт ${DASH_PORT} слушается не только на 127.0.0.1!" "Port ${DASH_PORT} is listening not only on 127.0.0.1!"
    fi
}

# Перевод дашборда на английский. Файлы дашборда пишутся на русском, а при английском
# интерфейсе фразы заменяются по списку "русский|английский" (длинные фразы — раньше коротких).
dash_localize() {
    [[ $XLANG == en ]] || return 0
    local p args=() pairs=(
        'lang="ru"|lang="en"'
        'Добро пожаловать!|Welcome!'
        'Панель статистики Fail2ban|Fail2ban statistics panel'
        'Для входа нужен включённый JavaScript.|JavaScript is required to sign in.'
        'Введите имя пользователя и пароль|Enter the username and password'
        'Неверное имя пользователя или пароль|Wrong username or password'
        'Имя пользователя|Username'
        'Сессия завершена: пароль был изменён. Войдите снова.|Session ended: the password was changed. Sign in again.'
        'Данные ещё не сформированы. Подождите минуту и попробуйте снова.|Data is not ready yet. Wait a minute and try again.'
        'Слишком много попыток. Подождите немного.|Too many attempts. Please wait a little.'
        'Ошибка обновления: |Update error: '
        'Ошибка сервера: |Server error: '
        'Нет связи с сервером|No connection to the server'
        'Проверка…|Checking…'
        'Обновлено: |Updated: '
        '>Пароль<|>Password<'
        'Войти|Sign in'
        'Обновить|Refresh'
        'Выйти|Sign out'
        'Защита от подбора паролей по SSH|Protection against SSH password guessing'
        'Блокировка ботов и поиска уязвимостей|Blocks bots and vulnerability scanners'
        'Защита от флуда и перебора путей|Protection against floods and path probing'
        'Защита от подбора паролей на сайте|Protection against website password guessing'
        'Джейл «|Jail «'
        '» не найден или fail2ban не запущен.|» not found or fail2ban is not running.'
        'Забаненных IP нет|No banned IPs'
        'Забанено сейчас|Banned now'
        'Банов всего|Total bans'
        'Ошибок сейчас|Failures now'
        'Ошибок всего|Total failures'
        'Вывод fail2ban-client status|Output of fail2ban-client status'
        'Джейлов активно|Active jails'
        'Служба fail2ban|fail2ban service'
        'Последние события|Recent events'
        'Событий пока нет|No events yet'
        'Восстановлен|Restored'
        'Разбан|Unbanned'
        '>Бан<|>Banned<'
        'Не найден|Not found'
        'Активен|Active'
        'Работает|Running'
        'Остановлена|Stopped'
        '>Джейлы<|>Jails<'
        '>Джейл<|>Jail<'
        '>Время<|>Time<'
        '>Действие<|>Action<'
        '>IP-адрес<|>IP address<'
        'аптайм|uptime'
        'нагрузка|load'
        'н/д|n/a'
    )
    for p in "${pairs[@]}"; do args+=(-e "s|${p%%|*}|${p#*|}|g"); done
    sed -i "${args[@]}" "${DASH_ROOT}/index.html" "${DASH_ROOT}/assets/app.js" "$DASH_GEN"
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
        say "  Fail2ban: \e[1;32mработает\e[0m ($(fail2ban-client status 2>/dev/null | sed -nE 's/.*Jail list:[[:space:]]*//p'))" "  Fail2ban: \e[1;32mrunning\e[0m ($(fail2ban-client status 2>/dev/null | sed -nE 's/.*Jail list:[[:space:]]*//p'))"
    elif command -v fail2ban-client >/dev/null 2>&1; then
        say "  Fail2ban: \e[1;33mустановлен, не запущен\e[0m" "  Fail2ban: \e[1;33minstalled, not running\e[0m"
    else
        say "  Fail2ban: \e[1;33mне установлен\e[0m" "  Fail2ban: \e[1;33mnot installed\e[0m"
    fi
    if [[ -n "$F2B_PATH" ]]; then
        local dash_login
        dash_login=$(cut -d: -f1 "$DASH_HTPASSWD" 2>/dev/null | head -1)
        say "  Дашборд:  \e[1;34mhttps://${MAIN_DOMAIN}/${F2B_PATH}/\e[0m (логин: ${dash_login})" \
            "  Dashboard: \e[1;34mhttps://${MAIN_DOMAIN}/${F2B_PATH}/\e[0m (login: ${dash_login})"
    else
        say "  Дашборд:  \e[1;33mне установлен\e[0m" "  Dashboard: \e[1;33mnot installed\e[0m"
    fi
}

# Дописывает актуальные доступы дашборда в файл сводки (его читает пункт меню [7])
summary_append_dash() {
    {
        echo
        say "Дашборд Fail2ban — обновлено $(date '+%d.%m.%Y %H:%M')" "Fail2ban dashboard — updated $(date '+%d.%m.%Y %H:%M')"
        say "  Ссылка:  https://${MAIN_DOMAIN}/${F2B_PATH}/" "  Link:      https://${MAIN_DOMAIN}/${F2B_PATH}/"
        say "  Логин:   ${DASH_USER}" "  Login:     ${DASH_USER}"
        echo "$(L "  Пароль:  " "  Password:  ")${DASH_PASS}"      # без echo -e: в пароле могут быть обратные слэши
    } >> "$SUMMARY_FILE"
    chmod 600 "$SUMMARY_FILE"
}

f2b_dash_setup() {
    dash_ask_credentials
    f2b_install || msg_wrn "Fail2ban не настроен — дашборд будет без данных." "Fail2ban is not configured — the dashboard will have no data."
    if dash_install; then
        save_state
        apply_nginx
        dash_selftest
        summary_append_dash
        echo
        say "  Дашборд: https://${MAIN_DOMAIN}/${F2B_PATH}/" "  Dashboard: https://${MAIN_DOMAIN}/${F2B_PATH}/"
        say "  Логин:   ${DASH_USER}" "  Login:     ${DASH_USER}"
        echo "$(L "  Пароль:  " "  Password:  ")${DASH_PASS}"      # без echo -e: в пароле могут быть обратные слэши
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
        say "\e[1;36m── Fail2ban и дашборд ──\e[0m" "\e[1;36m── Fail2ban and dashboard ──\e[0m"
        f2b_status
        echo
        say "  [1] Установить / обновить Fail2ban и дашборд" "  [1] Install / update Fail2ban and the dashboard"
        say "  [2] Сменить логин и пароль дашборда" "  [2] Change the dashboard login and password"
        say "  [3] Удалить дашборд (Fail2ban остаётся)" "  [3] Remove the dashboard (Fail2ban stays)"
        say "  [4] Удалить Fail2ban и дашборд" "  [4] Remove Fail2ban and the dashboard"
        say "  [5] Установить / обновить только Fail2ban (без дашборда)" "  [5] Install / update Fail2ban only (no dashboard)"
        say "  [0] Назад" "  [0] Back"
        read -rp "$(L "  Выберите пункт: " "  Choose an item: ")" c
        if [[ $INSTALLED == n && "$c" =~ ^[123]$ ]]; then
            msg_wrn "Дашборду нужна установленная 3x-ui (пункт [1] главного меню)." "The dashboard requires an installed 3x-ui (item [1] of the main menu)."
            msg_inf "Сам Fail2ban можно поставить уже сейчас — пункт [5]." "Fail2ban itself can be installed right now — item [5]."
            continue
        fi
        case "$c" in
            1)  f2b_dash_setup ;;
            5)  f2b_install ;;
            2)  if [[ -z "$F2B_PATH" ]]; then msg_wrn "Дашборд не установлен." "The dashboard is not installed."; continue; fi
                dash_ask_credentials
                if dash_write_htpasswd -B; then
                    dash_selftest
                    summary_append_dash
                    echo "$(L "  Логин: " "  Login: ")${DASH_USER}   $(L "Пароль: " "Password: ")${DASH_PASS}"
                else
                    msg_wrn "Не удалось обновить файл паролей." "Failed to update the password file."
                fi
                DASH_PASS="" ;;
            3)  confirml "Удалить дашборд Fail2ban?" "Remove the Fail2ban dashboard?" n || continue
                dash_remove_files; save_state; apply_nginx
                msg_ok "Дашборд удалён." "Dashboard removed." ;;
            4)  confirml "Удалить Fail2ban вместе с дашбордом?" "Remove Fail2ban together with the dashboard?" n || continue
                if [[ $INSTALLED == y ]]; then dash_remove_files; save_state; apply_nginx; fi
                systemctl stop fail2ban 2>/dev/null
                apt-get purge -y fail2ban >/dev/null 2>&1
                rm -rf /etc/fail2ban
                msg_ok "Fail2ban и дашборд удалены." "Fail2ban and the dashboard removed." ;;
            0)  return ;;
            *)  msg_wrn "Нет такого пункта." "No such item." ;;
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
    msg_wrn "Скрипт рассчитан на Debian 12/13 и Ubuntu 22.04/24.04/26.04, обнаружено: ${id} ${ver}." "The script is designed for Debian 12/13 and Ubuntu 22.04/24.04/26.04, detected: ${id} ${ver}."
    confirml "Продолжить на свой риск?" "Continue at your own risk?" n || return 1
}

collect_install_settings() {
    echo; msg_inf "── Проект ──" "── Project ──"
    # Необязательно: пустое значение оставляет имя подписки по умолчанию
    askl PROJECT_NAME "Название вашего VPN-проекта, видно клиентам в приложении (Enter — пропустить)" "Name of your VPN project, shown to clients in the app (Enter — skip)"

    echo; msg_inf "── Панель 3x-ui ──" "── 3x-ui panel ──"
    while true; do
        askl PANEL_USER "Логин панели" "Panel login"
        [[ "$PANEL_USER" =~ ^[A-Za-z0-9_.-]{3,}$ ]] && break
        msg_wrn "Логин: минимум 3 символа, латиница/цифры/._-" "Login: at least 3 characters, Latin letters/digits/._-"
    done
    PANEL_PASS_GENERATED=n
    while true; do
        read -rsp "$(L "Пароль панели (Enter = сгенерировать): " "Panel password (Enter = generate): ")" PANEL_PASS; echo
        if [[ -z "$PANEL_PASS" ]]; then
            PANEL_PASS=$(gen_random_string 20); PANEL_PASS_GENERATED=y; break
        fi
        local again
        read -rsp "$(L "Повторите пароль: " "Repeat the password: ")" again; echo
        [[ "$PANEL_PASS" == "$again" ]] && break
        msg_wrn "Пароли не совпадают." "Passwords do not match."
    done

    echo; msg_inf "── Домены (A-записи должны указывать на этот сервер) ──" "── Domains (A records must point to this server) ──"
    ask_domain MAIN_DOMAIN "$(L "Основной домен (панель, подписка, сайт-заглушка)" "Main domain (panel, subscription, decoy site)")"
    while true; do
        ask_domain REALITY_DOMAIN "$(L "Резервный домен (SNI/target для Reality)" "Reserve domain (SNI/target for Reality)")"
        [[ "$REALITY_DOMAIN" != "$MAIN_DOMAIN" ]] && break
        msg_wrn "Домены должны различаться." "The domains must be different."
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

    echo; msg_inf "── Подключения (inbounds) ──" "── Connections (inbounds) ──"
    collect_inbounds_loop

    echo; msg_inf "── Защита ──" "── Protection ──"
    # Fail2ban можно поставить с дашбордом, без него или не ставить вовсе
    local f2b_choice
    INSTALL_F2B=n; INSTALL_DASH=n
    echo "  Fail2ban:"
    say "    1) Установить Fail2ban и веб-дашборд статистики" "    1) Install Fail2ban and the statistics web dashboard"
    say "    2) Установить только Fail2ban (без дашборда)" "    2) Install Fail2ban only (no dashboard)"
    say "    3) Не устанавливать" "    3) Do not install"
    while true; do
        askl f2b_choice "  Выбор" "  Choice" "1"
        [[ "$f2b_choice" =~ ^[123]$ ]] && break
        msg_wrn "Введите 1, 2 или 3." "Enter 1, 2 or 3."
    done
    case "$f2b_choice" in
        1) INSTALL_F2B=y; INSTALL_DASH=y; dash_ask_credentials ;;
        2) INSTALL_F2B=y ;;
    esac

    INSTALL_GEOIP=n
    if confirml "Включить защиту GeoIP для админ-панелей?" "Enable GeoIP protection for the admin panels?" n; then
        INSTALL_GEOIP=y
        msg_wrn "Панель и дашборд будут открываться только из ${GEOIP_ALLOW_COUNTRY} и с адресов whitelist." "The panel and dashboard will open only from ${GEOIP_ALLOW_COUNTRY} and whitelisted addresses."
        msg_wrn "VPN-подключения и подписки это не затрагивает — они доступны из любой страны." "VPN connections and subscriptions are not affected — they are reachable from any country."
        whitelist_ask
    fi
}

install_packages() {
    msg_inf "Установка пакетов..." "Installing packages..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y || die "apt-get update не выполнен" "apt-get update failed"
    apt-get install -y curl wget tar jq sqlite3 openssl ca-certificates tzdata ufw \
        nginx-full libnginx-mod-stream certbot psmisc iproute2 \
        || die "Не удалось установить пакеты" "Failed to install packages"
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
            msg_wrn "$d → ${a:-не резолвится}, ожидался $IP4" "$d → ${a:-does not resolve}, expected $IP4"
            bad=y
        fi
    done
    if [[ $bad == y ]]; then
        confirml "DNS не совпадает с IP сервера (за NAT это нормально). Продолжить?" "DNS does not match the server IP (this is normal behind NAT). Continue?" n || die "Отменено." "Cancelled."
    fi
}

# UFW: только SSH, 80, 443. Панель, подписка и inbounds — на loopback за nginx.
# Старые правила сбрасываются (ufw сам делает их бэкап в /etc/ufw).
setup_firewall() {
    msg_inf "Настройка UFW..." "Configuring UFW..."
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
        [[ "$p" != "22" ]] && msg_wrn "SSH слушает нестандартный порт ${p} — он оставлен открытым." "SSH listens on a non-standard port ${p} — it is left open."
    done
    ufw allow 80/tcp  >/dev/null
    ufw allow 443/tcp >/dev/null
    ufw --force enable >/dev/null
    msg_ok "UFW: открыты только SSH(${ssh_ports//$'\n'/,}), 80, 443." "UFW: only SSH(${ssh_ports//$'\n'/,}), 80 and 443 are open."
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
        *) die "Неподдерживаемая архитектура CPU: $(uname -m)" "Unsupported CPU architecture: $(uname -m)" ;;
    esac
}

install_panel() {
    local arch tag url
    arch=$(_arch)

    tag=$(curl -Ls "https://api.github.com/repos/MHSanaei/3x-ui/releases/latest" \
          | grep -m1 '"tag_name":' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')
    [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+ ]] || die "Не удалось получить версию 3x-ui с GitHub." "Failed to get the 3x-ui version from GitHub."

    msg_inf "Установка 3x-ui ${tag} (${arch})..." "Installing 3x-ui ${tag} (${arch})..."
    url="https://github.com/MHSanaei/3x-ui/releases/download/${tag}/x-ui-linux-${arch}.tar.gz"
    wget -q --show-progress -O /tmp/x-ui.tar.gz "$url" || die "Не удалось скачать $url" "Failed to download $url"
    tar -xzf /tmp/x-ui.tar.gz -C /usr/local/ || die "Ошибка распаковки архива" "Archive extraction failed"
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
        msg_wrn "Не удалось скачать x-ui.sh (штатное меню панели), продолжаю без него." "Failed to download x-ui.sh (the stock panel menu), continuing without it."
    fi

    # systemd unit: в новых релизах — x-ui.service.debian, в старых — x-ui.service
    if   [[ -f "$XUI_DIR/x-ui.service.debian" ]]; then cp -f "$XUI_DIR/x-ui.service.debian" /etc/systemd/system/x-ui.service
    elif [[ -f "$XUI_DIR/x-ui.service" ]];        then cp -f "$XUI_DIR/x-ui.service"        /etc/systemd/system/x-ui.service
    else die "В архиве не найден systemd unit x-ui." "systemd unit x-ui not found in the archive."; fi
    systemctl daemon-reload
    systemctl enable x-ui >/dev/null 2>&1
    # Панель запускается только после полной настройки, чтобы ни секунды не слушать 0.0.0.0
}

# set_setting KEY VALUE — запись в таблицу settings (key/value)
set_setting() {
    sqlite3 "$XUIDB" "DELETE FROM settings WHERE key='$1'; INSERT INTO settings (key,value) VALUES ('$1','$(sq "$2")');" \
        || die "Ошибка записи настройки $1" "Failed to write setting $1"
}

configure_panel() {
    msg_inf "Настройка панели..." "Configuring the panel..."
    # Логин/пароль/порт/путь пишем штатным CLI: он создаёт БД и хеширует пароль так,
    # как этого ждёт текущая версия панели. Прямой INSERT пароля в users сломал бы вход.
    "$XUI_DIR/x-ui" setting -username "$PANEL_USER" -password "$PANEL_PASS" \
        -port "$PANEL_PORT" -webBasePath "$PANEL_PATH" >/dev/null \
        || die "x-ui setting завершился с ошибкой" "x-ui setting failed"
    "$XUI_DIR/x-ui" migrate >/dev/null 2>&1 || true
    [[ -f "$XUIDB" ]] || die "База $XUIDB не создана." "Database $XUIDB was not created."

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
    systemctl restart x-ui || die "x-ui не запустился: journalctl -u x-ui -n 50" "x-ui did not start: journalctl -u x-ui -n 50"
    sleep 2
    systemctl is-active --quiet x-ui || die "x-ui не активен: journalctl -u x-ui -n 50" "x-ui is not active: journalctl -u x-ui -n 50"
    msg_ok "x-ui перезапущен." "x-ui restarted."
}

show_results() {
    {
        say "══════════════════════════ Установка завершена ══════════════════════════" "══════════════════════════ Installation complete ══════════════════════════"
        [[ -n "$PROJECT_NAME" ]] && say "Проект: ${PROJECT_NAME}" "Project: ${PROJECT_NAME}"
        echo
        say "┌─ Панель 3x-ui" "┌─ 3x-ui panel"
        say "│  Ссылка:  https://${MAIN_DOMAIN}/${PANEL_PATH}/" "│  Link:      https://${MAIN_DOMAIN}/${PANEL_PATH}/"
        say "│  Логин:   ${PANEL_USER}" "│  Login:     ${PANEL_USER}"
        echo "$(L "│  Пароль:  " "│  Password:  ")${PANEL_PASS}"   # без echo -e: в пароле могут быть обратные слэши
        if [[ -n "$F2B_PATH" ]]; then
            say "├─ Дашборд Fail2ban" "├─ Fail2ban dashboard"
            say "│  Ссылка:  https://${MAIN_DOMAIN}/${F2B_PATH}/" "│  Link:      https://${MAIN_DOMAIN}/${F2B_PATH}/"
            say "│  Логин:   ${DASH_USER}" "│  Login:     ${DASH_USER}"
            echo "$(L "│  Пароль:  " "│  Password:  ")${DASH_PASS}"
        fi
        say "├─ Подписка" "├─ Subscription"
        say "│  Ссылка:  https://${MAIN_DOMAIN}/${SUB_PATH}/<subId>" "│  Link:      https://${MAIN_DOMAIN}/${SUB_PATH}/<subId>"
        echo "│  JSON:    https://${MAIN_DOMAIN}/${JSON_PATH}/<subId>"
        say "└─ Защита" "└─ Protection"
        if [[ $GEOIP_ENABLED == y ]]; then
            say "   GeoIP:    включён — панель и дашборд только из ${GEOIP_ALLOW_COUNTRY} и whitelist" "   GeoIP:    enabled — panel and dashboard only from ${GEOIP_ALLOW_COUNTRY} and the whitelist"
        else
            say "   GeoIP:    выключен" "   GeoIP:    disabled"
        fi
        if command -v fail2ban-client >/dev/null 2>&1 && fail2ban-client ping >/dev/null 2>&1; then
            say "   Fail2ban: работает" "   Fail2ban: running"
        else
            say "   Fail2ban: не установлен" "   Fail2ban: not installed"
        fi
        say "   VPN и подписки доступны из любой страны, наружу открыты только SSH, 80 и 443." "   VPN and subscriptions are reachable from any country; only SSH, 80 and 443 are open."
        echo
        say "Подключения:" "Connections:"
        list_inbounds
        echo
        say "Клиентов добавьте в панели (для VLESS TCP+Reality выберите flow xtls-rprx-vision)." "Add clients in the panel (for VLESS TCP+Reality choose flow xtls-rprx-vision)."
        echo "══════════════════════════════════════════════════════════════════"
    } | tee "$SUMMARY_FILE"
    chmod 600 "$SUMMARY_FILE"
    msg_ok "Сводка сохранена в ${SUMMARY_FILE}" "Summary saved to ${SUMMARY_FILE}"
}

action_install() {
    check_os || return

    if [[ -f "$XUIDB" || -d "$XUI_DIR" ]]; then
        msg_wrn "Обнаружена существующая установка 3x-ui." "An existing 3x-ui installation was detected."
        confirml "УДАЛИТЬ её вместе с базой (все подключения и клиенты будут потеряны) и поставить заново?" "DELETE it together with the database (all connections and clients will be lost) and install again?" n || return
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
    if ! confirml "Начать установку? (доменов: ${#domains[@]}, подключений: ${#P_PORT[@]})" "Start the installation? (domains: ${#domains[@]}, connections: ${#P_PORT[@]})" y; then
        # Отмена: возвращаем к работе прежнюю установку, если она была
        [[ -f "$XUIDB" ]] && systemctl start x-ui 2>/dev/null
        return
    fi

    install_packages
    get_server_ip
    check_dns "${domains[@]}"
    setup_firewall

    msg_inf "Выпуск сертификатов Let's Encrypt..." "Issuing Let's Encrypt certificates..."
    for s in "${domains[@]}"; do
        issue_cert "$s" || die "Не удалось выпустить сертификат для $s (проверьте DNS и порт 80)." "Failed to issue a certificate for $s (check DNS and port 80)."
    done
    setup_renewal_hooks

    # Удаление прежней установки (подтверждено выше), база сохраняется в /root
    systemctl stop x-ui 2>/dev/null || true
    [[ -f "$XUIDB" ]] && cp -a "$XUIDB" "/root/x-ui.db.bak.$(date +%s)" && msg_inf "Бэкап старой базы сохранён в /root/." "A backup of the old database was saved to /root/."
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
        f2b_install || msg_wrn "Fail2ban не настроен." "Fail2ban is not configured."
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

    say "Текущие подключения:" "Current connections:"; list_inbounds; echo
    P_REMARK=(); P_PORT=(); P_PROTO=(); P_NET=(); P_SEC=(); P_SNI=()
    collect_one_inbound

    local sni="${P_SNI[0]}"
    if [[ -n "$sni" ]]; then
        msg_inf "Выпуск сертификата для ${sni} (nginx остановится на несколько секунд)..." "Issuing a certificate for ${sni} (nginx will stop for a few seconds)..."
        if ! issue_cert "$sni"; then
            systemctl start nginx 2>/dev/null || true
            msg_wrn "Не удалось выпустить сертификат для ${sni} (проверьте DNS и порт 80). Подключение не добавлено." "Failed to issue a certificate for ${sni} (check DNS and port 80). The connection was not added."
            return
        fi
    fi

    db_add_inbound "${P_REMARK[0]}" "${P_PORT[0]}" "${P_PROTO[0]}" "${P_NET[0]}" "${P_SEC[0]}" "$sni"
    apply_nginx
    restart_xui
    msg_ok "Готово. Добавьте клиентов в панели: https://${MAIN_DOMAIN}/${PANEL_PATH}/" "Done. Add clients in the panel: https://${MAIN_DOMAIN}/${PANEL_PATH}/"
}

###############################################################################
# [3] ИЗМЕНИТЬ ПОДКЛЮЧЕНИЕ (протокол / транспорт)
###############################################################################
action_modify() {
    require_install || return
    find_xray

    say "Подключения:" "Connections:"; list_inbounds; echo
    local id row old_proto old_stream old_sni old_reality settings sni=""
    askl id "ID подключения для изменения" "ID of the connection to change"
    [[ "$id" =~ ^[0-9]+$ ]] || { msg_wrn "Некорректный ID." "Invalid ID."; return; }
    row=$(inbounds_json | jq -c --argjson id "$id" '.[] | select(.id == $id)')
    [[ -n "$row" ]] || { msg_wrn "Подключение #${id} не найдено." "Connection #${id} not found."; return; }

    old_proto=$(jq -r '.protocol' <<<"$row")
    old_stream=$(jq -r '.stream_settings' <<<"$row")
    old_sni=$(jq -r '.realitySettings.serverNames[0] // .tlsSettings.serverName // empty' <<<"$old_stream" 2>/dev/null)
    old_reality=$(jq -c '.realitySettings // empty' <<<"$old_stream" 2>/dev/null)

    choose_variant

    # Смена протокола делает прежних клиентов недействительными (UUID ≠ пароль Trojan/SS)
    if [[ "$V_PROTO" != "$old_proto" ]]; then
        msg_wrn "Протокол меняется (${old_proto} → ${V_PROTO}): клиенты этого подключения будут удалены." "The protocol changes (${old_proto} → ${V_PROTO}): the clients of this connection will be removed."
        confirml "Продолжить?" "Continue?" n || return
        settings=$(build_settings "$V_PROTO")
    else
        settings=$(jq -r '.settings' <<<"$row")
    fi

    if needs_sni "$V_SEC"; then
        if [[ -n "$old_sni" ]]; then
            sni="$old_sni"                      # домен (и ключи Reality, если они были) остаются прежними
        else
            ask_sni sni
            old_reality=""
            msg_inf "Выпуск сертификата для ${sni} (nginx остановится на несколько секунд)..." "Issuing a certificate for ${sni} (nginx will stop for a few seconds)..."
            if ! issue_cert "$sni"; then
                systemctl start nginx 2>/dev/null || true
                msg_wrn "Не удалось выпустить сертификат для ${sni}. Подключение не изменено." "Failed to issue a certificate for ${sni}. The connection was not changed."
                return
            fi
        fi
    else
        old_reality=""
    fi

    build_stream "$V_NET" "$V_SEC" "$sni" "$old_reality"
    add_external_proxy "$V_SEC" "$sni"

    sqlite3 "$XUIDB" "UPDATE inbounds SET protocol='${V_PROTO}', settings='$(sq "$settings")',
        stream_settings='$(sq "$STREAM_JSON")' WHERE id=${id};" || die "Ошибка обновления подключения #${id}" "Failed to update connection #${id}"
    if [[ "$V_PROTO" != "$old_proto" ]]; then
        sqlite3 "$XUIDB" "DELETE FROM client_traffics WHERE inbound_id=${id};" 2>/dev/null || true
    fi
    set_host "$id" "$V_SEC" "$sni"

    apply_nginx
    restart_xui
    msg_ok "Подключение #${id} изменено: ${V_PROTO}, ${V_NET}, ${V_SEC}. Клиентам нужно обновить подписку." "Connection #${id} changed: ${V_PROTO}, ${V_NET}, ${V_SEC}. Clients need to refresh the subscription."
}

###############################################################################
# [4] ПОЛНОЕ УДАЛЕНИЕ
###############################################################################
action_uninstall() {
    msg_wrn "Будут удалены: 3x-ui с базой (все подключения и клиенты), nginx со всеми конфигами," "Will be removed: 3x-ui with its database (all connections and clients), nginx with all configs,"
    msg_wrn "сайт-заглушка, Fail2ban с дашбордом и GeoIP-защита." "the decoy site, Fail2ban with the dashboard and GeoIP protection."
    confirml "Продолжить удаление?" "Continue the removal?" n || return

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
    if confirml "Удалить также certbot и все сертификаты Let's Encrypt (/etc/letsencrypt)?" "Also remove certbot and all Let's Encrypt certificates (/etc/letsencrypt)?" n; then
        apt-get purge -y certbot >/dev/null 2>&1 || true
        rm -rf /etc/letsencrypt /var/lib/letsencrypt /var/log/letsencrypt
    fi
    if confirml "Сбросить и выключить UFW (сервер останется без фаервола)?" "Reset and disable UFW (the server will be left without a firewall)?" n; then
        ufw --force reset >/dev/null 2>&1 || true
        ufw disable >/dev/null 2>&1 || true
    fi
    apt-get autoremove -y >/dev/null 2>&1 || true
    msg_ok "3x-ui и nginx удалены." "3x-ui and nginx removed."

    if confirml "Удалить и сам скрипт ($0) вместе с командой xpro?" "Remove the script itself ($0) together with the xpro command?" n; then
        rm -f -- "$0" "$XPRO_BIN" "${XPRO_BIN}.bak" "$LANG_FILE"
        msg_ok "Скрипт удалён." "Script removed."
        exit 0
    fi
}

###############################################################################
# ГЛАВНОЕ МЕНЮ
###############################################################################
# ─── Заголовок раздела ───────────────────────────────────────────────────────
section() { echo; echo -e "\e[1;36m── $(L "$@") ──\e[0m"; }

# ─── [1] Показать доступы ────────────────────────────────────────────────────
# Всё читается из базы панели в момент вызова, поэтому видны и подключения,
# и клиенты, созданные позже через веб-панель 3x-ui.

# Строки: email<US>sub_id<US>enable. Новые версии 3x-ui держат клиентов в таблице clients,
# старые — внутри JSON настроек каждого подключения.
clients_rows() {
    if [[ -n "$(sqlite3 "$XUIDB" "SELECT name FROM sqlite_master WHERE type='table' AND name='clients';" 2>/dev/null)" ]]; then
        sqlite3 -separator $'\x1f' "$XUIDB" "SELECT email, sub_id, enable FROM clients ORDER BY id;" 2>/dev/null
    else
        sqlite3 -json "$XUIDB" "SELECT settings FROM inbounds;" 2>/dev/null \
            | jq -r '[.[] | (.settings | fromjson?) | .clients[]?] | unique_by(.email) | .[]
                     | [.email, (.subId // ""), (if .enable == false then 0 else 1 end)] | join("\u001f")'
    fi
}

list_clients() {
    local email sub en n=0 mark
    while IFS=$'\x1f' read -r email sub en; do
        [[ -n "$email" ]] || continue
        n=$((n + 1))
        if [[ "$en" == 0 ]]; then mark="\e[1;31m●\e[0m"; else mark="\e[1;32m●\e[0m"; fi
        echo -e "  ${mark} \e[1m${email}\e[0m"
        [[ -n "$sub" ]] && echo "      https://${MAIN_DOMAIN}/${SUB_PATH}/${sub}"
    done < <(clients_rows)
    if (( n == 0 )); then
        say "  (клиентов пока нет — добавьте их в пункте «Управление пользователями»)" \
            "  (no clients yet — add them under «Manage users»)"
    else
        say "  Зелёная точка — клиент включён, красная — отключён. Всего: ${n}" \
            "  Green dot — client enabled, red — disabled. Total: ${n}"
    fi
}

action_access() {
    load_state 2>/dev/null || { msg_wrn "Установка не найдена." "Installation not found."; return; }

    section "Ссылки" "Links"
    say "  Панель 3x-ui:      \e[1;34mhttps://${MAIN_DOMAIN}/${PANEL_PATH}/\e[0m" \
        "  3x-ui panel:       \e[1;34mhttps://${MAIN_DOMAIN}/${PANEL_PATH}/\e[0m"
    [[ -n "$F2B_PATH" ]] && say "  Дашборд Fail2ban:  \e[1;34mhttps://${MAIN_DOMAIN}/${F2B_PATH}/\e[0m" \
                                "  Fail2ban dashboard: \e[1;34mhttps://${MAIN_DOMAIN}/${F2B_PATH}/\e[0m"
    say "  Подписка клиента:  https://${MAIN_DOMAIN}/${SUB_PATH}/<id клиента>" \
        "  Client subscription: https://${MAIN_DOMAIN}/${SUB_PATH}/<client id>"

    section "Подключения (сейчас в базе панели)" "Connections (currently in the panel database)"
    list_inbounds

    section "Клиенты и их ссылки-подписки" "Clients and their subscription links"
    list_clients

    # Пароли в базе хранятся только в виде хеша, поэтому показать можно лишь те,
    # что были записаны в файл сводки при установке и при смене пароля дашборда.
    section "Логины и пароли (сохранены при установке)" "Logins and passwords (saved at installation)"
    local pat='(Панель 3x-ui|3x-ui panel|Дашборд Fail2ban|Fail2ban dashboard|Логин:|Login:|Пароль:|Password:)'
    if [[ ! -s "$SUMMARY_FILE" ]]; then
        say "  Файл ${SUMMARY_FILE} удалён. Пароль дашборда меняется в настройках, пароль панели — командой x-ui." \
            "  File ${SUMMARY_FILE} was removed. Change the dashboard password in settings, the panel password with the x-ui command."
        return
    fi
    grep -E "$pat" "$SUMMARY_FILE" | sed -E 's/((Пароль|Password):[[:space:]]*).*/\1********/'
    say "  Пароль панели, изменённый потом в самой панели, здесь не обновляется." \
        "  A panel password changed later inside the panel is not updated here."
    echo
    if confirml "Отобразить пароли открытым текстом?" "Show the passwords in plain text?" n; then
        echo
        grep -E "$pat" "$SUMMARY_FILE"
    fi
}

# ─── API панели 3x-ui ────────────────────────────────────────────────────────
# Клиентов добавляем и удаляем только через штатный API панели: она сама обновляет все
# связанные таблицы и конфигурацию Xray. Прямая запись в базу здесь была бы ненадёжной.
API_TOKEN_FILE="${STATE_DIR}/api-token"
API_BODY=""; API_CODE=""

api_new_token() {
    local out tok
    out=$("$XUI_DIR/x-ui" setting -getApiToken -tokenName xpro 2>&1)
    tok=$(sed -nE 's/^apiToken:[[:space:]]*//p' <<<"$out" | tail -1)
    [[ -n "$tok" ]] || return 1
    mkdir -p "$STATE_DIR"
    ( umask 077; echo "$tok" > "$API_TOKEN_FILE" )
}

# api_call МЕТОД ПУТЬ [JSON] → ответ в API_BODY, код HTTP в API_CODE
api_call() {
    local method="$1" path="$2" data="${3:-}" tok raw attempt
    local url="http://127.0.0.1:${PANEL_PORT}/${PANEL_PATH}/panel/api/${path}"
    for attempt in 1 2; do
        if [[ ! -s "$API_TOKEN_FILE" ]]; then api_new_token || return 1; fi
        tok=$(cat "$API_TOKEN_FILE")
        local args=(-s --max-time 20 -w '\n%{http_code}' -X "$method" -H "Authorization: Bearer ${tok}")
        [[ -n "$data" ]] && args+=(-H 'Content-Type: application/json' --data "$data")
        raw=$(curl "${args[@]}" "$url" 2>/dev/null)
        API_CODE="${raw##*$'\n'}"
        API_BODY="${raw%$'\n'*}"
        [[ "$API_CODE" == 401 || "$API_CODE" == 403 ]] || return 0
        # Токен не принят: выпускаем новый и один раз перезапускаем панель, чтобы она его увидела
        rm -f "$API_TOKEN_FILE"
        if (( attempt == 1 )); then
            api_new_token || return 1
            systemctl restart x-ui 2>/dev/null
            sleep 4
        fi
    done
    return 1
}

api_ok() { jq -e '.success == true' <<<"$API_BODY" >/dev/null 2>&1; }

api_error() {
    local m
    m=$(jq -r '.msg // empty' <<<"$API_BODY" 2>/dev/null)
    msg_wrn "Панель отклонила запрос (код ${API_CODE:-нет ответа}): ${m:-без пояснения}" \
            "The panel rejected the request (code ${API_CODE:-no response}): ${m:-no details}"
    say "  Это же действие можно выполнить в веб-панели: https://${MAIN_DOMAIN}/${PANEL_PATH}/" \
        "  The same action can be done in the web panel: https://${MAIN_DOMAIN}/${PANEL_PATH}/"
}

# ─── [2] Управление пользователями ───────────────────────────────────────────
user_add() {
    local email ids days gb all_ids payload sub exp=0 total=0
    while true; do
        askl email "Имя клиента (латиница, цифры, . _ -)" "Client name (Latin letters, digits, . _ -)"
        [[ "$email" =~ ^[A-Za-z0-9._-]{1,40}$ ]] && break
        msg_wrn "Допустимы латинские буквы, цифры и . _ - (до 40 символов)." "Latin letters, digits and . _ - are allowed (up to 40 characters)."
    done

    section "Подключения" "Connections"
    list_inbounds
    all_ids=$(all_inbounds_json | jq -r '[.[].id] | join(",")')
    [[ -n "$all_ids" ]] || { msg_wrn "Сначала создайте хотя бы одно подключение." "Create at least one connection first."; return; }
    while true; do
        askl ids "ID подключений через запятую (Enter — все)" "Connection IDs, comma-separated (Enter — all)" "$all_ids"
        ids="${ids// /}"
        [[ "$ids" =~ ^[0-9]+(,[0-9]+)*$ ]] && break
        msg_wrn "Пример: 1,3" "Example: 1,3"
    done
    while true; do
        askl days "Срок действия в днях (0 — бессрочно)" "Validity in days (0 — unlimited)" "0"
        [[ "$days" =~ ^[0-9]+$ ]] && break
    done
    while true; do
        askl gb "Лимит трафика в ГБ (0 — без лимита)" "Traffic limit in GB (0 — unlimited)" "0"
        [[ "$gb" =~ ^[0-9]+$ ]] && break
    done
    (( days > 0 )) && exp=$(( ( $(date +%s) + days * 86400 ) * 1000 ))
    (( gb > 0 ))   && total=$(( gb * 1073741824 ))
    sub=$(gen_random_string 16 | tr 'A-Z' 'a-z')

    payload=$(jq -cn --arg id "$(cat /proc/sys/kernel/random/uuid)" --arg email "$email" --arg sub "$sub" \
        --arg pw "$(openssl rand -base64 32)" --arg ids "$ids" --argjson exp "$exp" --argjson total "$total" '{
            client: {id:$id, email:$email, enable:true, subId:$sub, password:$pw, security:"auto", flow:"",
                     limitIp:0, totalGB:$total, expiryTime:$exp, tgId:0, comment:"", reset:0},
            inboundIds: [$ids | split(",")[] | tonumber]}')

    msg_inf "Добавляю клиента..." "Adding the client..."
    if api_call POST "clients/add" "$payload" && api_ok; then
        msg_ok "Клиент ${email} добавлен." "Client ${email} added."
        say "  Ссылка-подписка: \e[1;34mhttps://${MAIN_DOMAIN}/${SUB_PATH}/${sub}\e[0m" \
            "  Subscription link: \e[1;34mhttps://${MAIN_DOMAIN}/${SUB_PATH}/${sub}\e[0m"
        say "  Для VLESS TCP+Reality при желании включите flow xtls-rprx-vision в панели." \
            "  For VLESS TCP+Reality you may enable flow xtls-rprx-vision in the panel."
    else
        api_error
    fi
}

user_del() {
    local email
    askl email "Имя клиента для удаления" "Name of the client to remove"
    [[ "$email" =~ ^[A-Za-z0-9._@-]{1,64}$ ]] || { msg_wrn "Некорректное имя." "Invalid name."; return; }
    if ! clients_rows | cut -d$'\x1f' -f1 | grep -xF "$email" >/dev/null; then
        msg_wrn "Клиента ${email} нет в базе." "Client ${email} is not in the database."; return
    fi
    confirml "Удалить клиента ${email}? Его ссылка-подписка перестанет работать." \
             "Remove client ${email}? Their subscription link will stop working." n || return
    if api_call POST "clients/del/${email}" && api_ok; then
        msg_ok "Клиент ${email} удалён." "Client ${email} removed."
    else
        api_error
    fi
}

action_users() {
    load_state 2>/dev/null || return
    local c
    while true; do
        section "Пользователи" "Users"
        list_clients
        echo
        say "  [1] Добавить клиента" "  [1] Add a client"
        say "  [2] Удалить клиента"  "  [2] Remove a client"
        say "  [0] Назад" "  [0] Back"
        read -rp "$(L "  Выберите пункт: " "  Choose an item: ")" c
        case "$c" in
            1) user_add ;;
            2) user_del ;;
            0) return ;;
            *) msg_wrn "Нет такого пункта." "No such item." ;;
        esac
    done
}

# ─── [3] Настройки сервера ───────────────────────────────────────────────────
# Смена секретных путей. Внутренние порты не меняются: они слушают только 127.0.0.1
# и снаружи не видны, поэтому менять их незачем.
action_paths() {
    local c new
    while true; do
        section "Секретные пути" "Secret paths"
        say "  Панель:   /${PANEL_PATH}/" "  Panel:        /${PANEL_PATH}/"
        [[ -n "$F2B_PATH" ]] && say "  Дашборд:  /${F2B_PATH}/" "  Dashboard:    /${F2B_PATH}/"
        say "  Подписка: /${SUB_PATH}/" "  Subscription: /${SUB_PATH}/"
        echo
        say "  [1] Сменить путь панели" "  [1] Change the panel path"
        say "  [2] Сменить путь дашборда" "  [2] Change the dashboard path"
        say "  [3] Сменить путь подписки (ссылки ВСЕХ клиентов изменятся)" \
            "  [3] Change the subscription path (links of ALL clients will change)"
        say "  [0] Назад" "  [0] Back"
        read -rp "$(L "  Выберите пункт: " "  Choose an item: ")" c
        case "$c" in
            1)  new=$(gen_random_string 14)
                if "$XUI_DIR/x-ui" setting -webBasePath "$new" >/dev/null 2>&1; then
                    PANEL_PATH="$new"; save_state; rm -f "$API_TOKEN_FILE"
                    apply_nginx; restart_xui
                    msg_ok "Новый адрес панели: https://${MAIN_DOMAIN}/${PANEL_PATH}/" "New panel address: https://${MAIN_DOMAIN}/${PANEL_PATH}/"
                else
                    msg_wrn "Панель не приняла новый путь." "The panel rejected the new path."
                fi ;;
            2)  if [[ -z "$F2B_PATH" ]]; then msg_wrn "Дашборд не установлен." "The dashboard is not installed."; continue; fi
                F2B_PATH=$(gen_random_string 12); save_state; apply_nginx
                msg_ok "Новый адрес дашборда: https://${MAIN_DOMAIN}/${F2B_PATH}/" "New dashboard address: https://${MAIN_DOMAIN}/${F2B_PATH}/" ;;
            3)  msg_wrn "Старые ссылки-подписки перестанут работать у всех клиентов." "The old subscription links will stop working for all clients."
                confirml "Точно сменить путь подписки?" "Really change the subscription path?" n || continue
                SUB_PATH=$(gen_random_string 12)
                set_setting subPath "/${SUB_PATH}/"
                set_setting subURI  "https://${MAIN_DOMAIN}/${SUB_PATH}/"
                save_state; apply_nginx; restart_xui
                msg_ok "Новая основа ссылок: https://${MAIN_DOMAIN}/${SUB_PATH}/<id клиента>" "New link base: https://${MAIN_DOMAIN}/${SUB_PATH}/<client id>" ;;
            0)  return ;;
            *)  msg_wrn "Нет такого пункта." "No such item." ;;
        esac
    done
}

action_settings() {
    local c
    [[ $INSTALLED == y ]] && { load_state 2>/dev/null; }
    while true; do
        section "Настройки сервера" "Server settings"
        if [[ $INSTALLED == y ]]; then
            say "  [1] Добавить подключение (inbound)" "  [1] Add a connection (inbound)"
            say "  [2] Изменить подключение (протокол / транспорт)" "  [2] Change a connection (protocol / transport)"
            say "  [3] Сменить сайт-заглушку (другой случайный шаблон)" "  [3] Change the decoy site (another random template)"
            say "  [4] Сменить секретные пути (панель, дашборд, подписка)" "  [4] Change secret paths (panel, dashboard, subscription)"
        fi
        say "  [5] Fail2ban и дашборд" "  [5] Fail2ban and the dashboard"
        say "  [6] GeoIP и whitelist" "  [6] GeoIP and whitelist"
        echo "  [7] Язык / Language"
        [[ $INSTALLED == y ]] && say "  [8] Переустановить 3x-ui с нуля (база будет удалена)" "  [8] Reinstall 3x-ui from scratch (the database will be deleted)"
        say "  \e[1;31m[9]\e[0m Полное удаление всего" "  \e[1;31m[9]\e[0m Full removal of everything"
        say "  [0] Назад" "  [0] Back"
        read -rp "$(L "  Выберите пункт: " "  Choose an item: ")" c
        if [[ $INSTALLED == n && "$c" =~ ^[12348]$ ]]; then
            msg_wrn "Сначала установите 3x-ui (пункт [1] главного меню)." "Install 3x-ui first (item [1] of the main menu)."
            continue
        fi
        case "$c" in
            1) action_add;    pause ;;
            2) action_modify; pause ;;
            3) install_fake_site; pause ;;
            4) action_paths ;;
            5) action_f2b ;;
            6) action_geoip ;;
            7) choose_lang ;;
            8) action_install; pause; return ;;
            9) action_uninstall; pause; return ;;
            0) return ;;
            *) msg_wrn "Нет такого пункта." "No such item." ;;
        esac
    done
}

# ─── [4] Статус служб ────────────────────────────────────────────────────────
svc_line() {      # ИМЯ_СЛУЖБЫ ПОДПИСЬ
    local st
    # Без конвейера с grep -q: при включённом pipefail он обрывал systemctl и давал ложное «не установлена»
    if [[ -z "$(systemctl list-unit-files "$1.service" --no-legend 2>/dev/null)" ]]; then
        st="\e[1;33m$(L "не установлена" "not installed")\e[0m"
    elif systemctl is-active --quiet "$1"; then
        st="\e[1;32m$(L "работает" "running")\e[0m"
    else
        st="\e[1;31m$(L "остановлена" "stopped")\e[0m"
    fi
    echo -e "  $(printf '%-10s' "$2") ${st}"
}

action_status() {
    section "Службы" "Services"
    svc_line nginx    "Nginx"
    svc_line x-ui     "3x-ui"
    svc_line fail2ban "Fail2ban"
    if command -v ufw >/dev/null 2>&1 && [[ "$(ufw status 2>/dev/null)" == *"Status: active"* ]]; then
        echo -e "  $(printf '%-10s' "UFW") \e[1;32m$(L "включён" "active")\e[0m"
    else
        echo -e "  $(printf '%-10s' "UFW") \e[1;31m$(L "выключен" "inactive")\e[0m"
    fi

    section "Версии" "Versions"
    echo "  xpro:   ${XPRO_VERSION}"
    [[ -x "$XUI_DIR/x-ui" ]] && echo "  3x-ui:  $("$XUI_DIR/x-ui" -v 2>/dev/null | head -1)"
    command -v nginx >/dev/null 2>&1 && echo "  nginx:  $(nginx -v 2>&1 | sed 's/^nginx version: //')"

    # Наружу должны смотреть только SSH, 80 и 443 — всё остальное на 127.0.0.1
    section "Порты, открытые наружу" "Ports listening on external interfaces"
    ss -Hltn 2>/dev/null | awk '$4 !~ /^(127\.|\[::1\])/ {n=split($4,a,":"); print a[n]}' | sort -un | paste -sd' ' | sed 's/^/  /'

    section "Сертификаты" "Certificates"
    local d end
    for d in /etc/letsencrypt/live/*/; do
        [[ -f "${d}fullchain.pem" ]] || continue
        end=$(openssl x509 -in "${d}fullchain.pem" -noout -enddate 2>/dev/null | cut -d= -f2)
        echo "  $(basename "$d") — $(L "до" "until") ${end}"
    done

    if command -v fail2ban-client >/dev/null 2>&1 && fail2ban-client ping >/dev/null 2>&1; then
        section "Fail2ban: забанено сейчас" "Fail2ban: currently banned"
        local j
        for j in $(fail2ban-client status 2>/dev/null | sed -nE 's/.*Jail list:[[:space:]]*//p' | tr -d ' ' | tr ',' ' '); do
            echo "  ${j}: $(fail2ban-client status "$j" 2>/dev/null | sed -nE 's/.*Currently banned:[[:space:]]*//p')"
        done
    fi
}

# ─── [5] Обновления ──────────────────────────────────────────────────────────
# Ни одно из обновлений не трогает базу /etc/x-ui/x-ui.db, конфигурацию Nginx,
# настройки Fail2ban и сертификаты: меняются только программы.

update_system() {
    confirml "Обновить пакеты системы (apt upgrade)? Настроенные конфиги сохраняются." \
             "Upgrade system packages (apt upgrade)? Existing config files are kept." y || return
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y || { msg_wrn "apt-get update не выполнен." "apt-get update failed."; return; }
    # --force-confold: при обновлении пакета остаётся наш конфиг (nginx.conf, jail.local и т.д.)
    if apt-get -y -o Dpkg::Options::=--force-confold -o Dpkg::Options::=--force-confdef upgrade; then
        msg_ok "Пакеты системы обновлены." "System packages upgraded."
        [[ -f /var/run/reboot-required ]] && msg_wrn "Для завершения обновления нужна перезагрузка сервера." "A server reboot is required to finish the upgrade."
    else
        msg_wrn "Обновление пакетов завершилось с ошибкой." "Package upgrade failed."
    fi
}

# Обновление самой панели: заменяются только программы в /usr/local/x-ui, база остаётся на месте
update_panel() {
    [[ -f "$XUIDB" ]] || { msg_wrn "3x-ui не установлена." "3x-ui is not installed."; return; }
    say "  Сейчас: $("$XUI_DIR/x-ui" -v 2>/dev/null | head -1)" "  Current: $("$XUI_DIR/x-ui" -v 2>/dev/null | head -1)"
    confirml "Обновить 3x-ui до последней версии? VPN прервётся примерно на минуту, клиенты и настройки сохраняются." \
             "Update 3x-ui to the latest version? VPN will be interrupted for about a minute; clients and settings are kept." n || return

    cp -a "$XUIDB" "/root/x-ui.db.bak.$(date +%s)"
    msg_inf "Копия базы сохранена в /root/." "A copy of the database was saved to /root/."
    systemctl stop x-ui 2>/dev/null
    # В подоболочке: если загрузка сорвётся, die завершит только её, а старая панель останется целой
    if ( install_panel ); then
        "$XUI_DIR/x-ui" migrate >/dev/null 2>&1 || true
        restart_xui
        msg_ok "3x-ui обновлена: $("$XUI_DIR/x-ui" -v 2>/dev/null | head -1)" "3x-ui updated: $("$XUI_DIR/x-ui" -v 2>/dev/null | head -1)"
    else
        systemctl start x-ui 2>/dev/null
        msg_wrn "Обновление не удалось — запущена прежняя версия панели." "The update failed — the previous panel version was started."
    fi
}

action_updates() {
    local c
    while true; do
        section "Обновления" "Updates"
        say "  Данные не затрагиваются: база 3x-ui, конфиги Nginx и Fail2ban, сертификаты остаются как есть." \
            "  Your data is not touched: the 3x-ui database, Nginx and Fail2ban configs and certificates stay as they are."
        echo
        if [[ -n "$UPDATE_VERSION" ]]; then
            say "  \e[1;33m[1]\e[0m Обновить скрипт xpro до ${UPDATE_VERSION} (сейчас ${XPRO_VERSION})" \
                "  \e[1;33m[1]\e[0m Update the xpro script to ${UPDATE_VERSION} (current ${XPRO_VERSION})"
        else
            say "  [1] Проверить обновление скрипта xpro (сейчас ${XPRO_VERSION})" "  [1] Check for an xpro script update (current ${XPRO_VERSION})"
        fi
        say "  [2] Обновить пакеты системы" "  [2] Upgrade system packages"
        say "  [3] Обновить панель 3x-ui" "  [3] Update the 3x-ui panel"
        say "  [4] Обновить базу GeoIP" "  [4] Update the GeoIP database"
        say "  [0] Назад" "  [0] Back"
        read -rp "$(L "  Выберите пункт: " "  Choose an item: ")" c
        case "$c" in
            1) action_update ;;
            2) update_system ;;
            3) update_panel ;;
            4) geoip_download_db || msg_wrn "Не удалось скачать базу." "Failed to download the database." ;;
            0) return ;;
            *) msg_wrn "Нет такого пункта." "No such item." ;;
        esac
    done
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

box_right() {     # $1 — текст (прижат к правому краю), $2 — ANSI-стиль текста
    local t="$1" l
    l=$(( BOX_W - ${#t} - 2 ))
    printf '\e[1;36m║\e[0m%*s\e[%sm%s\e[0m  \e[1;36m║\e[0m\n' "$l" '' "${2:-0}" "$t"
}

show_menu() {
    local status
    if systemctl is-active --quiet x-ui 2>/dev/null; then
        status=$(L "работает" "running")
    elif [[ -f "$XUIDB" ]]; then
        status=$(L "установлен, остановлен" "installed, stopped")
    else
        status=$(L "не установлен" "not installed")
    fi

    clear 2>/dev/null || true
    box_border "╔" "╗"
    box_line ""
    box_line "xpro v${XPRO_VERSION} — Secure VPN Deploy" "1;37"
    box_line "3x-ui · Nginx SNI · Reality · Fail2ban · GeoIP · 443" "0;36"
    box_right "by sheijuro" "2;37"
    box_border "╚" "╝"
    # Сообщение об установке команды xpro показываем один раз (clear стирает вывод до меню)
    if [[ -n "$XPRO_NOTE" ]]; then
        echo -e "  \e[1;32m${XPRO_NOTE}\e[0m"
        XPRO_NOTE=""
    fi
    say "  Состояние 3x-ui: \e[1;33m${status}\e[0m" "  3x-ui status: \e[1;33m${status}\e[0m"
    if load_state 2>/dev/null; then
        say "  Панель:  \e[1;34mhttps://${MAIN_DOMAIN}/${PANEL_PATH}/\e[0m" "  Panel:     \e[1;34mhttps://${MAIN_DOMAIN}/${PANEL_PATH}/\e[0m"
        [[ -n "$F2B_PATH" ]] && say "  Дашборд: \e[1;34mhttps://${MAIN_DOMAIN}/${F2B_PATH}/\e[0m" "  Dashboard: \e[1;34mhttps://${MAIN_DOMAIN}/${F2B_PATH}/\e[0m"
        [[ $GEOIP_ENABLED == y ]] && say "  GeoIP:   \e[1;32mвключён\e[0m (панель и дашборд — только ${GEOIP_ALLOW_COUNTRY} и whitelist)" "  GeoIP:     \e[1;32menabled\e[0m (panel and dashboard — only ${GEOIP_ALLOW_COUNTRY} and the whitelist)"
    fi
    echo
    # Пункты про саму панель без установленной 3x-ui не показываем: вместо них — установка.
    INSTALLED=n
    [[ -f "$STATE_FILE" && -f "$XUIDB" ]] && INSTALLED=y

    if [[ $INSTALLED == y ]]; then
        say "  \e[1;32m[1]\e[0m 🔐 Показать доступы (ссылки, подключения, клиенты)" \
            "  \e[1;32m[1]\e[0m 🔐 Show access details (links, connections, clients)"
        say "  \e[1;32m[2]\e[0m 👥 Управление пользователями (добавить / удалить клиента)" \
            "  \e[1;32m[2]\e[0m 👥 Manage users (add / remove a client)"
    else
        say "  \e[1;32m[1]\e[0m 🚀 Установить 3x-ui с нуля (Nginx, SSL, UFW, БД)" \
            "  \e[1;32m[1]\e[0m 🚀 Install 3x-ui from scratch (Nginx, SSL, UFW, DB)"
    fi
    say "  \e[1;32m[3]\e[0m 🛠  Настройки сервера (подключения, заглушка, пути, защита, язык)" \
        "  \e[1;32m[3]\e[0m 🛠  Server settings (connections, decoy site, paths, protection, language)"
    say "  \e[1;32m[4]\e[0m 📊 Статус служб (Nginx, 3x-ui, Fail2ban)" \
        "  \e[1;32m[4]\e[0m 📊 Service status (Nginx, 3x-ui, Fail2ban)"
    if [[ -n "$UPDATE_VERSION" ]]; then
        say "  \e[1;33m[5]\e[0m 🔄 Обновить систему и скрипт — доступна версия \e[1;33m${UPDATE_VERSION}\e[0m" \
            "  \e[1;33m[5]\e[0m 🔄 Update the system and script — version \e[1;33m${UPDATE_VERSION}\e[0m is available"
    else
        say "  \e[1;32m[5]\e[0m 🔄 Обновить систему и скрипт" "  \e[1;32m[5]\e[0m 🔄 Update the system and script"
    fi
    say "  \e[1;37m[0]\e[0m 🚪 Выход" "  \e[1;37m[0]\e[0m 🚪 Exit"
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

    # Не откатываем: если команда xpro уже новее запущенного файла (обновилась через меню), оставляем её
    local binver
    binver=$(grep -m1 -oP '^XPRO_VERSION="\K[0-9]+\.[0-9]+\.[0-9]+' "$XPRO_BIN" 2>/dev/null)
    if [[ -n "$binver" && "$binver" != "$XPRO_VERSION" \
          && "$(printf '%s\n' "$XPRO_VERSION" "$binver" | sort -V | tail -1)" == "$binver" ]]; then
        return 0
    fi

    local what
    what=$(L "установлена" "installed")
    [[ -f "$XPRO_BIN" ]] && what=$(L "обновлена" "updated")
    if install -m 755 "$self" "$XPRO_BIN"; then
        XPRO_NOTE=$(L "Команда xpro ${what}: теперь меню можно вызывать из любого места — sudo xpro" \
                      "The xpro command is ${what}: the menu can now be opened from anywhere — sudo xpro")
        msg_ok "$XPRO_NOTE"
    else
        msg_wrn "Не удалось скопировать скрипт в ${XPRO_BIN}." "Failed to copy the script to ${XPRO_BIN}."
    fi
}

# ─── Обновление скрипта ──────────────────────────────────────────────────────
# При запуске скрипт сверяет свою версию с той, что лежит в репозитории, и только сообщает
# о новой. Сама замена файла — отдельным пунктом меню и только после подтверждения.
XPRO_UPDATE_URL="https://raw.githubusercontent.com/sheijuro/xpro-deploy/main/xpro.sh"
UPDATE_VERSION=""          # номер новой версии, если она есть

# xpro_fetch КУДА [ТАЙМАУТ] [head] — скачать скрипт из репозитория ("-" = в stdout).
# С третьим аргументом "head" запрашиваются только первые 8 КБ файла: номер версии стоит
# в самом начале, а качать весь скрипт ради одной строки на медленном канале незачем.
xpro_fetch() {
    local out="$1" t="${2:-5}" part="${3:-}"
    if command -v curl >/dev/null 2>&1; then
        local args=(-fsSL --max-time "$t" -o "$out")
        [[ -n "$part" ]] && args+=(-r 0-8191)
        curl "${args[@]}" "$XPRO_UPDATE_URL" 2>/dev/null
    else
        local args=(-q -T "$t" -t 1 -O "$out")
        [[ -n "$part" ]] && args+=(--header="Range: bytes=0-8191")
        wget "${args[@]}" "$XPRO_UPDATE_URL" 2>/dev/null
    fi
}

# check_update [ТАЙМАУТ] — код возврата: 0 — проверка выполнена, 1 — репозиторий не ответил.
# При сбое сети уже найденная ранее версия не забывается.
check_update() {
    local head remote
    head=$(xpro_fetch - "${1:-5}" head)
    remote=$(grep -m1 -oP '^XPRO_VERSION="\K[0-9]+\.[0-9]+\.[0-9]+' <<<"$head")
    [[ -n "$remote" ]] || return 1
    UPDATE_VERSION=""
    # Новее ли версия в репозитории, чем текущая
    if [[ "$remote" != "$XPRO_VERSION" \
          && "$(printf '%s\n' "$XPRO_VERSION" "$remote" | sort -V | tail -1)" == "$remote" ]]; then
        UPDATE_VERSION="$remote"
    fi
    return 0
}

action_update() {
    # Если новая версия уже найдена при запуске, повторно сеть не дёргаем
    if [[ -z "$UPDATE_VERSION" ]]; then
        msg_inf "Проверка обновлений..." "Checking for updates..."
        if ! check_update 20; then
            msg_wrn "Репозиторий не ответил — попробуйте ещё раз позже." \
                    "The repository did not respond — try again later."
            return
        fi
    fi
    if [[ -z "$UPDATE_VERSION" ]]; then
        msg_ok "Установлена последняя версия (${XPRO_VERSION})." "You have the latest version (${XPRO_VERSION})."
        return
    fi
    msg_inf "Доступна версия ${UPDATE_VERSION} (у вас ${XPRO_VERSION})." \
            "Version ${UPDATE_VERSION} is available (you have ${XPRO_VERSION})."
    confirml "Обновить скрипт? Установленная 3x-ui и её настройки не затрагиваются." \
             "Update the script? The installed 3x-ui and its settings are not affected." y || return

    local tmp
    tmp=$(mktemp)
    if ! xpro_fetch "$tmp" 120; then
        rm -f "$tmp"
        msg_wrn "Не удалось скачать новую версию." "Failed to download the new version."; return
    fi
    # Не заменяем рабочий скрипт чем попало: это должен быть наш bash-скрипт без синтаксических ошибок
    if [[ "$(head -c 11 "$tmp")" != '#!/bin/bash' ]] || ! grep -q '^XPRO_VERSION=' "$tmp" || ! bash -n "$tmp" 2>/dev/null; then
        rm -f "$tmp"
        msg_wrn "Скачанный файл не прошёл проверку — обновление отменено." \
                "The downloaded file failed validation — update cancelled."; return
    fi
    [[ -f "$XPRO_BIN" ]] && cp -a "$XPRO_BIN" "${XPRO_BIN}.bak"
    install -m 755 "$tmp" "$XPRO_BIN"
    rm -f "$tmp"
    msg_ok "Скрипт обновлён до ${UPDATE_VERSION}. Прежняя версия сохранена в ${XPRO_BIN}.bak. Перезапуск..." \
           "The script was updated to ${UPDATE_VERSION}. The previous version is kept in ${XPRO_BIN}.bak. Restarting..."
    sleep 1
    exec "$XPRO_BIN"
}

main_menu() {
    local choice
    while true; do
        show_menu
        read -rp "$(L "  Выберите пункт: " "  Choose an item: ")" choice
        echo
        case "$choice" in
            1) if [[ $INSTALLED == y ]]; then action_access; else action_install; fi; pause ;;
            2) if [[ $INSTALLED == y ]]; then action_users; else msg_wrn "Нет такого пункта." "No such item."; sleep 1; fi ;;
            3) action_settings ;;
            4) action_status;    pause ;;
            5) action_updates ;;
            0) exit 0 ;;
            *) msg_wrn "Нет такого пункта." "No such item."; sleep 1 ;;
        esac
    done
}

load_lang || choose_lang       # язык спрашивается один раз, при первом запуске
install_xpro
check_update                   # только проверка: о новой версии сообщит строка [9] в меню
main_menu
