#!/usr/bin/env bash
set -Eeuo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[1;36m'
NC='\033[0m'

DOMAIN="${1:-}"
PROJECT_DIR="/opt/myfakesite"
NGINX_CONF="/etc/nginx/sites-available/myfakesite-proxy.conf"

run_step() {
    local start=$1
    local end=$2
    local name=$3
    local cmd=$4

    # Печатаем первую строку и оставляем курсор на ней
    printf "[ %3d%% ] %s\n" "$start" "$name"

    eval "$cmd" > /tmp/myfakesite_task.log 2>&1 &
    local pid=$!
    local p=$start

    while kill -0 $pid 2>/dev/null; do
        if [ $p -lt $end ]; then
            p=$((p + 1))
            # Поднимаем курсор на 1 строку вверх, очищаем её и печатаем новые проценты
            printf "\033[1A\033[2K[ %3d%% ] %s\n" "$p" "$name"
        fi
        sleep 0.1
    done

    wait $pid
    local exit_code=$?

    if [ $exit_code -eq 0 ]; then
        # Поднимаем курсор, очищаем, ставим финальные проценты и галочку
        printf "\033[1A\033[2K[ %3d%% ] %s ${GREEN}[ ✓ ]${NC}\n" "$end" "$name"
    else
        printf "\033[1A\033[2K[ FAIL ] %s ${RED}[ ✗ ]${NC}\n" "$name"
        echo -e "${RED}Лог ошибки:${NC}"
        tail -n 15 /tmp/myfakesite_task.log
        exit 1
    fi
}

echo -e "${CYAN}--- Установка защиты MyFakeSite ---${NC}"

echo -ne "[   0% ] Проверка домена и сертификатов...\n"
sleep 0.5
if [[ -n "$DOMAIN" ]]; then
    if [[ ! -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]]; then
        echo -e "\n${RED}ОШИБКА: Сертификат Let's Encrypt для $DOMAIN не найден.${NC}"
        exit 1
    fi
    CERT_PATH="/etc/letsencrypt/live/$DOMAIN"
    SERVER_NAME="$DOMAIN"
else
    mkdir -p /etc/nginx/ssl
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout /etc/nginx/ssl/myfakesite.key \
      -out /etc/nginx/ssl/myfakesite.crt \
      -subj "/CN=$(curl -s ifconfig.me || echo 'localhost')" >/dev/null 2>&1
    CERT_PATH="/etc/nginx/ssl"
    SERVER_NAME="_"
fi
printf "\033[1A\033[2K[   5%% ] %s ${GREEN}[ ✓ ]${NC}\n" "Проверка домена и сертификатов"

run_step 5 25 "Проверка и установка Docker (без ubuntu-fan)" '
    if ! command -v docker >/dev/null 2>&1; then
        apt-get update >/dev/null 2>&1
        apt-get install -y --no-install-recommends docker.io docker-compose-v2 >/dev/null 2>&1
        if dpkg -l ubuntu-fan 2>/dev/null | grep -q "^ii"; then
            apt-get remove -y ubuntu-fan >/dev/null 2>&1 || true
        fi
        rm -f /etc/dnsmasq.d/ubuntu-fan
        systemctl enable --now docker >/dev/null 2>&1
    fi
'

run_step 25 45 "Скачивание конфигурации MyFakeSite" '
    rm -rf "'"$PROJECT_DIR"'"
    git clone --quiet https://github.com/iqubik/myfakesite.git "'"$PROJECT_DIR"'"
    mkdir -p /var/log/myfakesite /var/www/acme-challenge
    cd "'"$PROJECT_DIR"'"
    cp docker-compose.yml docker-compose.yml.bak
    sed -i "s/- \"80:80\"/- \"127.0.0.1:8080:80\"/g" docker-compose.yml
    sed -i "s/- \"443:443\"/- \"127.0.0.1:8443:443\"/g" docker-compose.yml
    
    if [[ -n "'"$DOMAIN"'" ]]; then
        sed -i "s|/etc/letsencrypt/live/YOUDOMEN.XXX/fullchain.pem|'"$CERT_PATH"'/fullchain.pem|g" docker-compose.yml
        sed -i "s|/etc/letsencrypt/live/YOUDOMEN.XXX/privkey.pem|'"$CERT_PATH"'/privkey.pem|g" docker-compose.yml
    else
        sed -i "s|/etc/letsencrypt/live/YOUDOMEN.XXX/fullchain.pem|'"$CERT_PATH"'/myfakesite.crt|g" docker-compose.yml
        sed -i "s|/etc/letsencrypt/live/YOUDOMEN.XXX/privkey.pem|'"$CERT_PATH"'/myfakesite.key|g" docker-compose.yml
    fi
'

run_step 45 85 "Запуск контейнеров MyFakeSite (скачивание образов)" '
    cd "'"$PROJECT_DIR"'"
    docker compose up -d
'

echo -ne "[  85% ] Настройка Nginx (проксирование)...\n"
sleep 0.5
if [[ -n "$DOMAIN" ]]; then
    SSL_CERT="$CERT_PATH/fullchain.pem"
    SSL_KEY="$CERT_PATH/privkey.pem"
else
    SSL_CERT="$CERT_PATH/myfakesite.crt"
    SSL_KEY="$CERT_PATH/myfakesite.key"
fi

cat > "$NGINX_CONF" <<NGINX
server {
    listen 80;
    listen [::]:80;
    server_name $SERVER_NAME;
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/html;
        default_type text/plain;
    }
    location / { return 301 https://\$host\$request_uri; }
}
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name $SERVER_NAME;
    ssl_certificate $SSL_CERT;
    ssl_certificate_key $SSL_KEY;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:SGAWGPlaceholder:10m;
    location / {
        proxy_pass https://127.0.0.1:8443;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_ssl_verify off; 
    }
}
NGINX

rm -f /etc/nginx/sites-enabled/sg-awg-placeholder.conf*
rm -f /etc/nginx/sites-enabled/default
ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/
printf "\033[1A\033[2K[  90%% ] %s ${GREEN}[ ✓ ]${NC}\n" "Настройка Nginx (проксирование)"

echo -ne "[  90% ] Проверка конфигурации Nginx...\n"
if ! nginx -t >/tmp/nginx_test.log 2>&1; then
    echo -e "${RED}ОШИБКА Nginx!${NC}"
    cat /tmp/nginx_test.log
    exit 1
fi
systemctl reload nginx
printf "\033[1A\033[2K[  99%% ] %s ${GREEN}[ ✓ ]${NC}\n" "Проверка конфигурации Nginx"

echo -e "\n${GREEN}=========================================${NC}"
echo -e "${GREEN}[ 100%] ✅ MyFakeSite успешно установлен!${NC}"
echo -e "${GREEN}=========================================${NC}"
