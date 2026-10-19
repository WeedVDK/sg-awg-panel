#!/usr/bin/env bash
set -Eeuo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

DOMAIN="${1:-}"
PROJECT_DIR="/opt/myfakesite"
NGINX_CONF="/etc/nginx/sites-available/myfakesite-proxy.conf"

if ! command -v docker >/dev/null 2>&1; then
    echo -e "${YELLOW}Docker не найден. Устанавливаем...${NC}"
    apt-get update && apt-get install -y --no-install-recommends docker.io docker-compose-v2
        if dpkg -l ubuntu-fan 2>/dev/null | grep -q "^ii"; then
            apt-get remove -y ubuntu-fan 2>/dev/null || true
        fi
        rm -f /etc/dnsmasq.d/ubuntu-fan
    systemctl enable --now docker
fi

echo -e "${GREEN}Скачиваем MyFakeSite...${NC}"
rm -rf "$PROJECT_DIR"
git clone --quiet https://github.com/iqubik/myfakesite.git "$PROJECT_DIR"
cd "$PROJECT_DIR"
cp docker-compose.yml docker-compose.yml.bak

mkdir -p /var/log/myfakesite /var/www/acme-challenge

if [[ -n "$DOMAIN" ]]; then
    echo -e "${GREEN}Настраиваем домен: $DOMAIN${NC}"
    if [[ ! -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]]; then
        echo -e "${RED}ОШИБКА: Сертификат Let's Encrypt для $DOMAIN не найден.${NC}"
        exit 1
    fi
    CERT_PATH="/etc/letsencrypt/live/$DOMAIN"
    SERVER_NAME="$DOMAIN"
else
    echo -e "${YELLOW}Генерируем самоподписанный сертификат (без домена).${NC}"
    mkdir -p /etc/nginx/ssl
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout /etc/nginx/ssl/myfakesite.key \
      -out /etc/nginx/ssl/myfakesite.crt \
      -subj "/CN=$(curl -s ifconfig.me || echo 'localhost')"
    CERT_PATH="/etc/nginx/ssl"
    SERVER_NAME="_"
fi

sed -i 's/- "80:80"/- "127.0.0.1:8080:80"/g' docker-compose.yml
sed -i 's/- "443:443"/- "127.0.0.1:8443:443"/g' docker-compose.yml

if [[ -n "$DOMAIN" ]]; then
    sed -i "s|/etc/letsencrypt/live/YOUDOMEN.XXX/fullchain.pem|$CERT_PATH/fullchain.pem|g" docker-compose.yml
    sed -i "s|/etc/letsencrypt/live/YOUDOMEN.XXX/privkey.pem|$CERT_PATH/privkey.pem|g" docker-compose.yml
    SSL_CERT="$CERT_PATH/fullchain.pem"
    SSL_KEY="$CERT_PATH/privkey.pem"
else
    sed -i "s|/etc/letsencrypt/live/YOUDOMEN.XXX/fullchain.pem|$CERT_PATH/myfakesite.crt|g" docker-compose.yml
    sed -i "s|/etc/letsencrypt/live/YOUDOMEN.XXX/privkey.pem|$CERT_PATH/myfakesite.key|g" docker-compose.yml
    SSL_CERT="$CERT_PATH/myfakesite.crt"
    SSL_KEY="$CERT_PATH/myfakesite.key"
fi

echo -e "${GREEN}Запускаем контейнеры MyFakeSite...${NC}"
docker compose up -d

echo -e "${GREEN}Настраиваем Nginx...${NC}"
cat > "$NGINX_CONF" <<NGINX
server {
    listen 80;
    listen [::]:80;
    server_name $SERVER_NAME;

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/html;
        default_type text/plain;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
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

# ИСПРАВЛЕНИЕ ОШИБКИ С ЗАГЛУШКОЙ
rm -f /etc/nginx/sites-enabled/sg-awg-placeholder.conf*
rm -f /etc/nginx/sites-enabled/default

ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/

if nginx -t; then
    systemctl reload nginx
    echo -e "${GREEN}✅ MyFakeSite успешно установлен!${NC}"
else
    echo -e "${RED}❌ Ошибка в конфигурации Nginx.${NC}"
    exit 1
fi
