#!/usr/bin/env bash
set -euo pipefail

for iface in sgo1 awg0; do
    # Проверяем, существует ли интерфейс. Если нет (например, sgo1 на изолированном сервере) - пропускаем.
    if ! ip link show "$iface" >/dev/null 2>&1; then
        continue
    fi

    iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -o "$iface" -j TCPMSS --set-mss 1240 2>/dev/null || \
        iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -o "$iface" -j TCPMSS --set-mss 1240 2>/dev/null || true
        
    iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -i "$iface" -j TCPMSS --set-mss 1240 2>/dev/null || \
        iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -i "$iface" -j TCPMSS --set-mss 1240 2>/dev/null || true
done
