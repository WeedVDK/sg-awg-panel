#!/usr/bin/env bash
set -uo pipefail

LOG_TAG="sg-cascade-fix"
LOCKFILE="/run/sg-cascade-fix.lock"

exec 9>"$LOCKFILE"
if ! flock -n 9; then
    exit 0
fi

IFACE_IN="awg0"
IFACE_OUT="sgo1"
CLIENT_NET="10.77.0.0/24"
DNSMASQ_IP="10.77.0.1"
TABLE=21001
RULE_PRIO=100
DNS_RULE_PRIO=50

log() { logger -t "$LOG_TAG" "$@"; }

# 1. src_valid_mark
if [ "$(sysctl -n net.ipv4.conf.all.src_valid_mark)" != "1" ]; then
    sysctl -w net.ipv4.conf.all.src_valid_mark=1 >/dev/null && log "set src_valid_mark=1"
fi

# 2. ip rule source-based для клиентской подсети
if ! ip rule show | grep -qE "^${RULE_PRIO}:\s+from ${CLIENT_NET} lookup ${TABLE}"; then
    ip rule add from "$CLIENT_NET" lookup "$TABLE" priority "$RULE_PRIO" && \
        log "added ip rule from ${CLIENT_NET} lookup ${TABLE} prio ${RULE_PRIO}"
fi

# 3. ip rule для dnsmasq
if ! ip rule show | grep -qE "^${DNS_RULE_PRIO}:\s+from ${DNSMASQ_IP} lookup main"; then
    ip rule add from "$DNSMASQ_IP" lookup main priority "$DNS_RULE_PRIO" && \
        log "added ip rule from ${DNSMASQ_IP} lookup main prio ${DNS_RULE_PRIO}"
fi

# 4. route client net in table
if ! ip route show table "$TABLE" | grep -q "${CLIENT_NET} dev ${IFACE_IN}"; then
    ip route add "$CLIENT_NET" dev "$IFACE_IN" table "$TABLE" 2>/dev/null && \
        log "added route ${CLIENT_NET} dev ${IFACE_IN} table ${TABLE}"
fi

# 5. default route in table
if ! ip route show table "$TABLE" | grep -q "default dev ${IFACE_OUT}"; then
    ip route add default dev "${IFACE_OUT}" table "$TABLE" 2>/dev/null && \
        log "restored default dev ${IFACE_OUT} in table ${TABLE}"
fi

# 6. INPUT accept для DNS на awg0 (UDP)
if ! iptables -C INPUT -i "$IFACE_IN" -p udp --dport 53 -j ACCEPT 2>/dev/null; then
    iptables -I INPUT 1 -i "$IFACE_IN" -p udp --dport 53 -j ACCEPT && \
        log "added INPUT accept for DNS UDP on ${IFACE_IN}"
fi

# 7. INPUT accept для DNS на awg0 (TCP)
if ! iptables -C INPUT -i "$IFACE_IN" -p tcp --dport 53 -j ACCEPT 2>/dev/null; then
    iptables -I INPUT 1 -i "$IFACE_IN" -p tcp --dport 53 -j ACCEPT && \
        log "added INPUT accept for DNS TCP on ${IFACE_IN}"
fi
