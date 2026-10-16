from __future__ import annotations

import configparser
import ipaddress
import re
from dataclasses import dataclass
from io import StringIO


MAX_OUTBOUND_CONFIG_SIZE = 64 * 1024
MAX_OUTBOUND_PROFILES = 32
OUTBOUND_INTERFACE_PREFIX = "sgo"
OUTBOUND_TABLE_BASE = 21000
OUTBOUND_MARK_BASE = 0x5100
OUTBOUND_RULE_PRIORITY_BASE = 12100

_NAME_RE = re.compile(r"^[A-Za-z0-9А-Яа-яЁё_. -]{1,64}$")
_KEY_RE = re.compile(r"^[A-Za-z0-9+/=_-]{20,128}$")
_HOST_RE = re.compile(r"^\[[0-9A-Fa-f:]+\]|[A-Za-z0-9.-]+$")
_FORBIDDEN_INTERFACE_KEYS = {
    "preup",
    "postup",
    "predown",
    "postdown",
    "saveconfig",
}


@dataclass(frozen=True)
class ParsedOutboundConfig:
    config_text: str
    endpoint: str
    address: str
    allowed_ips: str


def normalize_outbound_name(value: object) -> str:
    name = str(value or "").strip()
    if not _NAME_RE.fullmatch(name):
        raise ValueError("Имя outbound должно содержать от 1 до 64 обычных символов")
    return name


def interface_name_for(outbound_id: int) -> str:
    if outbound_id <= 0:
        raise ValueError("Некорректный идентификатор outbound")
    value = f"{OUTBOUND_INTERFACE_PREFIX}{outbound_id}"
    if len(value) > 15:
        raise ValueError("Слишком большой идентификатор outbound")
    return value


def traffic_table_for(outbound_id: int) -> int:
    return OUTBOUND_TABLE_BASE + int(outbound_id)


def fwmark_for(outbound_id: int) -> int:
    return OUTBOUND_MARK_BASE + int(outbound_id)


def rule_priority_for(outbound_id: int) -> int:
    return OUTBOUND_RULE_PRIORITY_BASE + int(outbound_id)


def _casefolded_items(items: dict[str, str], section: str) -> tuple[dict[str, str], dict[str, str]]:
    lowered: dict[str, str] = {}
    original_names: dict[str, str] = {}
    for original_name, raw_value in items.items():
        key = original_name.lower()
        if key in lowered:
            raise ValueError(f"В секции [{section}] параметр {original_name} указан повторно")
        value = raw_value.strip()
        if "\r" in value or "\n" in value or "\x00" in value:
            raise ValueError(f"Параметр {original_name} должен занимать одну строку")
        lowered[key] = value
        original_names[key] = original_name
    return lowered, original_names


def _normalize_integer(value: str, field: str, minimum: int, maximum: int) -> str:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} outbound должен быть целым числом") from exc
    if not minimum <= number <= maximum:
        raise ValueError(f"{field} outbound должен быть от {minimum} до {maximum}")
    return str(number)


def _normalize_header(value: str, field: str) -> str:
    match = re.fullmatch(r"(\d+)(?:-(\d+))?", value)
    if not match:
        raise ValueError(f"{field} outbound должен быть числом или диапазоном start-end")
    start = int(match.group(1))
    end = int(match.group(2) or start)
    if not 0 <= start <= end <= 4_294_967_295:
        raise ValueError(f"{field} outbound должен находиться в пределах uint32")
    return f"{start}-{end}" if start != end else str(start)


def _normalize_signature(value: str, field: str) -> str:
    if len(value) > 4096:
        raise ValueError(f"{field} outbound слишком длинный")
    if "\r" in value or "\n" in value or "\x00" in value:
        raise ValueError(f"{field} outbound должен занимать одну строку")
    return value


def _parse_endpoint(value: str) -> str:
    endpoint = value.strip()
    if not endpoint or len(endpoint) > 260:
        raise ValueError("В outbound-конфигурации отсутствует корректный Endpoint")
    host = endpoint
    port_text = ""
    if endpoint.startswith("["):
        match = re.fullmatch(r"(\[[0-9A-Fa-f:]+\]):([0-9]{1,5})", endpoint)
        if match:
            host, port_text = match.groups()
    else:
        host, sep, port_text = endpoint.rpartition(":")
        if not sep:
            host = ""
    if not host or not _HOST_RE.fullmatch(host):
        raise ValueError("Endpoint outbound должен быть доменом или IP с портом")
    port = int(port_text or "0")
    if not 1 <= port <= 65535:
        raise ValueError("Порт Endpoint outbound должен быть от 1 до 65535")
    return endpoint


def _normalize_ipv4_interface(value: str) -> str:
    raw = value.split(",", 1)[0].strip()
    try:
        interface = ipaddress.ip_interface(raw)
    except ValueError as exc:
        raise ValueError("Address outbound должен быть корректным IPv4-адресом с префиксом") from exc
    if interface.version != 4:
        raise ValueError("IPv6 outbound пока не поддерживается")
    return str(interface)


def _normalize_allowed_ips(value: str) -> str:
    parts = [part.strip() for part in value.split(",") if part.strip()]
    if not parts:
        raise ValueError("В outbound-конфигурации отсутствует AllowedIPs")
    networks: list[ipaddress.IPv4Network] = []
    for part in parts:
        try:
            network = ipaddress.ip_network(part, strict=False)
        except ValueError as exc:
            raise ValueError(f"Некорректный AllowedIPs outbound: {part}") from exc
        if network.version != 4:
            # SG-AWG client profiles deliberately include ::/0 so official
            # AmneziaVPN recognizes a full tunnel. The outbound runtime is
            # currently IPv4-only, therefore the harmless IPv6 default route
            # is accepted on import and omitted from the normalized profile.
            if str(network) == "::/0":
                continue
            raise ValueError("IPv6-маршруты outbound пока не поддерживаются")
        networks.append(network)
    collapsed = list(ipaddress.collapse_addresses(networks))
    if ipaddress.ip_network("0.0.0.0/0") not in collapsed:
        raise ValueError("Outbound должен содержать AllowedIPs = 0.0.0.0/0")
    return ", ".join(str(network) for network in collapsed)


def parse_amneziawg_outbound_config(value: object) -> ParsedOutboundConfig:
    raw = str(value or "").replace("\r\n", "\n").strip()
    if not raw:
        raise ValueError("Вставьте конфигурацию AmneziaWG outbound")
    if len(raw.encode("utf-8")) > MAX_OUTBOUND_CONFIG_SIZE:
        raise ValueError("Outbound-конфигурация слишком большая")

    parser = configparser.RawConfigParser(
        interpolation=None,
        strict=True,
        delimiters=("=",),
        comment_prefixes=("#", ";"),
        inline_comment_prefixes=None,
    )
    parser.optionxform = str
    try:
        parser.read_file(StringIO(raw))
    except (configparser.Error, UnicodeError) as exc:
        raise ValueError("Не удалось разобрать outbound-конфигурацию") from exc

    sections = parser.sections()
    interface_sections = [section for section in sections if section.lower() == "interface"]
    peer_sections = [section for section in sections if section.lower() == "peer"]
    if len(interface_sections) != 1 or len(peer_sections) != 1 or len(sections) != 2:
        raise ValueError("Поддерживается конфигурация с одним [Interface] и одним [Peer]")

    interface = dict(parser.items(interface_sections[0]))
    peer = dict(parser.items(peer_sections[0]))
    lower_interface, original_interface_names = _casefolded_items(interface, "Interface")
    lower_peer, _original_peer_names = _casefolded_items(peer, "Peer")

    forbidden = sorted(_FORBIDDEN_INTERFACE_KEYS.intersection(lower_interface))
    if forbidden:
        raise ValueError(
            "Outbound-конфигурация не должна содержать команды: " + ", ".join(forbidden)
        )

    private_key = lower_interface.get("privatekey", "")
    public_key = lower_peer.get("publickey", "")
    if not _KEY_RE.fullmatch(private_key) or not _KEY_RE.fullmatch(public_key):
        raise ValueError("В outbound-конфигурации отсутствуют корректные ключи")

    address = _normalize_ipv4_interface(lower_interface.get("address", ""))
    endpoint = _parse_endpoint(lower_peer.get("endpoint", ""))
    allowed_ips = _normalize_allowed_ips(lower_peer.get("allowedips", ""))

    output: list[str] = ["[Interface]", f"Address = {address}", f"PrivateKey = {private_key}", "Table = off"]
    normalized_optional: dict[str, str] = {}
    integer_ranges = {
        "listenport": (1, 65535),
        "mtu": (576, 1500),
        "jc": (0, 10),
        "jmin": (64, 1024),
        "jmax": (64, 1024),
        "s1": (0, 64),
        "s2": (0, 64),
        "s3": (0, 64),
        "s4": (0, 32),
    }
    for key, (minimum, maximum) in integer_ranges.items():
        if key in lower_interface and lower_interface[key]:
            normalized_optional[key] = _normalize_integer(
                lower_interface[key], original_interface_names[key], minimum, maximum
            )
    if "jmin" in normalized_optional and "jmax" in normalized_optional:
        if int(normalized_optional["jmin"]) >= int(normalized_optional["jmax"]):
            raise ValueError("Для outbound должно выполняться Jmin < Jmax")
    for key in ("h1", "h2", "h3", "h4"):
        if key in lower_interface and lower_interface[key]:
            normalized_optional[key] = _normalize_header(
                lower_interface[key], original_interface_names[key]
            )
    for key in ("i1", "i2", "i3", "i4", "i5"):
        if key in lower_interface and lower_interface[key]:
            normalized_optional[key] = _normalize_signature(
                lower_interface[key], original_interface_names[key]
            )

    preferred_interface_keys = (
        "listenport", "mtu", "jc", "jmin", "jmax", "s1", "s2", "s3", "s4",
        "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5",
    )
    for key in preferred_interface_keys:
        if key in normalized_optional:
            output.append(f"{original_interface_names[key]} = {normalized_optional[key]}")

    output.extend(["", "[Peer]", f"PublicKey = {public_key}"])
    if lower_peer.get("presharedkey"):
        if not _KEY_RE.fullmatch(lower_peer["presharedkey"]):
            raise ValueError("Некорректный PresharedKey outbound")
        output.append(f"PresharedKey = {lower_peer['presharedkey']}")
    output.extend([f"AllowedIPs = {allowed_ips}", f"Endpoint = {endpoint}"])
    if lower_peer.get("persistentkeepalive"):
        try:
            keepalive = int(lower_peer["persistentkeepalive"])
        except ValueError as exc:
            raise ValueError("Некорректный PersistentKeepalive outbound") from exc
        if not 0 <= keepalive <= 65535:
            raise ValueError("Некорректный PersistentKeepalive outbound")
        output.append(f"PersistentKeepalive = {keepalive}")

    return ParsedOutboundConfig(
        config_text="\n".join(output).rstrip() + "\n",
        endpoint=endpoint,
        address=address,
        allowed_ips=allowed_ips,
    )


def render_nftables_script(
    *,
    inbound_interface: str,
    server_network: str,
    blocked_addresses: list[str],
    marked_clients: list[tuple[str, int, str]],
    outbound_interfaces: list[str],
    policy_declarations: list[str] | tuple[str, ...] = (),
    policy_classification: list[str] | tuple[str, ...] = (),
    policy_guards: list[str] | tuple[str, ...] = (),
    dns_redirect: bool = False,
    dns_server_address: str | None = None,
    dns_block_dot: bool = False,
    block_smtp: bool = False,
    block_private_networks: bool = False,
    block_metadata: bool = False,
    isolate_clients: bool = False,
    block_mark: int = 0x5FFF,
) -> str:
    """Render the complete atomic nftables ruleset for client egress.

    Ordered policy rules run first. Per-client текущий сервер/Block/Outbound settings are
    fallbacks only, so a more specific policy rule can override a client's
    default route. Both policy and fallback decisions are stored in conntrack
    marks, which keeps both directions of an established flow consistent.
    """
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", inbound_interface):
        raise ValueError("Некорректное имя входящего AWG-интерфейса")
    network = ipaddress.ip_network(server_network, strict=True)
    if network.version != 4:
        raise ValueError("IPv6 traffic пока не поддерживается")
    if not 1 <= int(block_mark) <= 0xFFFFFFFF:
        raise ValueError("Некорректная block mark")

    blocked: list[str] = []
    for value in blocked_addresses:
        address = ipaddress.ip_interface(value).ip
        if address not in network:
            raise ValueError("IP заблокированного клиента не входит в сеть AWG")
        blocked.append(str(address))

    marked: list[tuple[str, int, str]] = []
    for value, mark, outbound_interface in marked_clients:
        address = ipaddress.ip_interface(value).ip
        if address not in network:
            raise ValueError("IP клиента outbound не входит в сеть AWG")
        if not 1 <= int(mark) <= 0xFFFFFFFF:
            raise ValueError("Некорректная traffic mark")
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", outbound_interface):
            raise ValueError("Некорректное имя outbound-интерфейса")
        marked.append((str(address), int(mark), outbound_interface))

    interfaces: list[str] = []
    for value in outbound_interfaces:
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", value):
            raise ValueError("Некорректное имя outbound-интерфейса")
        if value not in interfaces:
            interfaces.append(value)

    lines = ["table inet sg_awg_traffic {"]
    lines.extend(str(item) for item in policy_declarations)
    lines.extend(
        [
            "  chain pretraffic {",
            "    type filter hook prerouting priority -150; policy accept;",
            "    ct mark != 0 meta mark set ct mark",
            "    ct state established,related return",
        ]
    )

    # First matching policy rule returns from the base chain. Only packets not
    # matched above reach the per-client fallback decisions below.
    lines.extend(str(item) for item in policy_classification)
    for address in blocked:
        lines.append(
            f'    iifname "{inbound_interface}" ip saddr {address} '
            f'meta mark set 0x{int(block_mark):x} ct mark set meta mark'
        )
    for address, mark, _outbound_interface in marked:
        lines.append(
            f'    iifname "{inbound_interface}" ip saddr {address} '
            f'meta mark set 0x{mark:x} ct mark set meta mark'
        )
    lines.extend(
        [
            "  }",
            "  chain forward_guard {",
            "    type filter hook forward priority -50; policy accept;",
        ]
    )

    # These are explicit, testable restrictions for traffic arriving from AWG clients.
    # They do not claim protocol detection or content inspection.
    if block_metadata:
        lines.append(
            f'    iifname "{inbound_interface}" ip daddr 169.254.169.254 reject'
        )
    if block_private_networks:
        lines.append(
            f'    iifname "{inbound_interface}" ip daddr {{ '
            '0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, '
            '169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, '
            '192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/4, 240.0.0.0/4 } reject'
        )
    if isolate_clients:
        lines.append(
            f'    iifname "{inbound_interface}" ip daddr {network} reject'
        )
    if block_smtp:
        lines.append(f'    iifname "{inbound_interface}" tcp dport 25 reject')

    # Policy kill-switch guards, followed by fallback guards. Guarding by mark
    # (rather than by client address) is what allows ordered rules to override
    # the client's default route without opening an accidental текущий сервер fallback.
    lines.extend(str(item) for item in policy_guards)
    lines.append(
        f'    iifname "{inbound_interface}" meta mark 0x{int(block_mark):x} drop'
    )
    seen_guard_marks: set[int] = set()
    for _address, mark, outbound_interface in marked:
        if mark in seen_guard_marks:
            continue
        seen_guard_marks.add(mark)
        lines.append(
            f'    iifname "{inbound_interface}" meta mark 0x{mark:x} '
            f'oifname != "{outbound_interface}" drop'
        )
    if dns_block_dot:
        lines.append(f'    iifname "{inbound_interface}" tcp dport 853 reject')
        lines.append(f'    iifname "{inbound_interface}" udp dport 853 reject')
    lines.extend(["  }"])

    if dns_redirect:
        dns_target = dns_server_address or str(next(network.hosts()))
        lines.extend(
            [
                "  chain dns_redirect {",
                "    type nat hook prerouting priority dstnat; policy accept;",
                f'    iifname "{inbound_interface}" udp dport 53 dnat ip to {dns_target}:53',
                f'    iifname "{inbound_interface}" tcp dport 53 dnat ip to {dns_target}:53',
                "  }",
            ]
        )

    lines.extend(["}", "table ip sg_awg_traffic_nat {", "  chain posttraffic {"])
    lines.append("    type nat hook postrouting priority srcnat; policy accept;")
    for interface in interfaces:
        lines.append(f'    ip saddr {network} oifname "{interface}" masquerade')
    lines.extend(["  }", "}"])
    return "\n".join(lines) + "\n"
