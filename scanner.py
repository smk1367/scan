#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Multi-city SNMP + RouterOS API + SSH scanner.

Supported vendors:
- MikroTik
- Mimosa C5 / C5c
- RACOM RAy2
- RACOM RAy3

Important:
- MikroTik behavior is preserved.
- Mimosa behavior is preserved.
- RACOM is SNMP-first.
- RouterOS API is plain TCP/8728 only.
- API-SSL/8729 remains disabled.
- Empty / invalid SNMP values never overwrite valid values.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import subprocess
import time
from typing import Any

import paramiko
import database as db

from database import (
    add_scan_result,
    cleanup_retention,
    create_scan,
    finish_scan,
    get_device,
    init_db,
    is_blacklisted,
    list_cities,
    list_manual_ips,
    record_changes,
    upsert_device,
)

from routeros_api import RouterOSAPI, collect_mikrotik_api


try:
    from pysnmp.hlapi.v1arch.asyncio import (
        SnmpDispatcher,
        CommunityData,
        UdpTransportTarget,
        get_cmd,
    )
except Exception:
    SnmpDispatcher = None
    CommunityData = None
    UdpTransportTarget = None
    get_cmd = None


LOG = logging.getLogger(__name__)


# =============================================================================
# STANDARD OIDS
# =============================================================================

STANDARD_OIDS = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysObjectID": "1.3.6.1.2.1.1.2.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "hrProcessorLoad": "1.3.6.1.2.1.25.3.3.1.2.1",
    "memTotalReal": "1.3.6.1.4.1.2021.4.5.0",
    "memAvailReal": "1.3.6.1.4.1.2021.4.6.0",
    "mtTemperature": "1.3.6.1.4.1.14988.1.1.3.10.0",
    "mtCpuTemperature": "1.3.6.1.4.1.14988.1.1.3.11.0",
}


IF_OIDS = {
    "name": "1.3.6.1.2.1.31.1.1.1.1",
    "descr": "1.3.6.1.2.1.2.2.1.2",
    "oper": "1.3.6.1.2.1.2.2.1.8",
    "admin": "1.3.6.1.2.1.2.2.1.7",
    "in_octets": "1.3.6.1.2.1.31.1.1.1.6",
    "out_octets": "1.3.6.1.2.1.31.1.1.1.10",
    "in_errors": "1.3.6.1.2.1.2.2.1.14",
    "out_errors": "1.3.6.1.2.1.2.2.1.20",
}


# =============================================================================
# MIMOSA
# =============================================================================

MIMOSA_ROOT = "1.3.6.1.4.1.43356.2.1.2"
MIMOSA_GENERAL_ROOT = "1.3.6.1.4.1.43356.2.1.2.1"
MIMOSA_LOC_ROOT = "1.3.6.1.4.1.43356.2.1.2.2"
MIMOSA_WAN_ROOT = "1.3.6.1.4.1.43356.2.1.2.3"
MIMOSA_RF_ROOT = "1.3.6.1.4.1.43356.2.1.2.6"
MIMOSA_CHAIN_ROOT = "1.3.6.1.4.1.43356.2.1.2.6.1.1"
MIMOSA_STREAM_ROOT = "1.3.6.1.4.1.43356.2.1.2.6.2.1"
MIMOSA_PERF_ROOT = "1.3.6.1.4.1.43356.2.1.2.7"


# =============================================================================
# RACOM
#
# IMPORTANT:
#   RAy2 root = 1.3.6.1.4.1.33555.1
#   RAy3 root = 1.3.6.1.4.1.33555.4
#
# All suffixes below are RELATIVE to that root.
#
# Correct:
#   RAy3 productName = .33555.4.1.1.1.0
# NOT:
#   .33555.4.1.1.1.1.0
#
# =============================================================================

RACOM_ENTERPRISE = "1.3.6.1.4.1.33555"

RACOM_RAY2_ROOT = "1.3.6.1.4.1.33555.1"
RACOM_RAY3_ROOT = "1.3.6.1.4.1.33555.4"


# station/product
RACOM_PRODUCT_NAME = ".1.1.1"
RACOM_SERIAL_NUMBER = ".1.1.2"
RACOM_UNIT_TYPE = ".1.1.3"

# station/info
RACOM_DEVICE_NAME = ".1.2.1"
RACOM_SW_VERSION = ".1.2.2"
RACOM_SW_RADIO_VERSION = ".1.2.3"

# station/status
RACOM_SYSTEM_STATUS = ".1.3.1"
RACOM_LINE_STATUS = ".1.3.2"
RACOM_PEER_NUMBER = ".1.3.3"
RACOM_RF_POWER_STATUS = ".1.3.4"
RACOM_LINE_STATUS_II = ".1.3.8"
RACOM_ETH1_LINK = ".1.3.9"
RACOM_ETH2_LINK = ".1.3.10"

# station/chassis
RACOM_TEMP_MODEM = ".1.4.1"
RACOM_TEMP_RADIO = ".1.4.2"
RACOM_VOLTAGE_UNIT = ".1.4.3"

# interface/radio
RACOM_RX_CHANNEL = ".2.1.1"
RACOM_TX_CHANNEL = ".2.1.2"
RACOM_RX_FREQ = ".2.1.3"
RACOM_TX_FREQ = ".2.1.4"
RACOM_RX_MODULATION = ".2.1.5"
RACOM_TX_MODULATION = ".2.1.6"
RACOM_RX_MODULATION_INDEX = ".2.1.7"
RACOM_TX_MODULATION_INDEX = ".2.1.8"
RACOM_BANDWIDTH = ".2.1.9"
RACOM_CHANNEL_CODING = ".2.1.10"
RACOM_MATCHING = ".2.1.11"
RACOM_RF_POWER_CONFIGURED = ".2.1.12"
RACOM_NET_BITRATE = ".2.1.13"
RACOM_MAX_NET_BITRATE = ".2.1.14"
RACOM_BANDWIDTH_KHZ = ".2.1.15"
RACOM_CHANNEL_ARRANGEMENT = ".2.1.16"
RACOM_RF_POWER_CURRENT = ".2.1.17"
RACOM_FREQUENCY_TABLE = ".2.1.20"
RACOM_RX_BANDWIDTH_KHZ = ".2.1.21"

# statistic/radio
RACOM_RSS = ".3.2.1"
RACOM_SNR = ".3.2.2"
RACOM_TIME_ALL_CONNECT = ".3.2.5"
RACOM_TIME_ALL_DISCONNECT = ".3.2.6"
RACOM_TIME_MAX_DISCONNECT = ".3.2.7"
RACOM_NUM_DISCONNECT = ".3.2.8"
RACOM_RELIABILITY = ".3.2.9"
RACOM_LINK_UPTIME = ".3.2.10"
RACOM_BER = ".3.2.11"
RACOM_MSE = ".3.2.12"

# statistic/ethernet
RACOM_ETH_IN_THROUGHPUT = ".3.3.1"
RACOM_ETH_OUT_THROUGHPUT = ".3.3.2"
RACOM_ETH2_IN_THROUGHPUT = ".3.3.3"
RACOM_ETH2_OUT_THROUGHPUT = ".3.3.4"


# =============================================================================
# BASIC HELPERS
# =============================================================================

def s(v: Any) -> str:
    return "" if v is None else str(v).strip()


def numeric_value(raw: Any) -> float | None:
    text = s(raw)

    if not text:
        return None

    m = re.search(
        r"[-+]?(?:\d+(?:\.\d*)?|\.\d+)",
        text,
    )

    if not m:
        return None

    try:
        return float(m.group(0))
    except Exception:
        return None


def avg_values(values: list[float]) -> float | None:
    values = [
        x
        for x in values
        if x is not None
    ]

    if not values:
        return None

    return sum(values) / len(values)


def normdbm(v: Any) -> str:
    text = s(v)

    if not text:
        return ""

    m = re.search(
        r"-?\d+(?:\.\d+)?",
        text,
    )

    return (
        f"{m.group(0)} dBm"
        if m
        else text
    )


def parse_key_value_lines(
    text: str,
) -> dict[str, str]:

    out = {}

    for line in text.replace(
        "\r",
        "",
    ).splitlines():

        m = re.match(
            r"^\s*([A-Za-z][A-Za-z0-9_.-]*)\s*:\s*(.*?)\s*$",
            line,
        )

        if m:
            out[
                m.group(1).lower()
            ] = m.group(2).strip()

    return out


def parse_equal_lines(
    text: str,
) -> dict[str, str]:

    out = {}

    for line in text.replace(
        "\r",
        "",
    ).splitlines():

        for m in re.finditer(
            r'([A-Za-z][A-Za-z0-9_.-]*)\s*=\s*(?:"([^"]*)"|([^\s]+))',
            line,
        ):

            out[
                m.group(1).lower()
            ] = (
                m.group(2)
                if m.group(2) is not None
                else m.group(3)
            )

    return out


def merge_nonempty(
    dst: dict[str, Any],
    src: dict[str, Any] | None,
    preserve: set[str] | None = None,
) -> dict[str, Any]:

    if not src:
        return dst

    preserve = set(
        preserve or ()
    )

    for key, value in src.items():

        if value is None:
            continue

        if isinstance(
            value,
            str,
        ):
            meaningful = bool(
                value.strip()
            )

        elif isinstance(
            value,
            (list, dict),
        ):
            meaningful = bool(
                value
            )

        else:
            meaningful = True

        if not meaningful:
            continue

        if (
            key in preserve
            or not s(
                dst.get(key)
            )
        ):
            dst[key] = value

    return dst


# =============================================================================
# MIMOSA DECIMAL HELPERS
# =============================================================================

def _mimosa_raw_number(
    raw: Any,
) -> float | None:

    text = s(raw)

    if not text:
        return None

    m = re.search(
        r"[-+]?(?:\d+(?:\.\d*)?|\.\d+)",
        text,
    )

    if not m:
        return None

    try:
        return float(
            m.group(0)
        )
    except Exception:
        return None


def mimosa_decimal_one(
    raw: Any,
) -> float | None:

    v = _mimosa_raw_number(
        raw
    )

    if v is None:
        return None

    return v / 10.0


def mimosa_decimal_two(
    raw: Any,
) -> float | None:

    text = s(raw)

    if not text:
        return None

    m = re.search(
        r"[-+]?(?:\d+\.\d+|\.\d+)",
        text,
    )

    if m:
        try:
            return float(
                m.group(0)
            )
        except Exception:
            pass

    v = _mimosa_raw_number(
        raw
    )

    if v is None:
        return None

    return v / 100.0


def mimosa_decimal_five(
    raw: Any,
) -> float | None:

    v = _mimosa_raw_number(
        raw
    )

    if v is None:
        return None

    return v / 100000.0


# =============================================================================
# SSH
# =============================================================================

class LegacySSH:

    def __init__(
        self,
        ip: str,
        username: str,
        password: str,
        port: int,
    ):
        self.ip = ip
        self.username = username
        self.password = password
        self.port = port

    def exec_command(
        self,
        command: str,
        timeout: float = 8,
    ):

        env = os.environ.copy()
        env["SSHPASS"] = self.password

        opts = [
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            f"ConnectTimeout={max(1, int(timeout))}",
            "-o",
            "HostKeyAlgorithms=+ssh-rsa,ssh-dss",
            "-o",
            "KexAlgorithms=+diffie-hellman-group1-sha1,diffie-hellman-group14-sha1",
            "-p",
            str(self.port),
        ]

        p = subprocess.run(
            [
                "sshpass",
                "-e",
                "ssh",
                *opts,
                f"{self.username}@{self.ip}",
                command,
            ],
            env=env,
            text=True,
            capture_output=True,
            timeout=max(
                10,
                int(timeout) + 5,
            ),
        )

        return (
            None,
            _Out(p.stdout),
            _Out(p.stderr),
        )

    def close(self):
        pass


class _Out:

    def __init__(self, x):
        self.x = x

    def read(self):
        return self.x.encode(
            "utf-8",
            "replace",
        )


def city_credentials(
    city: dict[str, Any],
) -> tuple[
    list[dict[str, str]],
    list[str],
]:

    try:
        ssh = json.loads(
            city.get(
                "ssh_credentials_json"
            )
            or "[]"
        )
    except Exception:
        ssh = []

    if not ssh:

        try:
            ssh = json.loads(
                os.getenv(
                    "SSH_CREDENTIALS_JSON",
                    "[]",
                )
                or "[]"
            )
        except Exception:
            ssh = []

    if (
        not ssh
        and os.getenv(
            "SSH_USER",
            "",
        ).strip()
    ):

        ssh = [
            {
                "username": os.getenv(
                    "SSH_USER",
                    "",
                ),
                "password": os.getenv(
                    "SSH_PASS",
                    "",
                ),
                "id": "default",
            }
        ]

    ssh_out = []

    for idx, item in enumerate(
        ssh,
        1,
    ):

        if (
            isinstance(item, dict)
            and s(
                item.get("username")
            )
        ):

            ssh_out.append(
                {
                    "username":
                        s(
                            item[
                                "username"
                            ]
                        ),

                    "password":
                        s(
                            item.get(
                                "password",
                                "",
                            )
                        ),

                    "id":
                        s(
                            item.get("id")
                        )
                        or f"city-{idx}",
                }
            )

    try:
        snmp = json.loads(
            city.get(
                "snmp_communities_json"
            )
            or "[]"
        )
    except Exception:
        snmp = []

    communities = []

    for item in snmp:

        if (
            isinstance(item, str)
            and item.strip()
        ):
            communities.append(
                item.strip()
            )

        elif (
            isinstance(item, dict)
            and s(
                item.get(
                    "community"
                )
            )
        ):
            communities.append(
                s(
                    item[
                        "community"
                    ]
                )
            )

    if not communities:

        communities = [
            os.getenv(
                "SNMP_COMMUNITY",
                "ngstehwl",
            ).strip()
            or "ngstehwl"
        ]

    return (
        ssh_out,
        list(
            dict.fromkeys(
                communities
            )
        ),
    )


def ssh_connect(
    ip: str,
    city: dict[str, Any],
):

    creds, _ = city_credentials(
        city
    )

    last = None

    for cred in creds:

        try:

            c = paramiko.SSHClient()

            c.set_missing_host_key_policy(
                paramiko.AutoAddPolicy()
            )

            c.connect(
                ip,
                port=int(
                    city[
                        "ssh_port"
                    ]
                ),
                username=cred[
                    "username"
                ],
                password=cred[
                    "password"
                ],
                timeout=float(
                    city[
                        "ssh_timeout"
                    ]
                ),
                banner_timeout=float(
                    city[
                        "ssh_timeout"
                    ]
                ),
                auth_timeout=float(
                    city[
                        "ssh_timeout"
                    ]
                ),
                allow_agent=False,
                look_for_keys=False,
            )

            return (
                c,
                f"ssh:{cred['id']}",
            )

        except Exception as exc:
            last = exc

    if (
        os.getenv(
            "LEGACY_SSH_FALLBACK",
            "1",
        ).lower()
        in {
            "1",
            "true",
            "yes",
            "on",
        }
        and shutil.which(
            "sshpass"
        )
    ):

        for cred in creds:

            try:

                c = LegacySSH(
                    ip,
                    cred[
                        "username"
                    ],
                    cred[
                        "password"
                    ],
                    int(
                        city[
                            "ssh_port"
                        ]
                    ),
                )

                _, o, e = c.exec_command(
                    "/system identity print",
                    timeout=float(
                        city[
                            "ssh_timeout"
                        ]
                    ),
                )

                txt = (
                    o.read()
                    .decode(
                        "utf-8",
                        "replace",
                    )
                    .strip()
                )

                if txt:

                    return (
                        c,
                        f"ssh-legacy:{cred['id']}",
                    )

                last = RuntimeError(
                    e.read()
                    .decode(
                        "utf-8",
                        "replace",
                    )[:200]
                    or "Legacy SSH failed"
                )

            except Exception as exc:
                last = exc

    raise RuntimeError(
        str(
            last
            or "No SSH credentials"
        )
    )


def ssh_cmd(
    c,
    command,
    timeout=8,
):

    try:

        _, o, _ = c.exec_command(
            command,
            timeout=timeout,
        )

        return (
            o.read()
            .decode(
                "utf-8",
                "replace",
            )
            .strip()
        )

    except Exception:
        return ""


# =============================================================================
# MIKROTIK SSH
# =============================================================================

def ssh_mikrotik(c):

    identity = ssh_cmd(
        c,
        "/system identity print",
    )

    resource = ssh_cmd(
        c,
        "/system resource print",
    )

    health = ssh_cmd(
        c,
        "/system health print",
    )

    monitor = ssh_cmd(
        c,
        "/interface wireless monitor wlan1 once",
    )

    if not monitor:

        monitor = ssh_cmd(
            c,
            "/interface wifi monitor wlan1 once",
        )

    registration = ssh_cmd(
        c,
        "/interface wireless registration-table print detail",
    )

    if not registration:

        registration = ssh_cmd(
            c,
            "/interface wifi registration-table print detail",
        )

    wireless_cfg = ssh_cmd(
        c,
        "/interface wireless print detail without-paging",
    )

    if not wireless_cfg:

        wireless_cfg = ssh_cmd(
            c,
            "/interface wifi print detail without-paging",
        )

    interfaces = ssh_cmd(
        c,
        "/interface print detail without-paging",
    )

    queues = ssh_cmd(
        c,
        "/queue simple print detail without-paging",
    )

    firewall = ssh_cmd(
        c,
        "/ip firewall filter print stats without-paging",
    )

    pppoe = ssh_cmd(
        c,
        "/interface pppoe-client print detail without-paging",
    )

    routes = ssh_cmd(
        c,
        "/ip route print detail without-paging",
    )

    i = parse_equal_lines(
        identity
        + "\n"
        + resource
    )

    m = parse_key_value_lines(
        monitor
    )

    w = parse_equal_lines(
        wireless_cfg
    )

    out = {
        "device_type":
            "MikroTik",

        "vendor":
            "MikroTik",

        "hostname":
            i.get(
                "name",
                "",
            ),

        "model":
            i.get(
                "board-name",
                "",
            )
            or i.get(
                "platform",
                "",
            ),

        "routeros_version":
            i.get(
                "version",
                "",
            ),

        "firmware_version":
            i.get(
                "version",
                "",
            ),

        "uptime":
            i.get(
                "uptime",
                "",
            ),

        "interfaces":
            interfaces,

        "wireless_registration":
            registration,

        "queues":
            queues,

        "firewall_counters":
            firewall,

        "pppoe_vpn":
            pppoe,

        "ip_routes":
            routes,

        "ssh_status":
            "success",

        "ssh_raw": {
            "identity":
                identity,
            "resource":
                resource,
            "health":
                health,
            "monitor":
                monitor,
            "registration":
                registration,
        },
    }

    mapping = {
        "ssid":
            "ssid",

        "channel":
            "channel",

        "mode":
            "mode",

        "frequency":
            "frequency",

        "noise-floor":
            "noise_floor",

        "signal-strength":
            "rx_power",

        "tx-signal-strength":
            "peer_tx_signal",

        "tx-rate":
            "tx_rate",

        "rx-rate":
            "rx_rate",

        "radio-name":
            "radio_name",

        "signal-to-noise":
            "snr",

        "tx-ccq":
            "tx_ccq",

        "rx-ccq":
            "rx_ccq",

        "overall-tx-ccq":
            "ccq",

        "status":
            "wireless_status",
    }

    for src, dst in mapping.items():

        if m.get(src):
            out[dst] = m[src]

    if not out.get("ssid"):
        out["ssid"] = w.get(
            "ssid",
            "",
        )

    if not out.get("mode"):
        out["mode"] = w.get(
            "mode",
            "",
        )

    if out.get(
        "rx_power"
    ):

        out[
            "rx_power"
        ] = normdbm(
            out[
                "rx_power"
            ]
        )

        out[
            "signal_strength"
        ] = out[
            "rx_power"
        ]

    if out.get(
        "peer_tx_signal"
    ):

        out[
            "peer_tx_signal"
        ] = normdbm(
            out[
                "peer_tx_signal"
            ]
        )

    if out.get(
        "noise_floor"
    ):

        out[
            "noise_floor"
        ] = normdbm(
            out[
                "noise_floor"
            ]
        )

    ch = s(
        out.get(
            "channel"
        )
    )

    mm = re.match(
        r"^(\d+(?:\.\d+)?)/(\d+(?:\.\d+)?)",
        ch,
    )

    if mm:

        out[
            "frequency"
        ] = mm.group(1)

        out[
            "bandwidth"
        ] = (
            mm.group(2)
            + " MHz"
        )

    out[
        "mac_address"
    ] = w.get(
        "mac-address",
        "",
    )

    return out


# =============================================================================
# SNMP CORE
# =============================================================================

def _snmp_is_invalid_value(
    value: Any,
) -> bool:

    text = s(value).lower()

    if not text:
        return False

    invalid_patterns = (
        "no such instance",
        "no such object",
        "no such name",
        "end of mib view",
        "nosuchinstance",
        "nosuchobject",
        "endofmibview",
    )

    return any(
        marker in text
        for marker in invalid_patterns
    )


async def _snmp_get_async(
    ip: str,
    port: int,
    community: str,
    oids: list[str],
    timeout: float,
    retries: int,
) -> dict[str, str]:

    if (
        not get_cmd
        or not SnmpDispatcher
        or not CommunityData
        or not UdpTransportTarget
    ):
        return {}

    disp = SnmpDispatcher()

    try:

        target = await UdpTransportTarget.create(
            (
                ip,
                port,
            ),
            timeout=float(timeout),
            retries=int(retries),
        )

        result = await get_cmd(
            disp,
            CommunityData(
                community,
                mpModel=1,
            ),
            target,
            *[
                (
                    oid,
                    None,
                )
                for oid in oids
            ],
        )

        (
            err_indication,
            err_status,
            _,
            var_binds,
        ) = result

        if err_indication:
            return {}

        if err_status:
            return {}

        out = {}

        for oid, value in var_binds:

            oid_text = s(
                oid
            )

            if hasattr(
                value,
                "prettyPrint",
            ):
                value_text = s(
                    value.prettyPrint()
                )
            else:
                value_text = s(
                    value
                )

            # IMPORTANT:
            # Do not store "No Such Instance..." as data.
            if _snmp_is_invalid_value(
                value_text
            ):
                continue

            out[
                oid_text
            ] = value_text

        return out

    except Exception as exc:

        LOG.debug(
            "SNMP async %s failed: %s",
            ip,
            exc,
        )

        return {}

    finally:

        try:
            disp.close_dispatcher()
        except Exception:
            pass


def snmp_get(
    ip: str,
    city: dict[str, Any],
    oids: list[str],
) -> tuple[
    dict[str, str],
    str,
]:

    for community in city_credentials(
        city
    )[1]:

        try:

            result = asyncio.run(
                _snmp_get_async(
                    ip,
                    int(
                        city[
                            "snmp_port"
                        ]
                    ),
                    community,
                    oids,
                    float(
                        city[
                            "snmp_timeout"
                        ]
                    ),
                    int(
                        city[
                            "snmp_retries"
                        ]
                    ),
                )
            )

            if result:
                return (
                    result,
                    community,
                )

        except Exception as exc:

            LOG.debug(
                "SNMP %s failed: %s",
                ip,
                exc,
            )

    return {}, ""


def snmpbulkwalk_numeric(
    ip: str,
    community: str,
    root: str,
    city: dict[str, Any],
) -> dict[str, str]:

    if (
        not community
        or not shutil.which(
            "snmpbulkwalk"
        )
    ):
        return {}

    cmd = [
        "snmpbulkwalk",
        "-v2c",
        "-c",
        community,
        "-On",
        "-t",
        str(
            float(
                city[
                    "snmp_timeout"
                ]
            )
        ),
        "-r",
        str(
            int(
                city[
                    "snmp_retries"
                ]
            )
        ),
        ip,
        root,
    ]

    try:

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(
                8,
                int(
                    float(
                        city[
                            "snmp_timeout"
                        ]
                    )
                )
                * 8
                + 4,
            ),
        )

    except Exception as exc:

        LOG.debug(
            "SNMP walk %s/%s failed: %s",
            ip,
            root,
            exc,
        )

        return {}

    if proc.returncode != 0:
        return {}

    out = {}

    for line in proc.stdout.splitlines():

        m = re.match(
            r"^([^ ]+)\s*=\s*(.*)$",
            line.strip(),
        )

        if not m:
            continue

        oid = m.group(1).lstrip(".")
        raw = m.group(2)

        value = (
            raw.split(
                ":",
                1,
            )[1].strip()
            if ":"
            in raw
            else raw.strip()
        )

        if _snmp_is_invalid_value(
            value
        ):
            continue

        out[oid] = value

    return out


def _snmp_lookup(
    data: dict[str, str],
    oid: str,
) -> str:

    clean = oid.lstrip(".")

    candidates = (
        clean,
        clean + ".0",
    )

    for candidate in candidates:

        value = s(
            data.get(
                candidate
            )
        )

        if (
            value
            and not _snmp_is_invalid_value(
                value
            )
        ):
            return value

    return ""


# =============================================================================
# MIMOSA PARSER
# =============================================================================

def parse_mimosa_vendor(
    data: dict[str, str],
) -> dict[str, Any]:

    out = {
        "mimosa_snmp":
            data,

        "mimosa_chains":
            [],

        "mimosa_streams":
            [],
    }

    general = (
        MIMOSA_GENERAL_ROOT
        .lstrip(".")
    )

    loc = (
        MIMOSA_LOC_ROOT
        .lstrip(".")
    )

    wan = (
        MIMOSA_WAN_ROOT
        .lstrip(".")
    )

    rf = (
        MIMOSA_RF_ROOT
        .lstrip(".")
    )

    chain = (
        MIMOSA_CHAIN_ROOT
        .lstrip(".")
    )

    stream = (
        MIMOSA_STREAM_ROOT
        .lstrip(".")
    )

    perf = (
        MIMOSA_PERF_ROOT
        .lstrip(".")
    )

    def val(
        root,
        suffix,
    ):

        return _snmp_lookup(
            data,
            root
            + "."
            + suffix,
        )

    # General
    v = val(
        general,
        "1.0",
    )

    if v:
        out[
            "mimosa_device_name"
        ] = v

        out[
            "hostname"
        ] = v

    v = val(
        general,
        "2.0",
    )

    if v:
        out[
            "serial_number"
        ] = v

    v = val(
        general,
        "3.0",
    )

    if v:
        out[
            "firmware_version"
        ] = v

    v = val(
        general,
        "4.0",
    )

    if v:
        out[
            "firmware_build_date"
        ] = v

    v = val(
        general,
        "5.0",
    )

    if v:
        out[
            "last_reboot_time"
        ] = v

    v = mimosa_decimal_one(
        val(
            general,
            "8.0",
        )
    )

    if v is not None:
        out[
            "temperature"
        ] = f"{v:g} C"

    # Location
    v = mimosa_decimal_five(
        val(
            loc,
            "1.0",
        )
    )

    if v is not None:
        out[
            "longitude"
        ] = f"{v:g}"

    v = mimosa_decimal_five(
        val(
            loc,
            "2.0",
        )
    )

    if v is not None:
        out[
            "latitude"
        ] = f"{v:g}"

    v = numeric_value(
        val(
            loc,
            "3.0",
        )
    )

    if v is not None:
        out[
            "altitude"
        ] = f"{v:g} m"

    v = mimosa_decimal_one(
        val(
            loc,
            "4.0",
        )
    )

    if v is not None:
        out[
            "gps_snr"
        ] = f"{v:g} dB"

    v = numeric_value(
        val(
            loc,
            "6.0",
        )
    )

    if v is not None:
        out[
            "gps_satellites"
        ] = f"{v:g}"

    v = numeric_value(
        val(
            loc,
            "7.0",
        )
    )

    if v is not None:
        out[
            "glonass_satellites"
        ] = f"{v:g}"

    # WAN
    v = val(
        wan,
        "1.0",
    )

    if v:
        out[
            "ssid"
        ] = v

    v = val(
        wan,
        "2.0",
    )

    if v:
        out[
            "mac_address"
        ] = v

    v = val(
        wan,
        "3.0",
    )

    if v:

        low = v.lower()

        if (
            "connected"
            in low
            or low
            in {
                "1",
                "1.0",
                "connected(1)",
            }
        ):

            out[
                "wireless_status"
            ] = "connected"

        elif (
            "disconnected"
            in low
            or low
            in {
                "2",
                "2.0",
                "disconnected(2)",
            }
        ):

            out[
                "wireless_status"
            ] = "disconnected"

        else:

            out[
                "wireless_status"
            ] = v

    # RF scalar
    v = numeric_value(
        val(
            rf,
            "4.0",
        )
    )

    if v is not None:
        out[
            "antenna_gain"
        ] = f"{v:g} dBi"

    v = mimosa_decimal_one(
        val(
            rf,
            "5.0",
        )
    )

    if v is not None:
        out[
            "total_tx_power"
        ] = f"{v:g} dBm"

    v = mimosa_decimal_one(
        val(
            rf,
            "6.0",
        )
    )

    if v is not None:

        out[
            "total_rx_power"
        ] = f"{v:g} dBm"

        out[
            "rx_power"
        ] = out[
            "total_rx_power"
        ]

        out[
            "signal_strength"
        ] = out[
            "rx_power"
        ]

    tx_values = []
    rx_values = []
    noise_values = []
    snr_values = []
    freq_values = []
    pol_values = []

    # RF chains
    for oid, raw in data.items():

        if not oid.startswith(
            chain + "."
        ):
            continue

        parts = oid[
            len(chain) + 1:
        ].split(".")

        if len(parts) < 2:
            continue

        try:
            col = int(parts[0])
            idx = int(parts[1])
        except Exception:
            continue

        row = next(
            (
                x
                for x
                in out[
                    "mimosa_chains"
                ]
                if x.get(
                    "index"
                ) == idx
            ),
            None,
        )

        if row is None:

            row = {
                "index":
                    idx
            }

            out[
                "mimosa_chains"
            ].append(
                row
            )

        if col == 1:

            row[
                "chain"
            ] = s(raw)

        elif col == 2:

            v = mimosa_decimal_one(
                raw
            )

            if v is not None:

                row[
                    "tx_power"
                ] = (
                    f"{v:g} dBm"
                )

                tx_values.append(
                    v
                )

        elif col == 3:

            v = mimosa_decimal_one(
                raw
            )

            if v is not None:

                row[
                    "rx_power"
                ] = (
                    f"{v:g} dBm"
                )

                rx_values.append(
                    v
                )

        elif col == 4:

            v = mimosa_decimal_one(
                raw
            )

            if v is not None:

                row[
                    "noise_floor"
                ] = (
                    f"{v:g} dBm"
                )

                noise_values.append(
                    v
                )

        elif col == 5:

            v = mimosa_decimal_one(
                raw
            )

            if v is not None:

                row[
                    "snr"
                ] = (
                    f"{v:g} dB"
                )

                snr_values.append(
                    v
                )

        elif col == 6:

            v = numeric_value(
                raw
            )

            if (
                v is not None
                and v > 0
            ):

                row[
                    "frequency"
                ] = (
                    f"{v:g} MHz"
                )

                freq_values.append(
                    v
                )

        elif col == 7:

            raw_text = s(
                raw
            ).lower()

            if raw_text in {
                "1",
                "horizontal",
                "horizontal(1)",
            }:

                value = (
                    "horizontal"
                )

            elif raw_text in {
                "2",
                "vertical",
                "vertical(2)",
            }:

                value = (
                    "vertical"
                )

            else:

                value = s(
                    raw
                )

            if value:

                row[
                    "polarization"
                ] = value

                pol_values.append(
                    value
                )

    if tx_values:

        out[
            "tx_power"
        ] = (
            f"{sum(tx_values) / len(tx_values):g} dBm"
        )

    if rx_values:

        out[
            "rx_power"
        ] = (
            f"{sum(rx_values) / len(rx_values):g} dBm"
        )

        out[
            "signal_strength"
        ] = out[
            "rx_power"
        ]

    if noise_values:

        out[
            "noise_floor"
        ] = (
            f"{sum(noise_values) / len(noise_values):g} dBm"
        )

    if snr_values:

        out[
            "snr"
        ] = (
            f"{sum(snr_values) / len(snr_values):g} dB"
        )

    if freq_values:

        out[
            "frequency"
        ] = (
            f"{sum(freq_values) / len(freq_values):g} MHz"
        )

    if pol_values:

        out[
            "polarization"
        ] = pol_values[0]

    # Streams
    stream_tx_rates = []
    stream_rx_rates = []
    stream_tx_widths = []
    stream_rx_widths = []

    for oid, raw in data.items():

        if not oid.startswith(
            stream + "."
        ):
            continue

        parts = oid[
            len(stream) + 1:
        ].split(".")

        if len(parts) < 2:
            continue

        try:
            col = int(parts[0])
            idx = int(parts[1])
        except Exception:
            continue

        row = next(
            (
                x
                for x
                in out[
                    "mimosa_streams"
                ]
                if x.get(
                    "index"
                ) == idx
            ),
            None,
        )

        if row is None:

            row = {
                "index":
                    idx
            }

            out[
                "mimosa_streams"
            ].append(
                row
            )

        if col == 1:

            row[
                "stream"
            ] = s(raw)

        elif col == 2:

            v = numeric_value(
                raw
            )

            if (
                v is not None
                and v >= 0
            ):

                row[
                    "tx_rate"
                ] = (
                    f"{v:g} Mbps"
                )

                stream_tx_rates.append(
                    v
                )

        elif col == 4:

            v = numeric_value(
                raw
            )

            if (
                v is not None
                and v >= 0
            ):

                row[
                    "tx_width"
                ] = (
                    f"{v:g} MHz"
                )

                stream_tx_widths.append(
                    v
                )

        elif col == 5:

            v = numeric_value(
                raw
            )

            if (
                v is not None
                and v >= 0
            ):

                row[
                    "rx_rate"
                ] = (
                    f"{v:g} Mbps"
                )

                stream_rx_rates.append(
                    v
                )

        elif col == 7:

            v = numeric_value(
                raw
            )

            if (
                v is not None
                and v >= 0
            ):

                row[
                    "rx_width"
                ] = (
                    f"{v:g} MHz"
                )

                stream_rx_widths.append(
                    v
                )

    if (
        not s(
            out.get(
                "tx_rate"
            )
        )
        and stream_tx_rates
    ):

        out[
            "tx_rate"
        ] = (
            f"{sum(stream_tx_rates) / len(stream_tx_rates):g} Mbps"
        )

    if (
        not s(
            out.get(
                "rx_rate"
            )
        )
        and stream_rx_rates
    ):

        out[
            "rx_rate"
        ] = (
            f"{sum(stream_rx_rates) / len(stream_rx_rates):g} Mbps"
        )

    if (
        not s(
            out.get(
                "bandwidth"
            )
        )
        and stream_tx_widths
    ):

        out[
            "bandwidth"
        ] = (
            f"{max(stream_tx_widths):g} MHz"
        )

    if (
        not s(
            out.get(
                "bandwidth"
            )
        )
        and stream_rx_widths
    ):

        out[
            "bandwidth"
        ] = (
            f"{max(stream_rx_widths):g} MHz"
        )

    # Performance
    v = mimosa_decimal_two(
        val(
            perf,
            "1.0",
        )
    )

    if v is not None:

        out[
            "tx_rate"
        ] = (
            f"{v / 1000:g} Mbps"
        )

    v = mimosa_decimal_two(
        val(
            perf,
            "2.0",
        )
    )

    if v is not None:

        out[
            "rx_rate"
        ] = (
            f"{v / 1000:g} Mbps"
        )

    v = mimosa_decimal_two(
        val(
            perf,
            "3.0",
        )
    )

    if v is not None:

        out[
            "tx_per"
        ] = f"{v:g}%"

    v = mimosa_decimal_two(
        val(
            perf,
            "4.0",
        )
    )

    if v is not None:

        out[
            "rx_per"
        ] = f"{v:g}%"

    if out[
        "mimosa_chains"
    ]:

        out[
            "antenna_count"
        ] = len(
            out[
                "mimosa_chains"
            ]
        )

        out[
            "chain_summary"
        ] = json.dumps(
            out[
                "mimosa_chains"
            ],
            ensure_ascii=False,
        )

    if out[
        "mimosa_streams"
    ]:

        out[
            "stream_summary"
        ] = json.dumps(
            out[
                "mimosa_streams"
            ],
            ensure_ascii=False,
        )

    return out


# =============================================================================
# RACOM
# =============================================================================

def racom_generation_from_oid(
    object_id: str,
) -> str:

    oid = s(
        object_id
    ).lstrip(".")

    if oid.startswith(
        RACOM_RAY3_ROOT
    ):
        return "RAy3"

    if oid.startswith(
        RACOM_RAY2_ROOT
    ):
        return "RAy2"

    return ""


def racom_oid(
    root: str,
    suffix: str,
    scalar: bool = True,
) -> str:

    oid = (
        root.rstrip(".")
        + suffix
    )

    if scalar:
        oid += ".0"

    return oid


def racom_clean_status(
    value: Any,
) -> str:

    text = s(
        value
    ).lower()

    if not text:
        return ""

    mapping = {
        "0":
            "na",

        "1":
            "ok",

        "2":
            "warning",

        "3":
            "alarm",

        "4":
            "authorizing",

        "5":
            "ok",

        "6":
            "analyzer",

        "1.0":
            "ok",

        "2.0":
            "warning",

        "3.0":
            "alarm",

        "5.0":
            "ok",

        "setup(1)":
            "setup",

        "single(2)":
            "single",

        "connecting(3)":
            "connecting",

        "authorizing(4)":
            "authorizing",

        "ok(5)":
            "ok",

        "analyzer(6)":
            "analyzer",

        "up(1)":
            "up",

        "down(2)":
            "down",

        "na(0)":
            "na",
    }

    return mapping.get(
        text,
        text,
    )


def racom_generation_root(
    generation: str,
) -> str:

    if generation == "RAy2":
        return RACOM_RAY2_ROOT

    if generation == "RAy3":
        return RACOM_RAY3_ROOT

    return ""


def parse_racom_vendor(
    data: dict[str, str],
    generation: str,
) -> dict[str, Any]:

    root = racom_generation_root(
        generation
    )

    if not root:
        return {}

    out = {
        "racom_snmp":
            data,

        "racom_generation":
            generation,

        "vendor":
            "Racom",

        "device_type":
            "Racom",
    }

    # -------------------------------------------------------------------------
    # Product
    # -------------------------------------------------------------------------

    product_name = _snmp_lookup(
        data,
        racom_oid(
            root,
            RACOM_PRODUCT_NAME,
            True,
        ),
    )

    serial = _snmp_lookup(
        data,
        racom_oid(
            root,
            RACOM_SERIAL_NUMBER,
            True,
        ),
    )

    unit_type = _snmp_lookup(
        data,
        racom_oid(
            root,
            RACOM_UNIT_TYPE,
            True,
        ),
    )

    device_name = _snmp_lookup(
        data,
        racom_oid(
            root,
            RACOM_DEVICE_NAME,
            True,
        ),
    )

    sw_version = _snmp_lookup(
        data,
        racom_oid(
            root,
            RACOM_SW_VERSION,
            True,
        ),
    )

    sw_radio_version = _snmp_lookup(
        data,
        racom_oid(
            root,
            RACOM_SW_RADIO_VERSION,
            True,
        ),
    )

    if product_name:
        out[
            "model"
        ] = product_name

    if serial:
        out[
            "serial_number"
        ] = serial

    if unit_type:
        out[
            "unit_type"
        ] = unit_type

    if device_name:
        out[
            "hostname"
        ] = device_name

    if sw_version:
        out[
            "firmware_version"
        ] = sw_version

    if sw_radio_version:
        out[
            "radio_firmware_version"
        ] = sw_radio_version

    # -------------------------------------------------------------------------
    # Status
    # -------------------------------------------------------------------------

    system_status = _snmp_lookup(
        data,
        racom_oid(
            root,
            RACOM_SYSTEM_STATUS,
            True,
        ),
    )

    line_status = _snmp_lookup(
        data,
        racom_oid(
            root,
            RACOM_LINE_STATUS,
            True,
        ),
    )

    line_status_ii = _snmp_lookup(
        data,
        racom_oid(
            root,
            RACOM_LINE_STATUS_II,
            True,
        ),
    )

    peer_number = _snmp_lookup(
        data,
        racom_oid(
            root,
            RACOM_PEER_NUMBER,
            True,
        ),
    )

    rf_power_status = _snmp_lookup(
        data,
        racom_oid(
            root,
            RACOM_RF_POWER_STATUS,
            True,
        ),
    )

    eth1_link = _snmp_lookup(
        data,
        racom_oid(
            root,
            RACOM_ETH1_LINK,
            True,
        ),
    )

    eth2_link = _snmp_lookup(
        data,
        racom_oid(
            root,
            RACOM_ETH2_LINK,
            True,
        ),
    )

    if system_status:
        out[
            "system_status"
        ] = racom_clean_status(
            system_status
        )

    if line_status:
        out[
            "line_status"
        ] = racom_clean_status(
            line_status
        )

    if line_status_ii:
        out[
            "line_status_ii"
        ] = racom_clean_status(
            line_status_ii
        )

    if peer_number:
        out[
            "peer_number"
        ] = peer_number

    if rf_power_status:
        out[
            "rf_power_status"
        ] = racom_clean_status(
            rf_power_status
        )

    if eth1_link:
        out[
            "eth1_link"
        ] = racom_clean_status(
            eth1_link
        )

    if eth2_link:
        out[
            "eth2_link"
        ] = racom_clean_status(
            eth2_link
        )

    # RAy2 and RAy3 lineStatusII:
    # 5 = ok
    # 0 = na
    # 1 = setup
    # 2 = single
    # 3 = connecting
    # 4 = authorizing
    # 6 = analyzer
    if line_status_ii:

        status = racom_clean_status(
            line_status_ii
        )

        if status == "ok":

            out[
                "wireless_status"
            ] = "connected"

        elif status in {
            "setup",
            "single",
            "connecting",
            "authorizing",
            "analyzer",
        }:

            out[
                "wireless_status"
            ] = status

        elif status == "na":

            out[
                "wireless_status"
            ] = "unknown"

        else:

            out[
                "wireless_status"
            ] = status

    elif system_status:

        status = racom_clean_status(
            system_status
        )

        if status == "ok":

            out[
                "wireless_status"
            ] = "connected"

        elif status in {
            "warning",
            "alarm",
            "na",
        }:

            out[
                "wireless_status"
            ] = status

    # -------------------------------------------------------------------------
    # Chassis
    # -------------------------------------------------------------------------

    temp_modem = numeric_value(
        _snmp_lookup(
            data,
            racom_oid(
                root,
                RACOM_TEMP_MODEM,
                True,
            ),
        )
    )

    temp_radio = numeric_value(
        _snmp_lookup(
            data,
            racom_oid(
                root,
                RACOM_TEMP_RADIO,
                True,
            ),
        )
    )

    voltage = numeric_value(
        _snmp_lookup(
            data,
            racom_oid(
                root,
                RACOM_VOLTAGE_UNIT,
                True,
            ),
        )
    )

    if temp_modem is not None:
        out[
            "temperature"
        ] = (
            f"{temp_modem / 100.0:g} C"
        )

    if temp_radio is not None:
        out[
            "radio_temperature"
        ] = (
            f"{temp_radio / 100.0:g} C"
        )

    if voltage is not None:
        out[
            "voltage"
        ] = (
            f"{voltage / 10.0:g} V"
        )

    # -------------------------------------------------------------------------
    # Radio configuration
    # -------------------------------------------------------------------------

    rx_channel = _snmp_lookup(
        data,
        racom_oid(
            root,
            RACOM_RX_CHANNEL,
            True,
        ),
    )

    tx_channel = _snmp_lookup(
        data,
        racom_oid(
            root,
            RACOM_TX_CHANNEL,
            True,
        ),
    )

    rx_freq = numeric_value(
        _snmp_lookup(
            data,
            racom_oid(
                root,
                RACOM_RX_FREQ,
                True,
            ),
        )
    )

    tx_freq = numeric_value(
        _snmp_lookup(
            data,
            racom_oid(
                root,
                RACOM_TX_FREQ,
                True,
            ),
        )
    )

    rx_modulation = _snmp_lookup(
        data,
        racom_oid(
            root,
            RACOM_RX_MODULATION,
            True,
        ),
    )

    tx_modulation = _snmp_lookup(
        data,
        racom_oid(
            root,
            RACOM_TX_MODULATION,
            True,
        ),
    )

    bandwidth_khz = numeric_value(
        _snmp_lookup(
            data,
            racom_oid(
                root,
                RACOM_BANDWIDTH_KHZ,
                True,
            ),
        )
    )

    rx_bandwidth_khz = numeric_value(
        _snmp_lookup(
            data,
            racom_oid(
                root,
                RACOM_RX_BANDWIDTH_KHZ,
                True,
            ),
        )
    )

    frequency_table = _snmp_lookup(
        data,
        racom_oid(
            root,
            RACOM_FREQUENCY_TABLE,
            True,
        ),
    )

    if rx_channel:
        out[
            "rx_channel"
        ] = rx_channel

    if tx_channel:
        out[
            "tx_channel"
        ] = tx_channel

    if rx_modulation:
        out[
            "rx_modulation"
        ] = rx_modulation

    if tx_modulation:
        out[
            "tx_modulation"
        ] = tx_modulation

    if frequency_table:
        out[
            "frequency_table"
        ] = frequency_table

    if rx_freq is not None:

        out[
            "frequency"
        ] = (
            f"{rx_freq / 1000.0:g} MHz"
        )

        out[
            "rx_frequency"
        ] = (
            f"{rx_freq / 1000.0:g} MHz"
        )

    if tx_freq is not None:

        out[
            "tx_frequency"
        ] = (
            f"{tx_freq / 1000.0:g} MHz"
        )

    if (
        rx_freq is not None
        and tx_freq is not None
    ):

        out[
            "frequency_pair"
        ] = (
            f"{rx_freq / 1000.0:g} MHz / "
            f"{tx_freq / 1000.0:g} MHz"
        )

    if bandwidth_khz is not None:

        out[
            "bandwidth"
        ] = (
            f"{bandwidth_khz / 1000.0:g} MHz"
        )

    elif rx_bandwidth_khz is not None:

        out[
            "bandwidth"
        ] = (
            f"{rx_bandwidth_khz / 1000.0:g} MHz"
        )

    # -------------------------------------------------------------------------
    # RF statistics
    # -------------------------------------------------------------------------

    rf_power = numeric_value(
        _snmp_lookup(
            data,
            racom_oid(
                root,
                RACOM_RF_POWER_CURRENT,
                True,
            ),
        )
    )

    rss = numeric_value(
        _snmp_lookup(
            data,
            racom_oid(
                root,
                RACOM_RSS,
                True,
            ),
        )
    )

    snr = numeric_value(
        _snmp_lookup(
            data,
            racom_oid(
                root,
                RACOM_SNR,
                True,
            ),
        )
    )

    mse = numeric_value(
        _snmp_lookup(
            data,
            racom_oid(
                root,
                RACOM_MSE,
                True,
            ),
        )
    )

    if rf_power is not None:

        out[
            "tx_power"
        ] = (
            f"{rf_power:g} dBm"
        )

    if rss is not None:

        out[
            "rx_power"
        ] = (
            f"{rss / 10.0:g} dBm"
        )

        out[
            "signal_strength"
        ] = out[
            "rx_power"
        ]

    if snr is not None:

        out[
            "snr"
        ] = (
            f"{snr / 10.0:g} dB"
        )

    if mse is not None:

        out[
            "mse"
        ] = (
            f"{mse / 10.0:g} dB"
        )

    # -------------------------------------------------------------------------
    # Link statistics
    # -------------------------------------------------------------------------

    reliability = numeric_value(
        _snmp_lookup(
            data,
            racom_oid(
                root,
                RACOM_RELIABILITY,
                True,
            ),
        )
    )

    link_uptime = _snmp_lookup(
        data,
        racom_oid(
            root,
            RACOM_LINK_UPTIME,
            True,
        ),
    )

    num_disconnect = _snmp_lookup(
        data,
        racom_oid(
            root,
            RACOM_NUM_DISCONNECT,
            True,
        ),
    )

    ber = numeric_value(
        _snmp_lookup(
            data,
            racom_oid(
                root,
                RACOM_BER,
                True,
            ),
        )
    )

    if reliability is not None:

        out[
            "reliability"
        ] = (
            f"{reliability / 1000.0:g}%"
        )

    if link_uptime:
        out[
            "wireless_uptime"
        ] = link_uptime

    if num_disconnect:
        out[
            "disconnect_count"
        ] = num_disconnect

    if ber is not None:

        out[
            "ber"
        ] = (
            f"{ber / 1_000_000_000:g}"
        )

    # -------------------------------------------------------------------------
    # Bitrates
    # -------------------------------------------------------------------------

    net_bitrate = numeric_value(
        _snmp_lookup(
            data,
            racom_oid(
                root,
                RACOM_NET_BITRATE,
                True,
            ),
        )
    )

    max_net_bitrate = numeric_value(
        _snmp_lookup(
            data,
            racom_oid(
                root,
                RACOM_MAX_NET_BITRATE,
                True,
            ),
        )
    )

    eth_in = numeric_value(
        _snmp_lookup(
            data,
            racom_oid(
                root,
                RACOM_ETH_IN_THROUGHPUT,
                True,
            ),
        )
    )

    eth_out = numeric_value(
        _snmp_lookup(
            data,
            racom_oid(
                root,
                RACOM_ETH_OUT_THROUGHPUT,
                True,
            ),
        )
    )

    if net_bitrate is not None:

        out[
            "net_bitrate"
        ] = (
            f"{net_bitrate / 1000.0:g} Mbps"
        )

        # If no directional throughput exists,
        # use the actual current net bitrate.
        out.setdefault(
            "rx_rate",
            f"{net_bitrate / 1000.0:g} Mbps",
        )

        out.setdefault(
            "tx_rate",
            f"{net_bitrate / 1000.0:g} Mbps",
        )

    if max_net_bitrate is not None:

        out[
            "max_net_bitrate"
        ] = (
            f"{max_net_bitrate:g} Mbps"
        )

    if eth_in is not None:

        out[
            "rx_rate"
        ] = (
            f"{eth_in / 1000.0:g} Mbps"
        )

    if eth_out is not None:

        out[
            "tx_rate"
        ] = (
            f"{eth_out / 1000.0:g} Mbps"
        )

    # -------------------------------------------------------------------------
    # CCQ
    # -------------------------------------------------------------------------

    # RACOM RAY-MIB does NOT define MikroTik CCQ.
    # Never generate fake CCQ.
    out[
        "ccq"
    ] = ""

    return out


def racom_vendor_collect(
    ip: str,
    city: dict[str, Any],
    object_id: str,
) -> dict[str, Any]:

    generation = (
        racom_generation_from_oid(
            object_id
        )
    )

    if not generation:
        return {}

    root = racom_generation_root(
        generation
    )

    if not root:
        return {}

    # First read the complete vendor subtree.
    # This is more compatible with old/new RAy firmware,
    # and avoids failure when one optional scalar isn't implemented.
    communities = city_credentials(
        city
    )[1]

    all_raw = {}
    used_community = ""

    for community in communities:

        raw = snmpbulkwalk_numeric(
            ip,
            community,
            root,
            city,
        )

        if raw:

            all_raw.update(
                raw
            )

            used_community = (
                community
            )

            break

    # Fallback to exact GETs when walking is unavailable.
    if not all_raw:

        suffixes = [
            RACOM_PRODUCT_NAME,
            RACOM_SERIAL_NUMBER,
            RACOM_UNIT_TYPE,

            RACOM_DEVICE_NAME,
            RACOM_SW_VERSION,
            RACOM_SW_RADIO_VERSION,

            RACOM_SYSTEM_STATUS,
            RACOM_LINE_STATUS,
            RACOM_PEER_NUMBER,
            RACOM_RF_POWER_STATUS,
            RACOM_LINE_STATUS_II,
            RACOM_ETH1_LINK,
            RACOM_ETH2_LINK,

            RACOM_TEMP_MODEM,
            RACOM_TEMP_RADIO,
            RACOM_VOLTAGE_UNIT,

            RACOM_RX_CHANNEL,
            RACOM_TX_CHANNEL,
            RACOM_RX_FREQ,
            RACOM_TX_FREQ,
            RACOM_RX_MODULATION,
            RACOM_TX_MODULATION,
            RACOM_RX_MODULATION_INDEX,
            RACOM_TX_MODULATION_INDEX,
            RACOM_BANDWIDTH,
            RACOM_RF_POWER_CONFIGURED,
            RACOM_NET_BITRATE,
            RACOM_MAX_NET_BITRATE,
            RACOM_BANDWIDTH_KHZ,
            RACOM_CHANNEL_ARRANGEMENT,
            RACOM_RF_POWER_CURRENT,
            RACOM_FREQUENCY_TABLE,
            RACOM_RX_BANDWIDTH_KHZ,

            RACOM_RSS,
            RACOM_SNR,
            RACOM_TIME_ALL_CONNECT,
            RACOM_TIME_ALL_DISCONNECT,
            RACOM_TIME_MAX_DISCONNECT,
            RACOM_NUM_DISCONNECT,
            RACOM_RELIABILITY,
            RACOM_LINK_UPTIME,
            RACOM_BER,
            RACOM_MSE,

            RACOM_ETH_IN_THROUGHPUT,
            RACOM_ETH_OUT_THROUGHPUT,
            RACOM_ETH2_IN_THROUGHPUT,
            RACOM_ETH2_OUT_THROUGHPUT,
        ]

        for community in communities:

            oids = [
                racom_oid(
                    root,
                    suffix,
                    True,
                )
                for suffix
                in suffixes
            ]

            raw, comm = snmp_get(
                ip,
                city,
                oids,
            )

            if raw:

                all_raw.update(
                    raw
                )

                used_community = (
                    comm
                )

                break

    if not all_raw:
        return {}

    parsed = parse_racom_vendor(
        all_raw,
        generation,
    )

    parsed[
        "snmp_community"
    ] = used_community

    return parsed


# =============================================================================
# SNMP COLLECTION
# =============================================================================

def snmp_collect(
    ip: str,
    city: dict[str, Any],
) -> dict[str, Any]:

    values, community = snmp_get(
        ip,
        city,
        list(
            STANDARD_OIDS.values()
        ),
    )

    reverse = {
        value: key
        for key, value
        in STANDARD_OIDS.items()
    }

    by = {
        reverse.get(
            oid,
            oid,
        ): value
        for oid, value
        in values.items()
    }

    out = {
        "snmp_status":
            (
                "success"
                if values
                else "failed"
            ),

        "snmp_community":
            community,

        "snmp_raw":
            by,
    }

    if not values:
        return out

    descr = s(
        by.get(
            "sysDescr"
        )
    )

    obj = s(
        by.get(
            "sysObjectID"
        )
    )

    ident_text = (
        descr
        + " "
        + obj
    ).lower()

    # -------------------------------------------------------------------------
    # Vendor detection
    # -------------------------------------------------------------------------

    if (
        "mikrotik"
        in ident_text
        or "routeros"
        in ident_text
    ):

        out.update(
            device_type="MikroTik",
            vendor="MikroTik",
        )

    elif (
        "mimosa"
        in ident_text
        or "43356"
        in obj
    ):

        out.update(
            device_type="Mimosa",
            vendor="Mimosa",
        )

    elif (
        "racom"
        in ident_text
        or "33555"
        in obj
        or "microwave link"
        in ident_text
    ):

        out.update(
            device_type="Racom",
            vendor="Racom",
        )

    elif (
        "cisco"
        in ident_text
        or "ios"
        in ident_text
    ):

        out.update(
            device_type="Cisco",
            vendor="Cisco",
        )

    out.update(
        {
            "hostname":
                s(
                    by.get(
                        "sysName"
                    )
                ),

            "firmware_version":
                descr,

            "uptime":
                s(
                    by.get(
                        "sysUpTime"
                    )
                ),
        }
    )

    # -------------------------------------------------------------------------
    # Mimosa
    # -------------------------------------------------------------------------

    if out.get(
        "device_type"
    ) == "Mimosa":

        try:

            raw, comm = snmp_get(
                ip,
                city,
                [
                    MIMOSA_GENERAL_ROOT
                    + ".1.0",

                    MIMOSA_GENERAL_ROOT
                    + ".2.0",

                    MIMOSA_GENERAL_ROOT
                    + ".3.0",

                    MIMOSA_GENERAL_ROOT
                    + ".4.0",

                    MIMOSA_GENERAL_ROOT
                    + ".5.0",

                    MIMOSA_GENERAL_ROOT
                    + ".8.0",

                    MIMOSA_LOC_ROOT
                    + ".1.0",

                    MIMOSA_LOC_ROOT
                    + ".2.0",

                    MIMOSA_LOC_ROOT
                    + ".3.0",

                    MIMOSA_LOC_ROOT
                    + ".4.0",

                    MIMOSA_LOC_ROOT
                    + ".6.0",

                    MIMOSA_LOC_ROOT
                    + ".7.0",

                    MIMOSA_WAN_ROOT
                    + ".1.0",

                    MIMOSA_WAN_ROOT
                    + ".2.0",

                    MIMOSA_WAN_ROOT
                    + ".3.0",

                    MIMOSA_WAN_ROOT
                    + ".4.0",

                    MIMOSA_RF_ROOT
                    + ".4.0",

                    MIMOSA_RF_ROOT
                    + ".5.0",

                    MIMOSA_RF_ROOT
                    + ".6.0",

                    MIMOSA_RF_ROOT
                    + ".7.0",

                    MIMOSA_PERF_ROOT
                    + ".1.0",

                    MIMOSA_PERF_ROOT
                    + ".2.0",

                    MIMOSA_PERF_ROOT
                    + ".3.0",

                    MIMOSA_PERF_ROOT
                    + ".4.0",
                ],
            )

            if raw:

                parsed = parse_mimosa_vendor(
                    raw
                )

                merge_nonempty(
                    out,
                    parsed,
                    preserve={
                        "mimosa_snmp",
                        "mimosa_chains",
                        "mimosa_streams",
                    },
                )

                out[
                    "snmp_vendor_raw"
                ] = parsed

        except Exception as exc:

            LOG.debug(
                "Mimosa SNMP %s failed: %s",
                ip,
                exc,
            )

        # Full Mimosa subtree fallback.
        try:

            raw = snmpbulkwalk_numeric(
                ip,
                community,
                MIMOSA_ROOT,
                city,
            )

            if raw:

                parsed = parse_mimosa_vendor(
                    raw
                )

                merge_nonempty(
                    out,
                    parsed,
                    preserve={
                        "mimosa_snmp",
                        "mimosa_chains",
                        "mimosa_streams",
                    },
                )

                out[
                    "snmp_vendor_raw"
                ] = parsed

        except Exception as exc:

            LOG.debug(
                "Mimosa walk %s failed: %s",
                ip,
                exc,
            )

    # -------------------------------------------------------------------------
    # Racom
    # -------------------------------------------------------------------------

    if out.get(
        "device_type"
    ) == "Racom":

        try:

            vendor_data = racom_vendor_collect(
                ip,
                city,
                obj,
            )

            if vendor_data:

                merge_nonempty(
                    out,
                    vendor_data,
                    preserve={
                        "racom_snmp",
                        "racom_generation",
                    },
                )

                out[
                    "snmp_vendor_raw"
                ] = vendor_data

                if not s(
                    out.get(
                        "hostname"
                    )
                ):

                    fallback_name = s(
                        vendor_data.get(
                            "hostname"
                        )
                    )

                    if fallback_name:
                        out[
                            "hostname"
                        ] = fallback_name

        except Exception as exc:

            LOG.debug(
                "Racom SNMP %s failed: %s",
                ip,
                exc,
            )

    # -------------------------------------------------------------------------
    # Generic SNMP system data
    # -------------------------------------------------------------------------

    cpu = s(
        by.get(
            "hrProcessorLoad"
        )
    )

    if cpu:

        out[
            "cpu_load"
        ] = (
            cpu
            if cpu.endswith("%")
            else f"{cpu}%"
        )

    try:

        total = float(
            re.sub(
                r"[^0-9.]",
                "",
                s(
                    by.get(
                        "memTotalReal"
                    )
                ),
            )
            or 0
        )

        free = float(
            re.sub(
                r"[^0-9.]",
                "",
                s(
                    by.get(
                        "memAvailReal"
                    )
                ),
            )
            or 0
        )

        if total:

            out[
                "memory_usage"
            ] = (
                f"{max(0.0, (1.0 - free / total) * 100.0):.1f}%"
            )

    except Exception:
        pass

    for key in (
        "mtTemperature",
        "mtCpuTemperature",
    ):

        value = s(
            by.get(
                key
            )
        )

        if not value:
            continue

        target = (
            "temperature"
            if key
            == "mtTemperature"
            else "cpu_temperature"
        )

        try:

            out[
                target
            ] = (
                f"{float(re.sub(r'[^0-9.-]', '', value))/10:.1f} C"
            )

        except Exception:
            pass

    # -------------------------------------------------------------------------
    # IF-MIB
    # -------------------------------------------------------------------------

    if (
        community
        and shutil.which(
            "snmpbulkwalk"
        )
    ):

        try:

            base_rows = {}

            for label, oid in IF_OIDS.items():

                cmd = [
                    "snmpbulkwalk",
                    "-v2c",
                    "-c",
                    community,
                    "-On",
                    "-t",
                    str(
                        float(
                            city[
                                "snmp_timeout"
                            ]
                        )
                    ),
                    "-r",
                    str(
                        int(
                            city[
                                "snmp_retries"
                            ]
                        )
                    ),
                    ip,
                    oid,
                ]

                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=max(
                        4,
                        int(
                            float(
                                city[
                                    "snmp_timeout"
                                ]
                            )
                        )
                        * 3
                        + 2,
                    ),
                )

                if proc.returncode != 0:
                    continue

                for line in proc.stdout.splitlines():

                    m = re.match(
                        r"^([^ ]+)\s*=\s*(.*)$",
                        line.strip(),
                    )

                    if not m:
                        continue

                    full_oid = m.group(
                        1
                    )

                    raw = m.group(
                        2
                    )

                    idx = full_oid.rsplit(
                        ".",
                        1,
                    )[-1]

                    value = (
                        raw.split(
                            ":",
                            1,
                        )[1].strip()
                        if ":"
                        in raw
                        else raw.strip()
                    )

                    if _snmp_is_invalid_value(
                        value
                    ):
                        continue

                    base_rows.setdefault(
                        idx,
                        {},
                    )[label] = value

            if base_rows:

                out[
                    "interfaces"
                ] = json.dumps(
                    [
                        {
                            "index":
                                idx,
                            **vals,
                        }
                        for idx, vals
                        in sorted(
                            base_rows.items(),
                            key=lambda x: x[0],
                        )
                    ],
                    ensure_ascii=False,
                )

        except Exception as exc:

            LOG.debug(
                "SNMP interface walk %s failed: %s",
                ip,
                exc,
            )

    return out


# =============================================================================
# TCP / PRECHECK
# =============================================================================

def tcp_open(
    ip: str,
    port: int,
    timeout: float = 1.0,
) -> bool:

    try:

        with socket.create_connection(
            (
                ip,
                int(port),
            ),
            timeout=float(
                timeout
            ),
        ):
            return True

    except Exception:
        return False


def precheck(
    ip: str,
    city: dict[str, Any],
) -> list[str]:

    reasons = []

    # RouterOS API only 8728.
    if (
        int(
            city.get(
                "api_enabled",
                1,
            )
        )
        and int(
            city.get(
                "api_ssl_enabled",
                0,
            )
        )
        == 0
        and tcp_open(
            ip,
            int(
                city[
                    "api_port"
                ]
            ),
        )
    ):

        reasons.append(
            f"API {city['api_port']}"
        )

    # SSH
    if tcp_open(
        ip,
        int(
            city[
                "ssh_port"
            ]
        ),
    ):

        reasons.append(
            "SSH"
        )

    # ICMP
    try:

        rc = subprocess.run(
            [
                "ping",
                "-c",
                "1",
                "-W",
                "1",
                ip,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
        ).returncode

        if rc == 0:
            reasons.append(
                "ICMP"
            )

    except Exception:
        pass

    # SNMP
    if not reasons:

        try:

            probe, _ = snmp_get(
                ip,
                city,
                [
                    STANDARD_OIDS[
                        "sysObjectID"
                    ]
                ],
            )

            if probe:

                reasons.append(
                    "SNMP"
                )

        except Exception:
            pass

    return reasons


# =============================================================================
# ROUTEROS API
# =============================================================================

def normalize_api_data(
    api_data: dict[str, Any] | None,
) -> dict[str, Any]:

    if not api_data:
        return {}

    out = {}

    def field(
        obj,
        *names,
    ):

        for name in names:

            if name in obj:

                value = s(
                    obj.get(
                        name
                    )
                )

                if value:
                    return value

        return ""

    for src, dst in (
        (
            "hostname",
            "hostname",
        ),
        (
            "routeros_version",
            "routeros_version",
        ),
        (
            "uptime",
            "uptime",
        ),
        (
            "cpu_load",
            "cpu_load",
        ),
        (
            "model",
            "model",
        ),
        (
            "serial_number",
            "serial_number",
        ),
        (
            "firmware_version",
            "firmware_version",
        ),
        (
            "interface_name",
            "interface_name",
        ),
    ):

        value = s(
            api_data.get(
                src
            )
        )

        if value:
            out[
                dst
            ] = value

    if (
        s(
            api_data.get(
                "board_name"
            )
        )
        and not s(
            out.get(
                "model"
            )
        )
    ):

        out[
            "model"
        ] = s(
            api_data[
                "board_name"
            ]
        )

    total = numeric_value(
        api_data.get(
            "memory_total"
        )
    )

    free = numeric_value(
        api_data.get(
            "memory_free"
        )
    )

    if (
        total is not None
        and free is not None
        and total > 0
    ):

        out[
            "memory_usage"
        ] = (
            f"{max(0.0, (1.0 - free / total) * 100.0):.1f}%"
        )

    if s(
        api_data.get(
            "temperature"
        )
    ):

        out[
            "temperature"
        ] = s(
            api_data[
                "temperature"
            ]
        )

    if s(
        api_data.get(
            "cpu_temperature"
        )
    ):

        out[
            "cpu_temperature"
        ] = s(
            api_data[
                "cpu_temperature"
            ]
        )

    radio = (
        api_data.get(
            "radio"
        )
        or {}
    )

    if isinstance(
        radio,
        list,
    ):

        radio = (
            radio[0]
            if radio
            else {}
        )

    if not isinstance(
        radio,
        dict,
    ):

        radio = {}

    mappings = {

        "ssid":
            (
                "ssid",
                "ssid-name",
                "network-name",
            ),

        "frequency":
            (
                "frequency",
                "freq",
            ),

        "channel":
            (
                "channel",
                "channel-id",
                "channel-number",
            ),

        "bandwidth":
            (
                "bandwidth",
                "channel-width",
                "channel-widths",
            ),

        "mode":
            (
                "mode",
                "station-mode",
            ),

        "wireless_status":
            (
                "status",
                "state",
                "wireless-status",
            ),

        "tx_power":
            (
                "tx-power",
                "tx-power-current",
            ),

        "rx_power":
            (
                "rx-power",
                "receive-power",
            ),

        "signal_strength":
            (
                "signal-strength",
                "signal",
                "rx-signal",
            ),

        "peer_tx_signal":
            (
                "tx-signal",
                "peer-tx-signal",
                "remote-signal",
            ),

        "tx_rate":
            (
                "tx-rate",
                "tx-rate-set",
                "tx-rates",
            ),

        "rx_rate":
            (
                "rx-rate",
                "rx-rate-set",
                "rx-rates",
            ),

        "ccq":
            (
                "ccq",
                "overall-ccq",
            ),

        "tx_ccq":
            (
                "tx-ccq",
            ),

        "rx_ccq":
            (
                "rx-ccq",
            ),

        "snr":
            (
                "snr",
                "signal-to-noise",
            ),

        "noise_floor":
            (
                "noise-floor",
                "noise",
            ),

        "radio_name":
            (
                "interface",
                "interface-name",
                "name",
            ),
    }

    for dst, aliases in mappings.items():

        value = field(
            radio,
            *aliases,
        )

        if value:
            out[
                dst
            ] = value

    if (
        not s(
            out.get(
                "interface_name"
            )
        )
        and s(
            api_data.get(
                "interface_name"
            )
        )
    ):

        out[
            "interface_name"
        ] = s(
            api_data[
                "interface_name"
            ]
        )

    if (
        not s(
            out.get(
                "radio_name"
            )
        )
        and s(
            out.get(
                "interface_name"
            )
        )
    ):

        out[
            "radio_name"
        ] = out[
            "interface_name"
        ]

    return out


# =============================================================================
# SCAN ONE
# =============================================================================

def scan_one(
    item: dict[str, Any],
) -> dict[str, Any]:

    ip = item[
        "ip_address"
    ]

    city = item[
        "city"
    ]

    result = {
        "ip_address":
            ip,

        "city_id":
            city["id"],

        "city_name":
            city["name"],

        "status":
            "failed",

        "stage":
            "precheck",

        "reason":
            "",

        "snapshot":
            {},
    }

    if is_blacklisted(
        ip
    ):

        result.update(
            status="blacklisted",
            stage="target",
            reason="IP or CIDR is blacklisted",
        )

        return result

    checks = precheck(
        ip,
        city,
    )

    result[
        "precheck"
    ] = checks

    if not checks:

        result.update(
            status="not_alive",
            reason="No response on SNMP/API/SSH/ICMP",
        )

        return result

    before = get_device(
        ip
    )

    data = {
        "ip_address":
            ip,

        "city_id":
            city["id"],

        "city":
            city["name"],

        "scan_status":
            "success",
    }

    sn = snmp_collect(
        ip,
        city,
    )

    merge_nonempty(
        data,
        {
            k: v
            for k, v
            in sn.items()
            if k
            not in {
                "snmp_raw",
                "snmp_community",
                "snmp_vendor_raw",
            }
        },
    )

    # Direct vendor fallback
    if not data.get(
        "device_type"
    ):

        try:

            object_id = s(
                sn.get(
                    "snmp_raw",
                    {}
                ).get(
                    "sysObjectID"
                )
            )

            generation = (
                racom_generation_from_oid(
                    object_id
                )
            )

            if generation:

                direct_vendor = (
                    racom_vendor_collect(
                        ip,
                        city,
                        object_id,
                    )
                )

                if direct_vendor:

                    merge_nonempty(
                        data,
                        direct_vendor,
                        preserve={
                            "racom_snmp",
                            "racom_generation",
                        },
                    )

                    data[
                        "device_type"
                    ] = "Racom"

                    data[
                        "vendor"
                    ] = "Racom"

                    data[
                        "snmp_vendor_raw"
                    ] = direct_vendor

        except Exception as exc:

            LOG.debug(
                "Direct vendor fallback %s failed: %s",
                ip,
                exc,
            )

    snmp_only_vendor = (
        data.get(
            "device_type"
        )
        in {
            "Mimosa",
            "Racom",
        }
        or data.get(
            "vendor"
        )
        in {
            "Mimosa",
            "Racom",
        }
    )

    api_data = {}

    # RouterOS API only for MikroTik.
    if (
        not snmp_only_vendor
        and int(
            city.get(
                "api_enabled",
                1,
            )
        )
        and int(
            city.get(
                "api_ssl_enabled",
                0,
            )
        )
        == 0
    ):

        creds, _ = city_credentials(
            city
        )

        for cred in creds:

            ac = None

            try:

                ac = RouterOSAPI(
                    ip,
                    cred[
                        "username"
                    ],
                    cred[
                        "password"
                    ],
                    port=int(
                        city[
                            "api_port"
                        ]
                    ),
                    timeout=float(
                        city[
                            "api_timeout"
                        ]
                    ),
                )

                ac.connect()

                api_data = (
                    collect_mikrotik_api(
                        ac
                    )
                )

                data[
                    "api_status"
                ] = "success"

                break

            except Exception as exc:

                data[
                    "api_status"
                ] = (
                    f"failed: {str(exc)[:180]}"
                )

            finally:

                if ac:
                    ac.close()

        merge_nonempty(
            data,
            api_data,
            preserve={
                "api_menus",
                "api_errors",
                "api_source",
                "api_status",
            },
        )

        merge_nonempty(
            data,
            normalize_api_data(
                api_data
            ),
        )

        if (
            not data.get(
                "device_type"
            )
            and (
                api_data.get(
                    "routeros_version"
                )
                or api_data.get(
                    "board_name"
                )
                or api_data.get(
                    "radio"
                )
            )
        ):

            data.update(
                device_type="MikroTik",
                vendor="MikroTik",
            )

    elif data.get(
        "device_type"
    ) == "MikroTik":

        data[
            "api_status"
        ] = "disabled"

    # SSH only for MikroTik/general devices.
    ssh_data = {}

    if snmp_only_vendor:

        data[
            "api_status"
        ] = "not_used_snmp_only"

        data[
            "ssh_status"
        ] = "not_used_snmp_only"

    try:

        if snmp_only_vendor:

            raise RuntimeError(
                "SNMP-only vendor"
            )

        c, method = ssh_connect(
            ip,
            city,
        )

        try:

            identity_probe = ssh_cmd(
                c,
                "/system identity print",
            )

            resource_probe = ssh_cmd(
                c,
                "/system resource print",
            )

            if (
                data.get(
                    "device_type"
                )
                == "MikroTik"
                or "routeros"
                in (
                    resource_probe
                    + identity_probe
                ).lower()
                or "name:"
                in identity_probe.lower()
            ):

                data.update(
                    device_type="MikroTik",
                    vendor="MikroTik",
                )

                ssh_data = ssh_mikrotik(
                    c
                )

            data[
                "ssh_status"
            ] = "success"

            data[
                "credential_id"
            ] = method

        finally:

            c.close()

        fields = (
            "ssid",
            "frequency",
            "channel",
            "bandwidth",
            "mode",
            "radio_name",
            "interface_name",
            "wireless_status",
            "tx_power",
            "rx_power",
            "signal_strength",
            "peer_tx_signal",
            "tx_rate",
            "rx_rate",
            "ccq",
            "tx_ccq",
            "rx_ccq",
            "snr",
            "noise_floor",
            "wireless_registration",
            "interfaces",
            "queues",
            "firewall_counters",
            "pppoe_vpn",
            "ip_routes",
        )

        for f in fields:

            if (
                not s(
                    data.get(f)
                )
                and s(
                    ssh_data.get(f)
                )
            ):

                data[
                    f
                ] = ssh_data[
                    f
                ]

    except Exception as exc:

        data[
            "ssh_status"
        ] = (
            f"failed: {str(exc)[:180]}"
        )

    data[
        "raw_data"
    ] = json.dumps(
        {
            "snmp":
                sn,

            "api":
                api_data,

            "ssh":
                ssh_data,
        },
        ensure_ascii=False,
        default=str,
    )

    protocol_ok = (
        sn.get(
            "snmp_status"
        )
        == "success"

        or bool(
            data.get(
                "snmp_vendor_raw"
            )
        )

        or data.get(
            "device_type"
        )
        in {
            "Mimosa",
            "Racom",
        }

        or data.get(
            "api_status"
        )
        == "success"

        or data.get(
            "ssh_status"
        )
        == "success"
    )

    if not protocol_ok:

        failed_reasons = []

        if (
            sn.get(
                "snmp_status"
            )
            != "success"
        ):

            failed_reasons.append(
                "SNMP failed"
            )

        if data.get(
            "api_status",
            "",
        ).startswith(
            "failed"
        ):

            failed_reasons.append(
                data[
                    "api_status"
                ]
            )

        if data.get(
            "ssh_status",
            "",
        ).startswith(
            "failed"
        ):

            failed_reasons.append(
                data[
                    "ssh_status"
                ]
            )

        reason = (
            "; ".join(
                failed_reasons
            )
            or
            "No usable monitoring protocol responded"
        )

        result.update(
            status="failed",
            stage="collect",
            reason=reason,
            snapshot=data,
            before=before,
            after=None,
        )

        return result

    row = db.upsert_device(
        data
    )

    result.update(
        status="success",
        stage="collect",
        reason="; ".join(
            checks
        ),
        snapshot=row,
        before=before,
        after=row,
    )

    return result


# =============================================================================
# TARGETS
# =============================================================================

def targets(
    city_ids: list[int] | None = None,
):

    cities = [
        c
        for c in list_cities()
        if c["enabled"]
    ]

    selected = set(
        city_ids or []
    )

    if selected:

        cities = [
            c
            for c in cities
            if c["id"]
            in selected
        ]

    out = []
    seen = set()

    all_city_map = {
        int(
            c["id"]
        ):
            c
        for c in list_cities()
    }

    for city in cities:

        try:

            for ip in ipaddress.ip_network(
                city[
                    "cidr"
                ],
                strict=False,
            ).hosts():

                sip = str(
                    ip
                )

                if sip not in seen:

                    seen.add(
                        sip
                    )

                    out.append(
                        {
                            "ip_address":
                                sip,

                            "city":
                                city,
                        }
                    )

        except Exception:
            continue

    # Manual IPs
    for m in list_manual_ips():

        if (
            not m["enabled"]
            or m["ip_address"]
            in seen
        ):
            continue

        assigned = (
            all_city_map.get(
                int(
                    m[
                        "city_id"
                    ]
                )
            )
            if m.get(
                "city_id"
            )
            not in {
                None,
                "",
            }
            else None
        )

        if assigned is None:

            try:

                obj = ipaddress.ip_address(
                    m[
                        "ip_address"
                    ]
                )

                for city in cities:

                    if (
                        obj
                        in ipaddress.ip_network(
                            city[
                                "cidr"
                            ],
                            strict=False,
                        )
                    ):

                        assigned = city
                        break

                if assigned is None:

                    for city in list_cities():

                        if (
                            obj
                            in ipaddress.ip_network(
                                city[
                                    "cidr"
                                ],
                                strict=False,
                            )
                        ):

                            assigned = city
                            break

            except Exception:
                assigned = None

        if assigned is not None:

            out.append(
                {
                    "ip_address":
                        m[
                            "ip_address"
                        ],

                    "city":
                        assigned,
                }
            )

            seen.add(
                m[
                    "ip_address"
                ]
            )

        else:

            out.append(
                {
                    "ip_address":
                        m[
                            "ip_address"
                        ],

                    "city": {

                        "id":
                            None,

                        "name":
                            "Manual",

                        "enabled":
                            1,

                        "ssh_port":
                            int(
                                os.getenv(
                                    "SSH_PORT",
                                    "22",
                                )
                            ),

                        "snmp_port":
                            int(
                                os.getenv(
                                    "SNMP_PORT",
                                    "161",
                                )
                            ),

                        "api_port":
                            int(
                                os.getenv(
                                    "API_PORT",
                                    "8728",
                                )
                            ),

                        "api_enabled":
                            1,

                        "api_ssl_enabled":
                            0,

                        "api_timeout":
                            float(
                                os.getenv(
                                    "API_TIMEOUT",
                                    "4",
                                )
                            ),

                        "snmp_timeout":
                            float(
                                os.getenv(
                                    "SNMP_TIMEOUT",
                                    "2.5",
                                )
                            ),

                        "snmp_retries":
                            int(
                                os.getenv(
                                    "SNMP_RETRIES",
                                    "1",
                                )
                            ),

                        "ssh_timeout":
                            float(
                                os.getenv(
                                    "SSH_TIMEOUT",
                                    "6",
                                )
                            ),

                        "ssh_credentials_json":
                            os.getenv(
                                "SSH_CREDENTIALS_JSON",
                                "[]",
                            ),

                        "snmp_communities_json":
                            json.dumps(
                                [
                                    os.getenv(
                                        "SNMP_COMMUNITY",
                                        "ngstehwl",
                                    )
                                ]
                            ),
                    },
                }
            )

            seen.add(
                m[
                    "ip_address"
                ]
            )

    return out


# =============================================================================
# RUN SCAN
# =============================================================================

def run_scan(
    city_ids: list[int] | None = None,
    started_by: str = "system",
):

    init_db()

    items = targets(
        city_ids
    )

    selected = [
        c["name"]
        for c in list_cities()
        if c["enabled"]
        and (
            not city_ids
            or c["id"]
            in city_ids
        )
    ]

    selection = {
        "mode":
            (
                "all"
                if not city_ids
                else "selected"
            ),

        "city_ids":
            city_ids or [],

        "cities":
            selected,
    }

    scan_id = create_scan(
        selection,
        started_by,
        len(items),
    )

    stats = {
        "found":
            0,

        "success":
            0,

        "failed":
            0,

        "skipped":
            0,
    }

    start = time.time()

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(
            100,
            max(
                1,
                int(
                    os.getenv(
                        "SCAN_WORKERS",
                        "40",
                    )
                ),
            ),
        )
    ) as pool:

        futures = [
            pool.submit(
                scan_one,
                x,
            )
            for x in items
        ]

        for fut in concurrent.futures.as_completed(
            futures
        ):

            try:

                r = fut.result()

            except Exception as exc:

                r = {
                    "ip_address":
                        "?",

                    "status":
                        "failed",

                    "stage":
                        "exception",

                    "reason":
                        str(exc)[:300],

                    "snapshot":
                        {},
                }

            st = r.get(
                "status"
            )

            if st == "success":

                stats[
                    "success"
                ] += 1

                stats[
                    "found"
                ] += 1

            elif st in {
                "not_alive",
                "blacklisted",
                "skipped",
            }:

                stats[
                    "skipped"
                ] += 1

            else:

                stats[
                    "failed"
                ] += 1

                stats[
                    "found"
                ] += 1

            if (
                st == "success"
                and r.get(
                    "ip_address"
                )
                != "?"
            ):

                record_changes(
                    scan_id,
                    r[
                        "ip_address"
                    ],
                    r.get(
                        "before"
                    ),
                    r.get(
                        "after"
                    ),
                )

            add_scan_result(
                scan_id,
                r,
            )

    duration = (
        time.time()
        - start
    )

    finish_scan(
        scan_id,
        stats,
        duration,
    )

    cleanup_retention()

    return {
        "scan_id":
            scan_id,

        "total_ips":
            len(items),

        **stats,

        "duration":
            duration,

        "selection":
            selection,
    }
