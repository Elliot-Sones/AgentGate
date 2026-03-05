from __future__ import annotations

from agentgate.trust.runtime.docker_runner import (
    _decode_ipv4_hex,
    _decode_ipv6_hex,
    _parse_proc_remote_ips,
)


def test_decode_ipv4_hex_little_endian() -> None:
    # /proc/net stores IPv4 values in little-endian hex format.
    assert _decode_ipv4_hex("08080808") == "8.8.8.8"
    assert _decode_ipv4_hex("0100007F") == "127.0.0.1"


def test_parse_proc_remote_ips_filters_loopback_and_zero_ports() -> None:
    sample = """
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 08080808:0050 01 00000000:00000000 00:00000000 00000000   100        0 0
   1: 0100007F:1F90 0100007F:0050 01 00000000:00000000 00:00000000 00000000   100        0 0
   2: 0100007F:1F90 04030201:0000 01 00000000:00000000 00:00000000 00000000   100        0 0
"""
    assert _parse_proc_remote_ips(sample) == {"8.8.8.8"}


def test_decode_ipv6_hex_roundtrip() -> None:
    # Encoded form of 2001:db8::1 in /proc tcp6/udp6 representation.
    assert _decode_ipv6_hex("b80d0120000000000000000001000000") == "2001:db8::1"


def test_parse_proc_remote_ips_includes_ipv6() -> None:
    sample = """
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:1F90 b80d0120000000000000000001000000:0050 01 00000000:00000000 00:00000000 00000000   100        0 0
"""
    assert _parse_proc_remote_ips(sample) == {"2001:db8::1"}
