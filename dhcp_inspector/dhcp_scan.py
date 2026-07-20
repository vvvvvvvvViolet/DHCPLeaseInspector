"""Broadcasts a DHCPDISCOVER and collects offers from any DHCP server on the LAN.

Pure-stdlib implementation (no scapy/npcap dependency). Because the Windows
"DHCP Client" service normally owns UDP port 68, this scan should be run
from an elevated (Administrator) prompt; if the port is already in use the
scan raises a RuntimeError with guidance instead of failing silently.
"""
import random
import socket
import struct
import time

_CLIENT_PORT = 68
_SERVER_PORT = 67
_MAGIC_COOKIE = bytes.fromhex("63825363")


def _build_discover(xid: int, mac: bytes) -> bytes:
    packet = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        1,          # op: BOOTREQUEST
        1,          # htype: Ethernet
        6,          # hlen
        0,          # hops
        xid,
        0,          # secs
        0x8000,     # flags: broadcast
        b"\x00\x00\x00\x00",  # ciaddr
        b"\x00\x00\x00\x00",  # yiaddr
        b"\x00\x00\x00\x00",  # siaddr
        b"\x00\x00\x00\x00",  # giaddr
        mac.ljust(16, b"\x00"),
        b"\x00" * 64,
        b"\x00" * 128,
    )
    options = _MAGIC_COOKIE
    options += bytes([53, 1, 1])       # DHCP Message Type = DISCOVER
    options += bytes([55, 3, 1, 3, 6])  # Parameter request list: subnet, router, DNS
    options += bytes([255])             # End
    return packet + options


def _random_mac() -> bytes:
    return bytes([0x02] + [random.randint(0, 255) for _ in range(5)])


def scan_for_dhcp_servers(timeout: float = 5.0) -> list[dict]:
    """Send a DHCPDISCOVER broadcast and return the offers received.

    Each result contains: server_ip, offered_ip.
    """
    xid = random.randint(0, 0xFFFFFFFF)
    mac = _random_mac()
    discover = _build_discover(xid, mac)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    try:
        sock.bind(("", _CLIENT_PORT))
    except OSError as exc:
        sock.close()
        raise RuntimeError(
            "Could not bind UDP port 68 (owned by the Windows DHCP Client "
            "service). Run this scan as Administrator, or temporarily stop "
            "the 'Dhcp' service before scanning."
        ) from exc

    offers = []
    try:
        sock.sendto(discover, ("255.255.255.255", _SERVER_PORT))
        sock.settimeout(0.5)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            if len(data) < 240:
                continue
            reply_xid = struct.unpack("!I", data[4:8])[0]
            if reply_xid != xid:
                continue
            offered_ip = socket.inet_ntoa(data[16:20])
            offers.append({"server_ip": addr[0], "offered_ip": offered_ip})
    finally:
        sock.close()

    return offers
