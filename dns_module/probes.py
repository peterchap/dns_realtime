"""
dns_module/probes.py

Blocking socket probes for HTTPS certs and SMTP STARTTLS certs.

This module intentionally exposes a small, well-defined async API that is
safe to call from an asyncio program: all blocking socket/ssl work is run
in a thread via asyncio.to_thread and bounded by asyncio.wait_for.

Functions:
- probe_https_cert(host, port=443, ips=None, connect_timeout=2.0, probe_timeout=5.0)
    -> (ok: bool, days_left: Optional[int], issuer: Optional[str], san_count: Optional[int])

- probe_smtp_starttls_cert(host, port=25, ips=None, connect_timeout=2.0, probe_timeout=5.0)
    -> (ok: bool, days_left: Optional[int], issuer: Optional[str])

Notes:
- If you already have resolved IPs (from DNSLookup.resolve_a_aaaa), pass them as `ips`
  to avoid the blocking getaddrinfo call. If ips is None, socket.create_connection(host, ...)
  will be used in the thread (may block due to getaddrinfo).
- These functions swallow errors and return safe defaults on failure.
"""
from __future__ import annotations
import asyncio
import socket
import ssl
import datetime
from typing import Optional, Tuple, Sequence


def _parse_cert_from_sock(sock) -> Tuple[bool, Optional[int], Optional[str], Optional[int]]:
    """Parse peer cert from an already-SSL-wrapped socket object."""
    try:
        cert = sock.getpeercert()
    except Exception:
        return False, None, None, None
    if not cert:
        return False, None, None, None

    # expiry
    exp_str = cert.get("notAfter")
    days_left = None
    if exp_str:
        try:
            dt = datetime.datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (dt - datetime.datetime.utcnow()).days
        except Exception:
            days_left = None

    # issuer
    issuer_tuples = cert.get("issuer", []) or []
    try:
        issuer = ", ".join("=".join(x) for part in issuer_tuples for x in part) if issuer_tuples else None
    except Exception:
        issuer = None

    # SAN count
    san = cert.get("subjectAltName", []) or []
    san_count = len(san) if san else 0

    return True, days_left, issuer, san_count


async def probe_https_cert(
    host: str,
    port: int = 443,
    ips: Optional[Sequence[str]] = None,
    connect_timeout: float = 2.0,
    probe_timeout: float = 5.0,
) -> Tuple[bool, Optional[int], Optional[str], Optional[int]]:
    """
    Probe host:port, open TLS and parse leaf cert.

    - If `ips` is provided, the first IP will be tried (avoids getaddrinfo).
    - All blocking work runs in a thread and is bounded by `probe_timeout`.
    - Returns (ok, days_left, issuer, san_count). On failure returns (False, None, None, None).
    """
    def _connect_and_parse(ip_addr: str):
        ctx = ssl.create_default_context()
        with socket.create_connection((ip_addr, port), timeout=connect_timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return _parse_cert_from_sock(ssock)

    def _get_host_and_parse():
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=connect_timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return _parse_cert_from_sock(ssock)

    try:
        if ips:
            try:
                return await asyncio.wait_for(asyncio.to_thread(_connect_and_parse, ips[0]), timeout=probe_timeout)
            except Exception:
                # fallthrough to host-based attempt
                pass
        # host-based attempt (may block inside thread due to getaddrinfo)
        return await asyncio.wait_for(asyncio.to_thread(_get_host_and_parse), timeout=probe_timeout)
    except asyncio.TimeoutError:
        return False, None, None, None
    except Exception:
        return False, None, None, None


async def probe_smtp_starttls_cert(
    host: str,
    port: int = 25,
    ips: Optional[Sequence[str]] = None,
    connect_timeout: float = 2.0,
    probe_timeout: float = 5.0,
) -> Tuple[bool, Optional[int], Optional[str]]:
    """
    Connect to SMTP host, issue EHLO and STARTTLS, parse cert.

    - If `ips` provided the first IP will be tried first.
    - Returns (ok, days_left, issuer). On failure returns (False, None, None).
    """
    def _smtp_with_ip(ip_addr: str):
        s = socket.create_connection((ip_addr, port), timeout=connect_timeout)
        f = s.makefile("rb", buffering=0)
        try:
            # read banner (may be bytes)
            try:
                _ = f.readline()
            except Exception:
                pass
            try:
                s.sendall(b"EHLO probe.example\r\n")
            except Exception:
                pass
            try:
                # read some server response/caps (best-effort)
                _ = f.read(8192)
            except Exception:
                pass
            try:
                s.sendall(b"STARTTLS\r\n")
            except Exception:
                pass
            try:
                _ = f.readline()
            except Exception:
                pass
            ctx = ssl.create_default_context()
            ssock = ctx.wrap_socket(s, server_hostname=host)
            ok, days, issuer, _san = _parse_cert_from_sock(ssock)
            try:
                ssock.close()
            except Exception:
                pass
            return ok, days, issuer
        finally:
            try:
                s.close()
            except Exception:
                pass

    def _smtp_get_host():
        s = socket.create_connection((host, port), timeout=connect_timeout)
        f = s.makefile("rb", buffering=0)
        try:
            try:
                _ = f.readline()
            except Exception:
                pass
            try:
                s.sendall(b"EHLO probe.example\r\n")
            except Exception:
                pass
            try:
                # read some server response/caps (best-effort)
                _ = f.read(8192)
            except Exception:
                pass
            try:
                s.sendall(b"STARTTLS\r\n")
            except Exception:
                pass
            try:
                _ = f.readline()
            except Exception:
                pass
            ctx = ssl.create_default_context()
            ssock = ctx.wrap_socket(s, server_hostname=host)
            ok, days, issuer, _san = _parse_cert_from_sock(ssock)
            try:
                ssock.close()
            except Exception:
                pass
            return ok, days, issuer
        finally:
            try:
                s.close()
            except Exception:
                pass

    try:
        if ips:
            try:
                return await asyncio.wait_for(asyncio.to_thread(_smtp_with_ip, ips[0]), timeout=probe_timeout)
            except Exception:
                pass
        return await asyncio.wait_for(asyncio.to_thread(_smtp_get_host), timeout=probe_timeout)
    except asyncio.TimeoutError:
        return False, None, None
    except Exception:
        return False, None, None
