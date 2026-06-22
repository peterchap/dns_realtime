# /root/dnsproject/dns_module/smtp_banner_fetcher.py

from __future__ import annotations
import asyncio
from typing import Optional

DEFAULT_PORT = 25
CONNECT_TIMEOUT = 4.0
READ_TIMEOUT = 3.0
BANNER_MAX_BYTES = 2048

async def fetch_smtp_banner(host: str, port: int = DEFAULT_PORT) -> Optional[str]:
    if not host:
        return None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host=host, port=port, ssl=None),
            timeout=CONNECT_TIMEOUT
        )
    except Exception:
        return None
    try:
        data = await asyncio.wait_for(reader.read(BANNER_MAX_BYTES), timeout=READ_TIMEOUT)
        # Close immediately; we only want the banner line.
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        if not data:
            return None
        text = data.decode(errors="ignore").strip()
        for line in text.splitlines():
            if line.strip().lower().startswith("220"):
                return line.strip()
        return None
    except Exception:
        try:
            writer.close()
        except Exception:
            pass
        return None

