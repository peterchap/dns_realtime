"""
Deprecated module: dns_query

This module is no longer used in the main DNS fetch pipeline.
Please use the consolidated resolver and typed helpers in dns_lookup instead.

Keeping this stub to avoid import errors; any attempt to instantiate DNSQuery
will raise a clear exception directing developers to dns_lookup.
"""

from typing import Optional, List, Tuple, Union, Any, cast


class DNSQuery:
    def __init__(self, domain: str, fallback_resolvers: Optional[List[str]] = None):
        raise RuntimeError(
            "dns_query.DNSQuery is deprecated. Use dns_module.dns_lookup instead (lookup_* helpers)."
        )

    async def query(self, domain: str, query_type: str) -> Tuple[Optional[Union[List, object]], str]:
        raise RuntimeError(
            "dns_query.DNSQuery is deprecated. Use dns_module.dns_lookup.perform_lookup or typed helpers."
        )

    async def get_A(self) -> Tuple[str, str, int, str, bool, int]:
        raise RuntimeError(
            "dns_query.DNSQuery is deprecated. Use dns_module.dns_lookup.lookup_a / resolve helpers."
        )

    async def has_dnssec(self, query_type: str) -> bool:
        """
        Check if DNSSEC is enabled for this domain.
        Note: RRSIG queries may not be supported by all resolvers.
        """
        raise RuntimeError(
            "dns_query.DNSQuery is deprecated. Use dns_module.dns_lookup.dnssec helpers."
        )

    async def get_NS(self) -> Tuple[str, str]:
        raise RuntimeError("dns_query is deprecated")

    async def get_CNAME(self) -> str:
        raise RuntimeError("dns_query is deprecated")

    async def get_AAAA(self) -> Tuple[str, str]:
        raise RuntimeError("dns_query is deprecated")

    async def get_SOA(self) -> Tuple[str, str]:
        raise RuntimeError("dns_query is deprecated")

    async def get_MX(self) -> Tuple[str, str, str, str]:
        raise RuntimeError("dns_query is deprecated")

    async def get_ptr(self, ip: str) -> str:
        raise RuntimeError("dns_query is deprecated")

    async def get_TXT(self, domain: str) -> List[str]:
        raise RuntimeError("dns_query is deprecated")

    async def get_SPF(self) -> str:
        raise RuntimeError("dns_query is deprecated")

    async def get_DMARC(self) -> str:
        raise RuntimeError("dns_query is deprecated")

    async def get_BIMI(self) -> str:
        raise RuntimeError("dns_query is deprecated")
