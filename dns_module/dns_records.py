# /dnsproject/dns_module/dns_records.py
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
import datetime

@dataclass
class DNSRecords:
    # --- Core domain identity ---
    domain: str
    registered_domain: str

    # --- Core DNS records ---
    ns1: str
    soa: str
    status: str
    ns_error: str
    soa_error: str
    a_error: str
    a: str
    aaaa: str
    ip_int: Optional[int]
    a_ttl: Optional[int]
    ptr: str
    cname: str

    # --- MX records ---
    mx: str
    mx_domain: str
    mx_tld: str
    mx_priority: Optional[int]
    mx_host_final: str
    mx_regdom_final: str
    mx_cname_chain: List[str]
    mx_under_customer: bool
    mx_ips: List[str]
    mx_ptr: str
    mx_ptr_regdom: str

    # --- TXT policies ---
    spf: str
    dmarc: str
    bimi: str

    

    # --- WWW subdomain ---
    www: str
    www_a: str
    www_int: Optional[int]
    www_ptr: str
    www_cname: str

    # --- Mail subdomain ---
    mail_a: str
    mail_int: Optional[int]
    mail_ptr: str
    mail_cname: str
    mail_mx: str
    mail_mx_domain: str
    mail_mx_tld: str
    mail_spf: str
    mail_dmarc: str
    mail_mx_banner_raw: str
    mail_mx_banner_host: str
    mail_mx_banner_details: str
    mail_mx_banner_provider: str
    mail_mx_banner_category: str

    # MTA-STS / TLS-RPT
    has_mta_sts: bool
    mta_sts_txt: str             # raw TXT at _mta-sts.<regdom> (or "")
    mta_sts_mode: str            # "", "none", "testing", "enforce"
    mta_sts_max_age: int | None  # seconds (policy), or None
    mta_sts_id: str | None
    tlsrpt_rua: str              # raw rua from _smtp._tls.<regdom> (or "")

    # SMTP STARTTLS cert (primary MX host — only if mx_under_customer or explicitly enabled)
    smtp_cert_ok: bool | None
    smtp_cert_days_left: int | None
    smtp_cert_issuer: str | None

    # HTTPS cert (apex + www)
    https_cert_ok: bool | None
    https_cert_days_left: int | None
    https_cert_issuer: str | None
    https_cert_san_count: int | None

    # --- SMTP banner (MX) ---
    mx_banner_raw: Optional[str]
    mx_banner_host: Optional[str]
    mx_banner_details: Optional[str]
    mx_banner_provider: Optional[str]
    mx_banner_category: Optional[str]
    
    # --- Zone-level metadata ---
    dnssec: bool
    soa_serial: Optional[int]

    # --- Timestamp ---
    refresh_date: datetime.datetime

    # --- Additional DNS records ---
    # Joined string representations for quick scanning
    caa: str = ""
    naptr: str = ""
    srv: str = ""
    # Structured lists capturing detailed record values
    caa_records: List[Dict[str, Any]] = field(default_factory=list)
    naptr_records: List[Dict[str, Any]] = field(default_factory=list)
    srv_records: List[Dict[str, Any]] = field(default_factory=list)

    # --- TTLs for grouped records ---
    aaaa_ttl: Optional[int] = None
    mx_ttl: Optional[int] = None
    txt_ttl: Optional[int] = None
    caa_ttl: Optional[int] = None
    naptr_ttl: Optional[int] = None


@dataclass
class DNSRecord:
    """
    DNSRecord dataclass representing the result of a domain DNS fetch.
    
    Attributes:
        domain: The queried domain name.
        status: One of 'alive', 'dormant', 'needs_retry', 'error'.
        records: Dictionary of DNS record types to their values.
        errors: Dictionary of record types to error messages.
        meta: Metadata about the lookup (core_rcodes, score, labels, etc.).
    """
    domain: str
    status: str  # 'alive', 'dormant', 'needs_retry', 'error'
    records: Dict[str, Any] = field(default_factory=dict)
    errors: Dict[str, str] = field(default_factory=dict)
    meta: Dict[str, Any] = field(default_factory=dict)
