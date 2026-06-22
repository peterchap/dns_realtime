import xxhash
import ipaddress
import idna

def _generate_ubigint(normalized_string: str) -> int:
    """Core function: Returns a strict unsigned 64-bit integer."""
    # .intdigest() natively returns a 64-bit integer compatible with DuckDB's UBIGINT
    return xxhash.xxh64(normalized_string.encode('utf-8')).intdigest()

def hash_domain(domain: str) -> int:
    """
    Normalizes domains to lowercase punycode.
    Converts 'München.de' -> 'xn--mnchen-3ya.de' -> hashes it.
    """
    try:
        # 1. Strip whitespace
        # 2. Convert to punycode (handles internationalized domains)
        # 3. Force lowercase
        normalized = idna.encode(domain.strip()).decode('utf-8').lower()
        return _generate_ubigint(normalized)
    except idna.IDNAError:
        # Fallback for malformed junk domains from CT logs
        return _generate_ubigint(domain.strip().lower())

def hash_ip(ip_str: str) -> int:
    """
    Normalizes IPs.
    CRITICAL FOR IPv6: Ensures '2001:db8::1' and '2001:0db8:0:0:0:0:0:1' 
    produce the exact same hash.
    """
    try:
        # ipaddress module natively standardizes formatting
        normalized = ipaddress.ip_address(ip_str.strip()).compressed
        return _generate_ubigint(normalized)
    except ValueError:
        return _generate_ubigint(ip_str.strip())

def hash_prefix(prefix_str: str) -> int:
    """Normalizes CIDR prefixes (e.g. 1.2.3.0/24)."""
    try:
        normalized = str(ipaddress.ip_network(prefix_str.strip(), strict=False))
        return _generate_ubigint(normalized)
    except ValueError:
        return _generate_ubigint(prefix_str.strip())

def hash_asn(asn: int) -> int:
    """
    ASNs can be their own ID, but hashing 'AS12345' ensures it fits 
    the UBIGINT namespace perfectly alongside other entities.
    """
    normalized = f"AS{asn}"
    return _generate_ubigint(normalized)

def hash_cert(sha256_fingerprint: str) -> int:
    """Normalizes cert fingerprints."""
    # Remove spaces/colons commonly found in copy-pasted fingerprints
    normalized = sha256_fingerprint.strip().replace(':', '').replace(' ', '').lower()
    return _generate_ubigint(normalized)

def hash_jarm(jarm_str: str) -> int:
    """Normalizes JARM strings."""
    return _generate_ubigint(jarm_str.strip().lower())

def hash_observation(source: str, entity_id: int, timestamp: float) -> int:
    """
    Generates a unique, reproducible ID for raw evidence logs.
    Useful for deduplicating feed imports.
    """
    normalized = f"{source}_{entity_id}_{int(timestamp)}"
    return _generate_ubigint(normalized)