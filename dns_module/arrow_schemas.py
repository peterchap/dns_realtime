import pyarrow as pa

# PyArrow Schema for entity_domain
domain_schema = pa.schema([
    ('domain_id', pa.uint64()),        # DuckDB UBIGINT
    ('domain', pa.string()),           # DuckDB VARCHAR
    ('apex', pa.string()),
    ('tld', pa.string()),
    ('first_seen_ts', pa.timestamp('us')), # Microsecond precision for DuckDB
    ('last_seen_ts', pa.timestamp('us')),
    ('source_flags', pa.string())      # Send JSON as a string; DuckDB will auto-cast it
])

# PyArrow Schema for entity_ip
ip_schema = pa.schema([
    ('ip_id', pa.uint64()),
    ('ip', pa.string()),
    ('ip_version', pa.uint8()),        # DuckDB UTINYINT (4 or 6)
    ('first_seen_ts', pa.timestamp('us')),
    ('last_seen_ts', pa.timestamp('us'))
])

# PyArrow Schema for entity_edge
edge_schema = pa.schema([
    ('src_type', pa.string()),         # Send ENUMs as strings; DuckDB casts them on INSERT
    ('src_id', pa.uint64()),
    ('dst_type', pa.string()),
    ('dst_id', pa.uint64()),
    ('edge_type', pa.string()),
    ('first_seen_ts', pa.timestamp('us')),
    ('last_seen_ts', pa.timestamp('us')),
    ('last_observed_ts', pa.timestamp('us')),
    ('attrs', pa.string())             # JSON payload as string
])