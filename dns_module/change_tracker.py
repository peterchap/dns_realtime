# /root/celery_app/dns_module/change_tracker.py
from __future__ import annotations

import hashlib
import time
import os
import csv
from typing import List, Dict, Tuple

import pyarrow as pa

# Reuse the same LMDB wrapper you installed earlier
from kv.lmdb_store import LMDBActivity


# --- DNS signature (must match LMDBActivity._sig) ----------------------------
def dns_sig(ns: str, a: str, mx_regdom: str) -> str:
    ns = (ns or "")
    a  = (a or "")
    mx = (mx_regdom or "")
    h = hashlib.sha1()
    h.update(ns.encode())
    h.update(b"|")
    h.update(a.encode())
    h.update(b"|")
    h.update(mx.encode())
    return "sha1:" + h.hexdigest()


# --- Row-by-row evaluator ----------------------------------------------------
def _row_needs_enrich(
    kv: LMDBActivity,
    domain: str,
    ns: str,
    a: str,
    mx_regdom: str,
    status: str,
    registered_domain: str,
    mx_ips: str,
) -> Tuple[bool, bool, bytes]:
    """
    Returns (needs_enrich, reactivated, new_sig)
      - needs_enrich: True if no prior state OR DNS sig changed OR reactivated
      - reactivated:  True if previous is_active==False and current now active
      - new_sig:      the computed dns_sig for delta file
    """
    cur_active = (str(status or "").upper() != "NXDOMAIN")
    # Compute signature using LMDBActivity's scheme for consistency
    try:
        new = LMDBActivity.compute_signature_values(
            ns=ns,
            a=a,
            mx_regdom=mx_regdom,
            registered_domain=registered_domain or domain,
            mx_ips=mx_ips,
        )
    except Exception:
        # Fallback: compute from dict to be permissive
        new = LMDBActivity.compute_signature_dict({
            "ns": ns,
            "a": a,
            "mx_regdom": mx_regdom,
            "registered_domain": registered_domain or domain,
            "mx_ips": mx_ips,
        })

    prev = kv.get_sig(domain)
    if prev is None:
        # New domain → enrich
        return True, False, new

    # Reactivation
    prev_active = bool(prev.get("is_active", True))
    reactivated = (not prev_active) and cur_active

    # Signature change
    changed  = (prev != new)

    needs = (reactivated or changed or (not prev))
    return needs, reactivated, new


# --- Vectorized annotator over an Arrow table --------------------------------
def annotate_change_flags_arrow(
    table: pa.Table,
    kv: LMDBActivity,
    *,
    domain_col: str = "domain",
    ns_col: str = "ns",
    a_col: str = "a",
    mx_regdom_col: str = "mx_regdom_final",
    status_col: str = "status",
    registered_domain_col: str = "registered_domain",
    mx_ips_col: str = "mx_ips",
) -> Tuple[pa.Table, List[Dict[str, str]]]:
    """
    Adds two bool columns to `table`:
      - needs_enrich
      - reactivated

    Also returns a list of delta dicts to write back to master:
      {domain,is_active,last_seen_ts,dns_sig,mx_regdom,mx_ips}
    """
    # Accept list input by converting to an Arrow Table (supports dicts or objects like DNSRecord)
    if isinstance(table, list):
        if not table:
            # Build an empty Arrow table with required columns and explicit types
            table = pa.Table.from_arrays(
                [
                    pa.array([], type=pa.string()),  # domain
                    pa.array([], type=pa.string()),  # ns
                    pa.array([], type=pa.string()),  # a
                    pa.array([], type=pa.string()),  # mx_regdom_final
                    pa.array([], type=pa.string()),  # status
                    pa.array([], type=pa.string()),  # mx_ips
                ],
                names=[domain_col, ns_col, a_col, mx_regdom_col, status_col, mx_ips_col]
            )
        elif isinstance(table[0], dict):
            keys = set()
            for row in table:
                keys.update(row.keys())
            data = {k: [r.get(k) for r in table] for k in keys}
            table = pa.Table.from_pydict(data)
        else:
            # Attempt to coerce generic objects (e.g., DNSRecord) into the required columns
            def _to_str_join(v):
                if v is None:
                    return ""
                if isinstance(v, list):
                    return "|".join([str(x) for x in v if x is not None])
                return str(v)

            rows: List[Dict[str, str]] = []
            for obj in table:
                try:
                    domain_val = getattr(obj, "domain", None)
                    status_val = getattr(obj, "status", None)
                    records = getattr(obj, "records", None)

                    ns_v = ""
                    a_v = ""
                    mx_v = ""
                    mx_ips_v = ""
                    if isinstance(records, dict):
                        ns_v = _to_str_join(records.get("ns", records.get("ns1")))
                        a_v = _to_str_join(records.get("a"))
                        mx_v = _to_str_join(records.get("mx_regdom_final", records.get("mx_domain")))
                        mx_ips_v = _to_str_join(records.get("mx_ips"))
                    else:
                        ns_v = _to_str_join(getattr(obj, "ns", getattr(obj, "ns1", None)))
                        a_v = _to_str_join(getattr(obj, "a", None))
                        mx_v = _to_str_join(getattr(obj, "mx_regdom_final", getattr(obj, "mx_domain", None)))
                        mx_ips_v = _to_str_join(getattr(obj, "mx_ips", None))

                    row = {
                        domain_col: str(domain_val or "").lower(),
                        ns_col: ns_v,
                        a_col: a_v,
                        mx_regdom_col: str(mx_v or "").lower(),
                        status_col: str(status_val or ""),
                        mx_ips_col: str(mx_ips_v or ""),
                    }
                    rows.append(row)
                except Exception:
                    # Skip un-coercible objects
                    continue

            if not rows:
                raise TypeError("annotate_change_flags_arrow: expected list[dict] or pyarrow.Table-compatible objects")
            table = pa.Table.from_pylist(rows)
    elif not isinstance(table, pa.Table):
        raise TypeError("annotate_change_flags_arrow: expected pyarrow.Table or list[dict]")

    cols = set(table.column_names)
    required = {domain_col, ns_col, a_col, mx_regdom_col, status_col}
    missing = required - cols
    if missing:
        raise ValueError(f"annotate_change_flags_arrow: missing columns: {sorted(missing)}")
    
    # Ensure mx_ips_col exists, defaulting to empty if missing in input table
    if mx_ips_col not in cols:
         table = table.append_column(mx_ips_col, pa.array([""] * table.num_rows, type=pa.string()))

    domains   = table[domain_col].to_pylist()
    ns_vals   = table[ns_col].to_pylist()
    a_vals    = table[a_col].to_pylist()
    mx_vals   = table[mx_regdom_col].to_pylist()
    statuses  = table[status_col].to_pylist()
    regdoms   = table[registered_domain_col].to_pylist() if registered_domain_col in cols else [None] * len(domains)
    mx_ips_vals = table[mx_ips_col].to_pylist()

    needs_list: List[bool] = []
    react_list: List[bool] = []
    deltas: List[Dict[str, str]] = []

    now_ts = int(time.time())

    for domain, ns, a, mxreg, status, regdom, mx_ips in zip(domains, ns_vals, a_vals, mx_vals, statuses, regdoms, mx_ips_vals):
        domain = (domain or "").lower()
        ns = ns or ""
        a  = a or ""
        mxreg = (mxreg or "").lower()
        status = status or ""
        regdom = (regdom or "").lower() or domain
        mx_ips = mx_ips or ""

        needs, reactivated, new = _row_needs_enrich(
            kv=kv,
            domain=domain,
            ns=ns,
            a=a,
            mx_regdom=mxreg,
            status=status,
            registered_domain=regdom,
            mx_ips=mx_ips,
        )
        needs_list.append(needs)
        react_list.append(reactivated)

        # Only emit delta when something actually changed (or it's new/reactivated)
        if needs:
            is_active_now = (str(status).upper() != "NXDOMAIN")
            deltas.append({
                "domain":        domain,
                "is_active":     "true" if is_active_now else "false",
                "last_seen_ts":  str(now_ts),
                "dns_sig":       (new.decode("ascii", "ignore") if isinstance(new, (bytes, bytearray)) else str(new)),
                "mx_regdom":     mxreg,
                "mx_ips":        mx_ips,
            })

    needs_arr = pa.array(needs_list, type=pa.bool_())
    react_arr = pa.array(react_list, type=pa.bool_())

    if "needs_enrich" in cols:
        table = table.set_column(table.schema.get_field_index("needs_enrich"), "needs_enrich", needs_arr)
    else:
        table = table.append_column("needs_enrich", needs_arr)

    if "reactivated" in cols:
        table = table.set_column(table.schema.get_field_index("reactivated"), "reactivated", react_arr)
    else:
        table = table.append_column("reactivated", react_arr)

    return table, deltas


# --- Delta writer -------------------------------------------------------------
def write_activity_delta_csv(deltas: List[Dict[str, str]], out_path: str) -> None:
    """
    Append (create if missing) CSV with:
      domain,is_active,last_seen_ts,dns_sig,mx_regdom,mx_ips
    """
    if not deltas:
        return
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    exists = os.path.exists(out_path)
    with open(out_path, "a", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["domain","is_active","last_seen_ts","dns_sig","mx_regdom","mx_ips"])
        if not exists:
            w.writeheader()
        for row in deltas:
            w.writerow(row)