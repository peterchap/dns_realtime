# /root/dnsproject/dns_module/dns_application.py
from __future__ import annotations
import asyncio
import dns.asyncresolver
import os
import pyarrow as pa
import pyarrow.parquet as pq
import traceback
from dotenv import load_dotenv
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from .chunked_tld_processor import ChunkedTLDProcessor
from .batch_processor import BatchProcessor
from . import dns_lookup
from .logger import configure_logging
from .config import CONFIG

# Load environment variables from the project .env (celery_app/.env) explicitly,
# falling back to current working directory .env if not found.
try:
    _ENV_PATH = Path(__file__).resolve().parents[1] / ".env"
    if _ENV_PATH.exists():
        load_dotenv(dotenv_path=str(_ENV_PATH))
    else:
        load_dotenv()
except Exception:
    load_dotenv()

# ---------------------------------------------------------------------
# Centralized logging (one-time)
# ---------------------------------------------------------------------
app_logger = configure_logging(app_name="dns_app")
app_logger.info("DNS Application logger configured.")
CONFIG.log_config(app_logger)

def get_logger():
    """Return the bound application logger for other modules to import."""
    return app_logger

def _detect_nfs_base() -> Path:
    # Keep this trivial here; change if your environment needs a different mount.
    return Path(os.getenv("NFS_BASE", "/mnt/shared"))

# ---------------------------------------------------------------------
# DNSApplication: orchestrates reading input, grouping domains and
# creating per-TLD BatchProcessor instances. It centralizes resolver
# & semaphore configuration by delegating to dns_lookup.
# ---------------------------------------------------------------------
class DNSApplication:
    """
    Orchestrates reading one input parquet (via relative file_key, e.g. 'inprogress/part-0001.parquet'),
    splitting domains by TLD, and running one BatchProcessor per TLD group with the configured rate.
    """

    def __init__(
        self,
        directory: str,
        file_key: str,
        input_directory: Optional[str] = None,
        output_directory: Optional[str] = None,
        retry_directory: Optional[str] = None,
        tld_rate_limits: Optional[Dict[str, int]] = None,
        nameservers: Optional[List[str]] = None,
    ):
        nfs_base = _detect_nfs_base()

        self.directory = directory
        self.file_key = file_key  # relative: e.g. 'inprogress/part-0001.parquet'
        self.input_directory = input_directory or (str(nfs_base) + "/")
        self.output_directory = output_directory or self.directory
        self.retry_directory = retry_directory or (str(nfs_base) + "/retries/")

        # Per-TLD limits from CONFIG unless overridden
        self.tld_rate_limits = tld_rate_limits or CONFIG.tld_rate_limits

        # Nameservers default from CONFIG unless overridden
        self.nameservers = nameservers if nameservers is not None else CONFIG.nameservers

        # Ensure dns_lookup uses the same application logger if dns_lookup supports a setter.
        try:
            if hasattr(dns_lookup, "set_logger"):
                dns_lookup.set_logger(app_logger)
        except Exception:
            app_logger.exception("Failed to inject logger in dns_lookup; continuing with default logging")

        # Configure resolver centrally via dns_lookup
        try:
            if hasattr(dns_lookup, "set_default_resolver"):
                resolver = dns.asyncresolver.Resolver()
                resolver.nameservers = self.nameservers
                resolver.timeout = CONFIG.timeout_s
                resolver.lifetime = CONFIG.lifetime_s
                dns_lookup.set_default_resolver(resolver)
                self.resolver = dns_lookup.get_default_resolver()
            else:
                self.resolver = dns_lookup.get_default_resolver(nameservers=self.nameservers)
        except Exception:
            app_logger.exception("Failed to configure resolver via dns_lookup; attempting fallback resolver")
            resolver = dns.asyncresolver.Resolver()
            resolver.nameservers = self.nameservers
            resolver.timeout = CONFIG.timeout_s
            resolver.lifetime = CONFIG.lifetime_s
            self.resolver = resolver

        # Configure semaphore centrally
        try:
            if hasattr(dns_lookup, "set_default_semaphore"):
                dns_lookup.set_default_semaphore(limit=CONFIG.semaphore_limit)
            # Obtain the semaphore to pass down to processors (ensures shared throttle)
            self.semaphore = dns_lookup.default_semaphore(CONFIG.semaphore_limit)
            try:
                app_logger.info("Configured semaphore limit: {} | nameservers: {}", CONFIG.semaphore_limit, self.nameservers)
            except Exception:
                pass
        except Exception:
            app_logger.exception("Failed to configure/obtain default semaphore from dns_lookup; creating local semaphore")
            self.semaphore = asyncio.Semaphore(CONFIG.semaphore_limit)

        # Configure global QPS limiter (token bucket) if enabled
        try:
            if hasattr(dns_lookup, "configure_rate_limiter"):
                if getattr(CONFIG, "enable_global_rate_limit", True):
                    dns_lookup.configure_rate_limiter(CONFIG.global_qps)
                    app_logger.info("Configured global QPS limit: {}", CONFIG.global_qps)
                else:
                    app_logger.info("Global QPS limiter disabled by config")
        except Exception:
            app_logger.exception("Failed to configure global QPS limiter")

        # LMDB initialization will be done in run_dns so we can pick a path relative to self.directory if needed.

    # ---- prioritization knobs (keep simple; you can replace) ----
    @staticmethod
    def _is_high_risk(domain: str) -> bool:
        try:
            suffix = domain.rsplit(".", 1)[-1].lower()
        except Exception:
            suffix = ""
        return suffix in {"tk","ml","ga","gq","pw","cn","xyz",
                          "top","click","buzz","win","top",
                          "site","club","icu","bid","cam",
                          "date","monster","quest","xin"}

    @staticmethod
    def _group_domains_by_tld(domains: List[str]) -> Dict[str, List[str]]:
        buckets: Dict[str, List[str]] = {
            "highrisk": [domain for domain in domains if DNSApplication._is_high_risk(domain)],
            "uk": [domain for domain in domains if domain.endswith(".uk")],
            "de": [domain for domain in domains if domain.endswith(".de")],
            "com": [domain for domain in domains if domain.endswith(".com") or domain.endswith(".net")],
            "rest": [],
        }
        for d in domains:
            if not isinstance(d, str):
                continue
            dn = d.strip().rstrip(".").lower()
            if not dn:
                continue

            tld = dn.rsplit(".", 1)[-1] if "." in dn else ""

            # Only populate "rest" here; other buckets are pre-populated above
            if not (DNSApplication._is_high_risk(dn) or tld in {"uk", "de", "com"}):
                buckets["rest"].append(dn)

        return {k: v for k, v in buckets.items() if v}

    def _rate_for_tld(self, tld: str) -> int:
        return self.tld_rate_limits.get(tld, self.tld_rate_limits.get("rest", CONFIG.global_qps))

    async def _process_interleaved(
        self,
        groups: Dict[str, List[str]],
        safe_key: str,
        chunked_processor: ChunkedTLDProcessor
    ) -> List:
        """
        Process TLDs in interleaved manner to eliminate idle cooldowns.

        Schedule:
        1. .com chunk 1 (warmup)
        2. .uk (full)
        3. .de (full)
        4. .com chunk 2
        5. .xyz (full)
        6. .rest (full)
        7. .com chunk 3 (if exists)
        8. .net (full)
        """
        app_logger.info("=" * 70)
        app_logger.info("INTERLEAVED PROCESSING (Eliminating Idle Cooldowns)")
        app_logger.info("=" * 70)

        all_results = []

        # Prepare .com chunks
        com_chunks = []
        if 'com' in groups:
            com_config = chunked_processor.get_config('com')
            com_chunks = chunked_processor.chunk_domains(
                groups['com'],
                com_config['chunk_size']
            )

        # Build processing order
        processing_order = []

        # 1. .com chunk 1
        if com_chunks:
            processing_order.append(('com', 'chunk', 1, com_chunks[0]))

        # 2-3. Small TLDs (uk, de)
        for tld in ['uk', 'co.uk', 'de']:
            if tld in groups:
                processing_order.append((tld, 'full', 0, groups[tld]))

        # 4. .com chunk 2
        if len(com_chunks) > 1:
            processing_order.append(('com', 'chunk', 2, com_chunks[1]))

        # 5. .xyz
        if 'xyz' in groups:
            processing_order.append(('xyz', 'full', 0, groups['xyz']))

        # 6. .rest (largest, good cooldown maker)
        if 'rest' in groups:
            processing_order.append(('rest', 'full', 0, groups['rest']))

        # 7. .com chunk 3
        if len(com_chunks) > 2:
            processing_order.append(('com', 'chunk', 3, com_chunks[2]))

        # Log schedule
        app_logger.info(f"\nProcessing {len(processing_order)} tasks:\n")
        for idx, (tld, task_type, chunk_num, domains) in enumerate(processing_order, 1):
            if task_type == 'chunk':
                app_logger.info(f"  {idx}. .{tld} chunk {chunk_num} ({len(domains):,} domains)")
            else:
                app_logger.info(f"  {idx}. .{tld} full batch ({len(domains):,} domains)")
        app_logger.info("")

        # Process schedule
        for idx, (tld, task_type, chunk_num, domains) in enumerate(processing_order, 1):
            app_logger.info(f"\n{'='*70}")
            if task_type == 'chunk':
                app_logger.info(f"Task {idx}: .{tld} chunk {chunk_num}")
            else:
                app_logger.info(f"Task {idx}: .{tld} (full batch)")
            app_logger.info(f"{'='*70}")

            # Get config for this TLD
            config = chunked_processor.get_config(tld)
            chunk_qps = config['qps']
            # Cap by app-level limits
            effective_qps = CONFIG.effective_qps_for_tld(tld, chunk_qps)
            effective_concurrency = CONFIG.effective_concurrency_for_tld(tld, effective_qps)

            # Create BatchProcessor
            def create_bp(file_key, semaphore, workers):
                return BatchProcessor(
                    file_key=file_key,
                    output_dir=self.output_directory,
                    retry_dir=self.retry_directory,
                    workers=workers,
                    semaphore=semaphore,
                    logger=app_logger,
                    lmdb_path=str(self.lmdb_path) if getattr(self, "lmdb_path", None) else None,
                    lookups_db_path=os.getenv("LOOKUPS_DB_PATH"),
                    flight_server_url=os.getenv("FLIGHT_SERVER_URL"),
                )

            bp = create_bp(
                file_key=f"{safe_key}_{tld}_{'chunk'+str(chunk_num) if task_type=='chunk' else 'full'}",
                semaphore=asyncio.Semaphore(effective_concurrency),
                workers=effective_concurrency
            )

            # Process
            start = asyncio.get_event_loop().time()
            result = await bp.process(domains)
            elapsed = asyncio.get_event_loop().time() - start

            app_logger.info(f"Completed in {elapsed:.1f}s")
            all_results.append(result)

        app_logger.info("\n" + "=" * 70)
        app_logger.info("INTERLEAVED PROCESSING COMPLETE")
        app_logger.info("=" * 70)

        return all_results

    async def run_dns(self, file_key: Optional[str] = None):
        if file_key is not None:
            self.file_key = file_key
        """
        Entrypoint called by the Celery worker.
        Reads from: <input_directory>/<file_key>
        """
        input_path = Path(self.input_directory) / self.file_key
        app_logger.info("Reading input table {}", input_path)
        table = pq.read_table(input_path, columns=["domain", "ns", "ip", "country_dm"])
        app_logger.info("Read {} rows from {}", table.num_rows, input_path)

        # Initialize LMDB in dns_lookup (if the function exists)
        try:
            # Prefer externally configured LMDB directory if provided.
            lmdb_dir_env = os.getenv("LMDB_DIR")
            if lmdb_dir_env:
                self.lmdb_path = Path(lmdb_dir_env)
            else:
                self.lmdb_path = Path("/mnt/shared/dns_lmdb")

            self.lmdb_path.mkdir(parents=True, exist_ok=True)

            if hasattr(dns_lookup, "init_lmdb"):
                dns_lookup.init_lmdb(str(self.lmdb_path), readonly=False)
            if hasattr(dns_lookup, "start_lmdb_writer"):
                dns_lookup.start_lmdb_writer()
            app_logger.info("LMDB initialized at {} (if supported)", self.lmdb_path)
        except Exception:
            app_logger.exception("LMDB init/writer startup failed; continuing without LMDB")

        # Normalize domain list
        raw_domains = table["domain"].to_pylist()
        domains: List[str] = []
        for d in raw_domains:
            if isinstance(d, str):
                dn = d.strip().rstrip(".").lower()
                if dn:
                    domains.append(dn)

        # Group by TLD/buckets
        groups = self._group_domains_by_tld(domains)

        # Make a safe key for output prefixes used in chunked processing
        safe_key = self.file_key.replace("/", "_")

        # Check if chunked processing is enabled
        use_chunked = os.getenv("USE_CHUNKED_PROCESSING", "true").lower() == "true"

        if use_chunked:
            app_logger.info("Using chunked TLD processing")

            chunked_processor = ChunkedTLDProcessor()
            use_interleaved = os.getenv("ENABLE_INTERLEAVED", "true").lower() == "true"

            if use_interleaved:
                all_results = await self._process_interleaved(groups, safe_key, chunked_processor)
            else:
                # Sequential estimate + processing
                app_logger.info("Using sequential processing")
                all_results = []
                tld_order = ['rest', 'xyz', 'de', 'uk', 'co.uk', 'net', 'com']

                # Estimate processing time
                domain_counts = {tld: len(group) for tld, group in groups.items()}
                time_estimate = chunked_processor.estimate_time(domain_counts)

                app_logger.info(f"\n{'='*70}")
                app_logger.info("BATCH PROCESSING PLAN")
                app_logger.info(f"{'='*70}")
                for tld, est in sorted(time_estimate.items()):
                    if tld == 'total':
                        app_logger.info(
                            f"\nESTIMATED TOTAL: {est['estimated_time_minutes']:.1f} minutes"
                        )
                    else:
                        app_logger.info(
                            f"  .{tld}: {est['domains']:,} domains in {est['chunks']} chunks "
                            f"→ ~{est['total_time']/60:.1f} min"
                        )
                app_logger.info(f"{'='*70}\n")

                all_results = []
                overall_start = asyncio.get_event_loop().time()

                for tld in tld_order:
                    if tld not in groups:
                        continue

                    group = groups[tld]

                    # Factory function to create BatchProcessor for each chunk.
                    # The processor receives a suggested 'workers', which equals the chunk_qps
                    # from ChunkedTLDProcessor (including warmup). We cap it using CONFIG.
                    def create_batch_processor(file_key, semaphore, workers):
                        # workers is the suggested chunk_qps from the caller; cap it.
                        suggested_qps = int(workers or 1)
                        cap = CONFIG.effective_concurrency_for_tld(tld, suggested_qps)
                        sem_capped = asyncio.Semaphore(cap)

                        return BatchProcessor(
                            file_key=file_key,
                            output_dir=self.output_directory,
                            retry_dir=self.retry_directory,
                            workers=cap,
                            semaphore=sem_capped,
                            logger=app_logger,
                            lmdb_path=str(self.lmdb_path) if getattr(self, "lmdb_path", None) else None,
                            lookups_db_path=os.getenv("LOOKUPS_DB_PATH"),
                            flight_server_url=os.getenv("FLIGHT_SERVER_URL"),
                        )

                    # Process TLD in chunks
                    tld_results = await chunked_processor.process_tld_chunked(
                        tld=tld,
                        domains=group,
                        batch_processor_factory=create_batch_processor,
                        file_key=safe_key
                    )

                    all_results.extend(tld_results)

                overall_elapsed = asyncio.get_event_loop().time() - overall_start
                app_logger.info(
                    f"\n{'='*70}\n"
                    f"BATCH COMPLETE\n"
                    f"Total time: {overall_elapsed/60:.1f} minutes\n"
                    f"{'='*70}\n"
                )

            results = all_results

        else:
            # === ORIGINAL CONCURRENT PROCESSING (FALLBACK) ===
            app_logger.info("Using concurrent TLD processing (original method)")

            tasks = []
            for tld, group in groups.items():
                tasks.append(
                    asyncio.create_task(
                        self._run_group(tld, group, table, "single")
                    )
                )
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, Exception):
                    app_logger.error(f"TLD group task failed: {r!r}")

            # Graceful shutdown of dns_lookup background tasks (if provided)
            try:
                if hasattr(dns_lookup, "shutdown"):
                    await dns_lookup.shutdown()
                    app_logger.info("dns_lookup shutdown complete")
            except Exception:
                app_logger.exception("Error during dns_lookup shutdown")

    async def _run_group(self, tld: str, group_domains: List[str], original_table: pa.Table, label: str):
        safe_key = self.file_key.replace("/", "_")
        # Pass shared semaphore and app_logger down to BatchProcessor so everything uses same settings
        bp = BatchProcessor(
            file_key=f"{safe_key}_{label}_{tld}",
            output_dir=self.output_directory,
            retry_dir=self.retry_directory,
            workers=CONFIG.workers_default,
            semaphore=self.semaphore,
            logger=app_logger,
            lmdb_path=str(self.lmdb_path) if getattr(self, "lmdb_path", None) else None,
            # Allow overriding the DuckDB lookups path for local/dev runs
            lookups_db_path=os.getenv("LOOKUPS_DB_PATH") if os.getenv("LOOKUPS_DB_PATH") else None,
            flight_server_url=os.getenv("FLIGHT_SERVER_URL"),
        )
        try:
            results_path, retries_path = await bp.process(group_domains)
            app_logger.info("Completed TLD group {}: results={} retries={}", tld, results_path, retries_path)
        except Exception as e:
            app_logger.error("TLD group task failed: %r\n%s", e, traceback.format_exc())