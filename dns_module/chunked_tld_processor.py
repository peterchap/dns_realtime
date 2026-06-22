# chunked_tld_processor.py
# Process dominant TLDs (.com/.net) in chunks to avoid sustained high rate

import asyncio
import math
from typing import List, Dict, Tuple
from .logger import get_child_logger
from .config import CONFIG

log = get_child_logger("chunked_tld_processor")


class ChunkedTLDProcessor:
    """
    Process large TLD groups in chunks to avoid registrar penalties.
    
    Strategy:
    - .com/net: Split into 5K chunks, process at 50 qps, 60s cooldown between chunks
    - .uk/de/xyz: Process normally with conservative rate
    - Others: Process at higher rate
    
    This avoids sustained high rate that triggers penalties while keeping
    overall processing time reasonable.
    """
    
    def __init__(self):
        # TLD-specific configurations
        self.tld_config = {
            'com': {'chunk_size': 5000, 'qps': 200, 'cooldown': 0, 'reason': 'Verisign strict rate limiting'},
            'net': {'chunk_size': 5000, 'qps': 200, 'cooldown': 0, 'reason': 'Verisign strict rate limiting'},
            'uk': {'chunk_size': 1000, 'qps': 50, 'cooldown': 0, 'reason': 'Nominet very strict'},
            'co.uk': {'chunk_size': 1000, 'qps': 50, 'cooldown': 0, 'reason': 'Nominet very strict'},
            'de': {'chunk_size': 2000, 'qps': 50, 'cooldown': 0, 'reason': 'DENIC moderate throttling'},
            'xyz': {'chunk_size': 1000, 'qps': 50, 'cooldown': 0, 'reason': 'xyz throttles unexpectedly'},
            'default': {'chunk_size': 10000, 'qps': 200, 'cooldown': 0, 'reason': 'No known throttling'}
        }
    
    def get_config(self, tld: str) -> Dict:
        """Get configuration for a TLD"""
        return self.tld_config.get(tld, self.tld_config['default'])
    
    def chunk_domains(self, domains: List[str], chunk_size: int) -> List[List[str]]:
        """Split domains into chunks"""
        chunks = []
        for i in range(0, len(domains), chunk_size):
            chunks.append(domains[i:i + chunk_size])
        return chunks
    
    async def process_tld_chunked(
        self,
        tld: str,
        domains: List[str],
        batch_processor_factory,  # Function that creates BatchProcessor
        **bp_kwargs
    ) -> List:
        """
        Process a TLD group in chunks with cooldowns.
        
        Args:
            tld: TLD being processed
            domains: All domains for this TLD
            batch_processor_factory: Function to create BatchProcessor
            **bp_kwargs: Additional kwargs for BatchProcessor
        
        Returns:
            List of results from each chunk
        """
        config = self.get_config(tld)
        
        log.info(
            f"\n{'='*70}\n"
            f"Processing TLD: .{tld}\n"
            f"  Total domains: {len(domains):,}\n"
            f"  Strategy: {config['chunk_size']:,} domains/chunk @ {config['qps']} qps\n"
            f"  Cooldown: {config['cooldown']}s between chunks\n"
            f"  Reason: {config['reason']}\n"
            f"{'='*70}"
        )
        
        # Split into chunks
        chunks = self.chunk_domains(domains, config['chunk_size'])
        num_chunks = len(chunks)
        
        log.info(f"Split into {num_chunks} chunks")
        
        all_results = []
        
        for chunk_idx, chunk in enumerate(chunks, 1):
    
            # === IP WARMUP: Use lower QPS on first chunk ===
            # This establishes IP as legitimate with registrars
            is_problematic_tld = tld in ['com', 'net', 'uk', 'co.uk', 'de', 'xyz']
            is_first_chunk = chunk_idx == 1
            
            # Suggested per-chunk QPS before caps (warmup on first chunk for problematic TLDs)
            suggested_qps = int(config['qps'] * 0.5) if (is_first_chunk and is_problematic_tld) else config['qps']

            # Apply app-level caps
            effective_qps = CONFIG.effective_qps_for_tld(tld, suggested_qps)
            effective_concurrency = CONFIG.effective_concurrency_for_tld(tld, effective_qps)

            label = "(IP WARMUP)" if (is_first_chunk and is_problematic_tld) else ""
            log.info(
                f"\n--- Chunk {chunk_idx}/{num_chunks} {label} ---\n"
                f"  Domains: {len(chunk):,}\n"
                f"  Rate requested: {suggested_qps} qps → effective: {effective_qps} qps\n"
                f"  Concurrency cap: {effective_concurrency}"
            )

            chunk_semaphore = asyncio.Semaphore(effective_concurrency)

            bp = batch_processor_factory(
                file_key=f"{bp_kwargs.get('file_key', 'batch')}_{tld}_chunk{chunk_idx}",
                semaphore=chunk_semaphore,
                workers=effective_concurrency,
                **{k: v for k, v in bp_kwargs.items() if k not in ['file_key', 'semaphore', 'workers']}
            )

            chunk_start = asyncio.get_event_loop().time()
            result = await bp.process(chunk)
            chunk_elapsed = asyncio.get_event_loop().time() - chunk_start
            all_results.append(result)

            actual_qps = len(chunk) / chunk_elapsed if chunk_elapsed > 0 else 0
            # success_count calculation unchanged...
            success_count = 0
            if isinstance(result, dict):
                success_count = result.get('success_count', 0)
            elif hasattr(result, 'success_count'):
                success_count = getattr(result, 'success_count', 0)
            elif isinstance(result, (list, tuple)):
                try:
                    success_count = sum(
                        1 for item in result
                        if (isinstance(item, dict) and bool(item.get('success'))) or getattr(item, 'success', False)
                    )
                except Exception:
                    success_count = 0

            log.info(
                f"  Completed: {chunk_elapsed:.1f}s ({actual_qps:.1f} qps actual)\n"
                f"  Success: {success_count:,}/{len(chunk):,}"
            )

            if chunk_idx < num_chunks and config['cooldown'] > 0:
                log.info(f"  Cooldown: {config['cooldown']}s before next chunk...")
                await asyncio.sleep(config['cooldown'])

        log.info(f"\n✓ TLD .{tld} complete: {len(domains):,} domains in {num_chunks} chunks")
        return all_results
    
    def estimate_time(self, domain_counts: Dict[str, int]) -> Dict:
        estimates = {}
        total_time = 0
        for tld, count in domain_counts.items():
            config = self.get_config(tld)
            num_chunks = math.ceil(count / config['chunk_size'])
            # Use effective QPS for realistic estimate
            effective_qps = CONFIG.effective_qps_for_tld(tld, config['qps'])
            time_per_chunk = count / max(1, effective_qps)
            cooldown_time = max(0, (num_chunks - 1)) * config['cooldown']
            tld_total = time_per_chunk + cooldown_time

            estimates[tld] = {
                'domains': count,
                'chunks': num_chunks,
                'qps': effective_qps,
                'processing_time': time_per_chunk,
                'cooldown_time': cooldown_time,
                'total_time': tld_total,
                'chunk_size': config['chunk_size']
            }
            total_time += tld_total

        estimates['total'] = {
            'estimated_time_seconds': total_time,
            'estimated_time_minutes': total_time / 60
        }
        return estimates


# Monitoring and Tuning

def log_chunk_performance(tld: str, chunk_idx: int, actual_qps: float, target_qps: float):
    """Log if actual rate deviates from target"""
    deviation = abs(actual_qps - target_qps) / target_qps
    
    if deviation > 0.2:  # >20% deviation
        if actual_qps < target_qps * 0.8:
            log.warning(
                f"⚠️  {tld} chunk {chunk_idx}: Slower than expected "
                f"({actual_qps:.1f} vs {target_qps:.1f} qps) - possible throttling?"
            )
        elif actual_qps > target_qps * 1.2:
            log.warning(
                f"⚠️  {tld} chunk {chunk_idx}: Faster than expected "
                f"({actual_qps:.1f} vs {target_qps:.1f} qps) - semaphore not limiting?"
            )
