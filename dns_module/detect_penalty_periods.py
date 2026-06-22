#!/usr/bin/env python3
"""
Penalty Period Detector - Monitor if your IPs are in registrar penalty boxes

Run this between batch jobs to check if you should wait before next run.
"""

import asyncio
import time
import sys
from collections import defaultdict
from typing import Dict, List
import dns.asyncresolver

# Test domains for each TLD (known-good, should always resolve)
TEST_DOMAINS = {
    'com': ['google.com', 'amazon.com', 'microsoft.com'],
    'net': ['cloudflare.net', 'akamai.net', 'google-analytics.net'],
    'uk': ['bbc.co.uk', 'gov.uk', 'cam.ac.uk'],
    'de': ['deutsche-bank.de', 'bmw.de', 'siemens.de'],
    'org': ['wikipedia.org', 'mozilla.org', 'apache.org'],
}

class PenaltyDetector:
    def __init__(self, nameserver: str = '127.0.0.1'):
        self.nameserver = nameserver
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.nameservers = [nameserver]
        self.resolver.timeout = 5.0
        self.resolver.lifetime = 10.0
    
    async def test_domain(self, domain: str) -> Dict:
        """Test a single domain and measure response"""
        start = time.time()
        
        try:
            answer = await self.resolver.resolve(domain, 'A')
            elapsed = time.time() - start
            
            return {
                'domain': domain,
                'status': 'OK',
                'rcode': 'NOERROR',
                'response_time': elapsed,
                'answers': len(answer)
            }
        
        except dns.resolver.NXDOMAIN:
            elapsed = time.time() - start
            return {
                'domain': domain,
                'status': 'NXDOMAIN',
                'rcode': 'NXDOMAIN',
                'response_time': elapsed
            }
        
        except dns.resolver.Timeout:
            elapsed = time.time() - start
            return {
                'domain': domain,
                'status': 'TIMEOUT',
                'rcode': 'TIMEOUT',
                'response_time': elapsed
            }
        
        except dns.exception.DNSException as e:
            elapsed = time.time() - start
            rcode = 'SERVFAIL' if 'SERVFAIL' in str(e) else 'ERROR'
            return {
                'domain': domain,
                'status': 'ERROR',
                'rcode': rcode,
                'response_time': elapsed,
                'error': str(e)
            }
    
    async def test_tld(self, tld: str, domains: List[str]) -> Dict:
        """Test all domains for a TLD"""
        print(f"\nTesting .{tld} domains...")
        
        results = []
        for domain in domains:
            result = await self.test_domain(domain)
            results.append(result)
            print(f"  {domain}: {result['status']} ({result['response_time']:.3f}s)")
        
        # Analyze results
        failures = [r for r in results if r['status'] in ['TIMEOUT', 'ERROR']]
        slow_queries = [r for r in results if r.get('response_time', 0) > 2.0]
        avg_time = sum(r['response_time'] for r in results) / len(results)
        
        failure_rate = len(failures) / len(results)
        
        # Determine penalty status
        in_penalty = False
        reason = []
        
        if failure_rate > 0.3:  # >30% failures
            in_penalty = True
            reason.append(f"High failure rate: {failure_rate:.0%}")
        
        if avg_time > 3.0:  # Average >3 seconds
            in_penalty = True
            reason.append(f"Slow responses: {avg_time:.1f}s avg")
        
        if len([r for r in results if r['rcode'] == 'SERVFAIL']) > 0:
            in_penalty = True
            reason.append("SERVFAIL detected")
        
        return {
            'tld': tld,
            'tested': len(results),
            'failures': len(failures),
            'failure_rate': failure_rate,
            'avg_response_time': avg_time,
            'in_penalty': in_penalty,
            'reason': ' | '.join(reason) if reason else 'OK',
            'details': results
        }
    
    async def detect_penalties(self) -> Dict[str, Dict]:
        """Test all TLDs and detect penalty periods"""
        print("="*70)
        print("TLD Penalty Period Detection")
        print(f"Using nameserver: {self.nameserver}")
        print("="*70)
        
        results = {}
        for tld, domains in TEST_DOMAINS.items():
            result = await self.test_tld(tld, domains)
            results[tld] = result
            
            # Small delay between TLD tests
            await asyncio.sleep(0.5)
        
        return results
    
    def print_summary(self, results: Dict[str, Dict]):
        """Print summary of penalty detection"""
        print("\n" + "="*70)
        print("PENALTY DETECTION SUMMARY")
        print("="*70)
        print(f"{'TLD':<8} {'Status':<12} {'Failures':<10} {'Avg Time':<12} {'Reason'}")
        print("-"*70)
        
        penalties_detected = []
        
        for tld, result in sorted(results.items()):
            status = "🚫 PENALTY" if result['in_penalty'] else "✅ OK"
            failures = f"{result['failures']}/{result['tested']}"
            avg_time = f"{result['avg_response_time']:.2f}s"
            reason = result['reason'] if result['in_penalty'] else ""
            
            print(f"{tld:<8} {status:<12} {failures:<10} {avg_time:<12} {reason}")
            
            if result['in_penalty']:
                penalties_detected.append(tld)
        
        print("-"*70)
        
        if penalties_detected:
            print(f"\n⚠️  PENALTY DETECTED for: {', '.join(penalties_detected)}")
            print("\nRECOMMENDATIONS:")
            print("1. Wait 15-30 minutes before next batch run")
            print("2. Use lower semaphore limits for these TLDs")
            print("3. Add cooldown periods between TLD groups")
            print("\nWait time estimate:")
            for tld in penalties_detected:
                if tld in ['com', 'uk']:
                    print(f"  .{tld}: Wait at least 30 minutes")
                else:
                    print(f"  .{tld}: Wait at least 15 minutes")
        else:
            print("\n✅ NO PENALTIES DETECTED")
            print("You can safely run next batch immediately.")
        
        print("\n" + "="*70)
    
    async def continuous_monitor(self, interval: int = 300):
        """Continuously monitor for penalties"""
        print(f"Starting continuous monitoring (every {interval}s)...")
        print("Press Ctrl+C to stop")
        
        try:
            while True:
                results = await self.detect_penalties()
                self.print_summary(results)
                
                print(f"\nNext check in {interval}s...")
                await asyncio.sleep(interval)
        
        except KeyboardInterrupt:
            print("\nMonitoring stopped")


async def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Detect TLD penalty periods")
    parser.add_argument('--nameserver', default='127.0.0.1', 
                       help='Nameserver to test (default: 127.0.0.1)')
    parser.add_argument('--monitor', action='store_true',
                       help='Continuous monitoring mode')
    parser.add_argument('--interval', type=int, default=300,
                       help='Monitoring interval in seconds (default: 300)')
    
    args = parser.parse_args()
    
    detector = PenaltyDetector(nameserver=args.nameserver)
    
    if args.monitor:
        await detector.continuous_monitor(interval=args.interval)
    else:
        results = await detector.detect_penalties()
        detector.print_summary(results)


if __name__ == '__main__':
    asyncio.run(main())
