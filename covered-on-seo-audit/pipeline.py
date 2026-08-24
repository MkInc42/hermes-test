#!/usr/bin/env python3
"""
Covered On — SEO Audit Pipeline
Orchestrates: Crawl → Performance Analysis → Report Generation
Customers will toggle tools on/off. This is the master runner.
"""

import asyncio
import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.crawler import run_crawl, run_frog_crawl
from src.tools.performance import PerformanceAnalyzer
from src.tools.security import SecurityScanner

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("pipeline")


class AuditPipeline:
    """Orchestrates the full SEO audit process."""

    def __init__(self, output_dir: str, crawler: str = "playwright"):
        if crawler not in {"playwright", "frog"}:
            raise ValueError(f"Unsupported crawler backend: {crawler}")
        self.output_dir = output_dir
        self.crawl_dir = os.path.join(output_dir, "crawl")
        self.perf_dir = os.path.join(output_dir, "performance")
        self.sec_dir = os.path.join(output_dir, "security")
        self.report_dir = os.path.join(output_dir, "report")

        os.makedirs(self.crawl_dir, exist_ok=True)
        os.makedirs(self.perf_dir, exist_ok=True)
        os.makedirs(self.sec_dir, exist_ok=True)
        os.makedirs(self.report_dir, exist_ok=True)

        # Tool flags — customers toggle these later
        self.run_crawler = True
        self.run_performance = True
        self.run_security = True
        self.performance_strategy = "mobile"
        self.crawler = crawler

    def run(self, url: str, max_urls: int = 100, max_depth: int = 3):
        """Run the full audit pipeline."""
        start = time.time()
        pages = []
        try:
            log.info(f"=== SEO Audit Pipeline ===")
            log.info(f"Target: {url}")
            log.info(f"Max URLs: {max_urls}, Max Depth: {max_depth}")
            log.info(f"Tools: crawler={self.run_crawler} ({self.crawler}), perf={self.run_performance}, sec={self.run_security}")
            log.info(f"Output: {self.output_dir}")

            # ─── Step 1: Crawl ────────────────────────────────────────────────
            if self.run_crawler:
                log.info("─" * 50)
                log.info("Step 1/3: Crawling website...")

                if self.crawler == "frog":
                    pages = run_frog_crawl(
                        start_url=url,
                        output_dir=self.crawl_dir,
                        max_urls=max_urls,
                        max_depth=max_depth,
                    )
                else:
                    pages = asyncio.run(run_crawl(
                        start_url=url,
                        output_dir=self.crawl_dir,
                        max_urls=max_urls,
                        max_depth=max_depth,
                    ))

                log.info(f"✓ Crawl complete: {len(pages)} pages")
            else:
                log.info("Step 1/3: Crawler disabled — skipping")
                pages = []

            # ─── Step 2: Performance Analysis ──────────────────────────────────
            if self.run_performance and pages:
                log.info("─" * 50)
                log.info("Step 2/3: Running performance analysis...")

                urls = [p.url for p in pages]

                analyzer = PerformanceAnalyzer(delay_ms=500)
                results = analyzer.analyze(urls, strategy=self.performance_strategy)
                analyzer.export_csv(self.perf_dir)

                log.info(f"✓ Performance analysis complete: {len(results)} URLs")
            elif self.run_performance and not pages:
                log.info("Running performance on start URL only...")
                analyzer = PerformanceAnalyzer(delay_ms=500)
                results = analyzer.analyze([url], strategy=self.performance_strategy)
                analyzer.export_csv(self.perf_dir)
            else:
                log.info("Step 2/3: Performance analysis disabled — skipping")
                results = []

            # ─── Step 3: Security Assessment ────────────────────────────────────
            if self.run_security:
                log.info("─" * 50)
                log.info("Step 3/4: Running security assessment...")

                scanner = SecurityScanner()
                sec_results = scanner.analyze([url])
                scanner.export_csv(self.sec_dir)

                sec_score = sec_results[0].score if sec_results else 0
                sec_info = f"score={sec_score}/100"
                log.info(f"✓ Security assessment complete: {sec_info}")
            else:
                log.info("Step 3/4: Security assessment disabled — skipping")
                sec_result = None

            # ─── Step 4: Generate Report ──────────────────────────────────────
            log.info("─" * 50)
            log.info("Step 4/4: Generating report...")

            from src.report_generator import generate_report, AuditData, analyze, calculate_score
            from src.internal_brief import generate_brief

            report_path = os.path.join(self.report_dir, "report.html")
            summary = generate_report(
                crawl_dir=self.crawl_dir,
                output_path=report_path,
                start_url=url,
                perf_dir=self.perf_dir if self.run_performance else None,
                sec_dir=self.sec_dir if self.run_security else None,
            )

            # Generate internal brief alongside client report
            data = AuditData(self.crawl_dir,
                             perf_dir=self.perf_dir if self.run_performance else None,
                             sec_dir=self.sec_dir if self.run_security else None)
            issues_dict = analyze(data)
            all_issues = []
            for level, items in issues_dict.items():
                for item in items:
                    all_issues.append({**item, "level": level})
            score_data = calculate_score(data, issues_dict)

            brief_path = os.path.join(self.report_dir, "brief-internal.html")
            generate_brief(
                crawl_dir=self.crawl_dir,
                output_path=brief_path,
                start_url=url,
                score_data=score_data,
                all_issues=all_issues,
                data=data,
            )

            elapsed = time.time() - start
            log.info("─" * 50)
            log.info(f"✓ Audit complete in {elapsed:.1f}s")
            log.info(f"  Report: {report_path}")
            log.info(f"  Crawl data: {self.crawl_dir}")
            log.info(f"  Performance data: {self.perf_dir}")
            log.info(f"  Security data: {self.sec_dir}")

            return {
                "report_path": report_path,
                "crawl_dir": self.crawl_dir,
                "perf_dir": self.perf_dir,
                "sec_dir": self.sec_dir,
                "pages_crawled": len(pages),
                "duration_seconds": round(elapsed, 1),
            }
        finally:
            self._cleanup_chrome()

    @staticmethod
    def _cleanup_chrome():
        """Kill orphaned Chrome/Chromium/Lighthouse processes."""
        killed = 0
        for pattern in ["chrome", "chromium", "lighthouse", "node.*lighthouse"]:
            try:
                r = subprocess.run(
                    ["pkill", "-f", pattern],
                    capture_output=True, timeout=5
                )
                if r.returncode == 0:
                    killed += 1
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
        if killed:
            log.info(f"Cleaned up {killed} orphaned process(es)")


 # ─── CLI ────────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Covered On SEO Audit Pipeline")
    parser.add_argument("url", help="Website URL to audit")
    parser.add_argument("--output", "-o", default=None, help="Output directory (default: ./audits/<domain>)")
    parser.add_argument("--max-urls", type=int, default=100, help="Max pages to crawl")
    parser.add_argument("--max-depth", type=int, default=3, help="Max crawl depth")
    parser.add_argument(
        "--crawler",
        choices=["playwright", "frog"],
        default="playwright",
        help="Crawler backend (default: playwright)",
    )
    parser.add_argument("--no-crawl", action="store_true", help="Skip crawling")
    parser.add_argument("--no-perf", action="store_true", help="Skip performance analysis")
    parser.add_argument("--no-sec", action="store_true", help="Skip security assessment")
    parser.add_argument("--perf-strategy", default="mobile", choices=["mobile", "desktop"])
    args = parser.parse_args()

    # Default output dir
    from urllib.parse import urlparse
    domain = urlparse(args.url).netloc.replace("www.", "").replace(".", "-")
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_dir = args.output or f"./audits/{domain}-{timestamp}"

    pipeline = AuditPipeline(output_dir, crawler=args.crawler)
    if args.no_crawl:
        pipeline.run_crawler = False
    if args.no_perf:
        pipeline.run_performance = False
    if args.no_sec:
        pipeline.run_security = False
    pipeline.performance_strategy = args.perf_strategy

    result = pipeline.run(args.url, args.max_urls, args.max_depth)

    print(f"\n{'='*50}")
    print(f"  Report: {result['report_path']}")
    print(f"  Pages: {result['pages_crawled']}")
    print(f"  Duration: {result['duration_seconds']}s")
    print(f"{'='*50}")


if __name__ == "__main__":
    main()
