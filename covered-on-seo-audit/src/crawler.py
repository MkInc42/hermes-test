#!/usr/bin/env python3
"""
Covered On — SEO Crawler
Headless Playwright-based crawler that extracts SEO data from websites.
Outputs CSV files consumable by the report generator.
"""

import asyncio
import csv
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse

import yaml
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("crawler")


# ─── Data Models ───────────────────────────────────────────────────────────

@dataclass
class PageData:
    url: str
    status_code: int = 0
    content_type: str = ""
    load_time_ms: float = 0.0
    title: str = ""
    title_length: int = 0
    meta_description: str = ""
    meta_description_length: int = 0
    h1s: list = field(default_factory=list)
    h2s: list = field(default_factory=list)
    canonical: str = ""
    robots_directives: list = field(default_factory=list)
    og_tags: dict = field(default_factory=dict)
    twitter_tags: dict = field(default_factory=dict)
    has_viewport: bool = False
    html_lang: str = ""
    has_favicon: bool = False
    word_count: int = 0
    structured_data: list = field(default_factory=list)
    internal_links: list = field(default_factory=list)
    external_links: list = field(default_factory=list)
    images: list = field(default_factory=list)
    error: str = ""


@dataclass
class CrawlConfig:
    start_url: str
    max_urls: int = 100
    max_depth: int = 3
    respect_robots: bool = True
    render_js: bool = True
    timeout_ms: int = 15000
    delay_ms: int = 500
    output_dir: str = "."


# ─── URL Utilities ─────────────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    """Normalize URL for dedup — strip fragment, lowercase host, strip trailing slash."""
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path.rstrip("/") or "/"
    query = parsed.query
    return f"{scheme}://{netloc}{path}" + (f"?{query}" if query else "")


def is_same_domain(url: str, start_url: str) -> bool:
    """Check if URL belongs to the same domain as the start URL."""
    return urlparse(url).netloc.lower() == urlparse(start_url).netloc.lower()


def is_html(url: str) -> bool:
    """Skip non-HTML resources."""
    parsed = urlparse(url)
    path = parsed.path.lower()
    skip_exts = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico",
                 ".css", ".js", ".json", ".xml", ".pdf", ".doc", ".docx",
                 ".zip", ".tar", ".gz", ".mp4", ".mp3", ".woff", ".woff2",
                 ".ttf", ".eot", ".webmanifest"}
    ext = os.path.splitext(path)[1]
    if ext in skip_exts:
        return False
    # Skip common non-HTML paths
    skip_patterns = ["/wp-json/", "/wp-admin/", "/wp-includes/", "/feed/",
                     "/xmlrpc.php", "?format=rss", "?format=feed"]
    for p in skip_patterns:
        if p in url.lower():
            return False
    return True


def should_crawl(url: str) -> bool:
    """Filter out non-crawlable URLs."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    if parsed.fragment:  # Strip fragments for crawling decisions
        pass
    return is_html(url)


# ─── Crawler ────────────────────────────────────────────────────────────────

class SEOCrawler:
    def __init__(self, config: CrawlConfig):
        self.config = config
        self.visited: set = set()
        self.queued: set = set()
        self.pages: dict[str, PageData] = {}
        self.queue: list[tuple[str, int]] = []  # (url, depth)
        self.browser = None
        self.context = None
        self.start_domain = urlparse(config.start_url).netloc.lower()

    async def start_browser(self):
        p = await async_playwright().start()
        self.browser = await p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-setuid-sandbox"]
        )
        self.context = await self.browser.new_context(
            user_agent="CoveredOn-SEO-Audit/1.0 (+https://coveredon.com/free-seo-audit)",
            viewport={"width": 1280, "height": 800},
            ignore_https_errors=True,
        )

    async def crawl(self) -> list[PageData]:
        log.info(f"Starting crawl of {self.config.start_url}")
        log.info(f"Max URLs: {self.config.max_urls}, Max Depth: {self.config.max_depth}")

        await self.start_browser()
        self.queue.append((self.config.start_url, 0))
        self.queued.add(normalize_url(self.config.start_url))

        try:
            while self.queue and len(self.visited) < self.config.max_urls:
                url, depth = self.queue.pop(0)
                norm_url = normalize_url(url)

                if norm_url in self.visited or depth > self.config.max_depth:
                    continue

                self.visited.add(norm_url)
                log.info(f"[{len(self.visited)}/{self.config.max_urls}] Crawling: {url} (depth={depth})")

                page_data = await self.crawl_page(url)
                self.pages[norm_url] = page_data

                # Queue internal links for further crawling
                if depth < self.config.max_depth:
                    for link in page_data.internal_links:
                        link_url = link.get("href", "")
                        if link_url and is_same_domain(link_url, url) and should_crawl(link_url):
                            norm_link = normalize_url(link_url)
                            if norm_link not in self.visited and norm_link not in self.queued:
                                self.queued.add(norm_link)
                                self.queue.append((link_url, depth + 1))

                # Respect delay
                if self.config.delay_ms > 0 and self.queue:
                    await asyncio.sleep(self.config.delay_ms / 1000)

        finally:
            await self.close_browser()

        log.info(f"Crawl complete. Visited {len(self.visited)} pages.")
        return list(self.pages.values())

    async def crawl_page(self, url: str) -> PageData:
        page = await self.context.new_page()
        page_data = PageData(url=url)

        try:
            start = time.time()
            response = await page.goto(url, wait_until="domcontentloaded",
                                        timeout=self.config.timeout_ms)
            elapsed = (time.time() - start) * 1000
            page_data.load_time_ms = round(elapsed, 2)

            if response:
                page_data.status_code = response.status
                ct = response.headers.get("content-type", "")
                page_data.content_type = ct.split(";")[0].strip()

            # Wait a bit for JS to execute if rendering is enabled
            if self.config.render_js:
                await page.wait_for_timeout(2000)

            # Get rendered HTML
            html = await page.content()
            soup = BeautifulSoup(html, "lxml")

            self._extract_seo_data(soup, page_data, url)
            self._extract_links(soup, page_data, url)
            self._extract_images(soup, page_data, url)
            self._extract_structured_data(soup, page_data)

        except PlaywrightTimeout:
            page_data.status_code = 0
            page_data.error = "Timeout"
            log.warning(f"Timeout crawling {url}")
        except Exception as e:
            page_data.error = str(e)[:200]
            log.warning(f"Error crawling {url}: {e}")
        finally:
            await page.close()

        return page_data

    def _extract_seo_data(self, soup: BeautifulSoup, pd: PageData, url: str):
        # Title
        title_tag = soup.find("title")
        if title_tag and title_tag.string:
            pd.title = title_tag.string.strip()
            pd.title_length = len(pd.title)

        # Meta description
        meta_desc = soup.find("meta", attrs={"name": "description"})
        if meta_desc and meta_desc.get("content"):
            pd.meta_description = meta_desc["content"].strip()
            pd.meta_description_length = len(pd.meta_description)

        # H1 headings
        for h1 in soup.find_all("h1"):
            text = h1.get_text(strip=True)
            if text:
                pd.h1s.append(text)

        # H2 headings
        for h2 in soup.find_all("h2"):
            text = h2.get_text(strip=True)
            if text:
                pd.h2s.append(text)

        # Canonical
        canon = soup.find("link", rel="canonical")
        if canon and canon.get("href"):
            pd.canonical = canon["href"].strip()

        # Robots directives (meta robots)
        robots = soup.find("meta", attrs={"name": "robots"})
        if robots and robots.get("content"):
            pd.robots_directives = [d.strip().lower()
                                     for d in robots["content"].split(",")]

        # Open Graph tags
        for og in soup.find_all("meta", attrs={"property": re.compile(r"^og:")}):
            prop = og.get("property", "").replace("og:", "")
            if prop and og.get("content"):
                pd.og_tags[prop] = og["content"]

        # Twitter Card tags
        for tc in soup.find_all("meta", attrs={"name": re.compile(r"^twitter:")}):
            name = tc.get("name", "").replace("twitter:", "")
            if name and tc.get("content"):
                pd.twitter_tags[name] = tc["content"]

        # Viewport meta
        vp = soup.find("meta", attrs={"name": "viewport"})
        pd.has_viewport = vp is not None

        # HTML lang
        html_tag = soup.find("html")
        if html_tag and html_tag.get("lang"):
            pd.html_lang = html_tag["lang"]

        # Favicon
        favicon = soup.find("link", rel=re.compile(r"(icon|shortcut icon|apple-touch-icon)"))
        pd.has_favicon = favicon is not None

        # Approximate word count
        for tag in soup(["script", "style", "nav", "footer", "header"]):
            tag.decompose()
        body = soup.find("body")
        if body:
            text = body.get_text(separator=" ", strip=True)
            pd.word_count = len(text.split())

    def _extract_links(self, soup: BeautifulSoup, pd: PageData, base_url: str):
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if not href or href.startswith("#") or href.startswith("javascript:"):
                continue

            absolute_url = urljoin(base_url, href)
            anchor_text = a.get_text(strip=True)[:200]
            rel = a.get("rel", [])
            rel_attrs = [r.lower() for r in rel] if rel else []

            link_data = {
                "href": absolute_url,
                "text": anchor_text,
                "rel": ",".join(rel_attrs) if rel_attrs else "",
                "nofollow": "nofollow" in rel_attrs,
            }

            if is_same_domain(absolute_url, base_url):
                pd.internal_links.append(link_data)
            else:
                pd.external_links.append(link_data)

    def _extract_images(self, soup: BeautifulSoup, pd: PageData, base_url: str):
        for img in soup.find_all("img"):
            src = img.get("src") or img.get("data-src") or ""
            if not src:
                continue
            absolute_src = urljoin(base_url, src)
            alt = img.get("alt", "").strip()
            img_data = {
                "src": absolute_src,
                "alt": alt,
                "has_alt": len(alt) > 0,
                "has_alt_attr": "alt" in img.attrs,
                "width": img.get("width", ""),
                "height": img.get("height", ""),
            }
            pd.images.append(img_data)

    def _extract_structured_data(self, soup: BeautifulSoup, pd: PageData):
        for script in soup.find_all("script", type="application/ld+json"):
            try:
                data = json.loads(script.string) if script.string else None
                if data:
                    pd.structured_data.append(data)
            except (json.JSONDecodeError, TypeError):
                pass

    async def close_browser(self):
        if self.context:
            await self.context.close()
        if self.browser:
            await self.browser.close()


# ─── CSV Export ─────────────────────────────────────────────────────────────

def export_csvs(pages: list[PageData], output_dir: str, start_url: str):
    """Export crawl data to CSV files for the report generator."""
    os.makedirs(output_dir, exist_ok=True)

    # 1. Page Titles
    with open(os.path.join(output_dir, "page-titles.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["URL", "Title", "Title Length", "Status Code", "Error"])
        for p in pages:
            w.writerow([p.url, p.title, p.title_length, p.status_code, p.error])

    # 2. Meta Descriptions
    with open(os.path.join(output_dir, "meta-descriptions.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["URL", "Meta Description", "Description Length", "Status Code"])
        for p in pages:
            w.writerow([p.url, p.meta_description, p.meta_description_length, p.status_code])

    # 3. H1 Headings
    with open(os.path.join(output_dir, "h1-headings.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["URL", "H1 Text", "H1 Count"])
        for p in pages:
            for h1 in p.h1s:
                w.writerow([p.url, h1, len(p.h1s)])

    # 4. H2 Headings
    with open(os.path.join(output_dir, "h2-headings.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["URL", "H2 Text", "H2 Count"])
        for p in pages:
            for h2 in p.h2s:
                w.writerow([p.url, h2, len(p.h2s)])

    # 5. Internal Links
    with open(os.path.join(output_dir, "internal-links.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Source URL", "Target URL", "Anchor Text", "Nofollow"])
        for p in pages:
            for link in p.internal_links:
                w.writerow([p.url, link["href"], link["text"], link["nofollow"]])

    # 6. External Links
    with open(os.path.join(output_dir, "external-links.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Source URL", "Target URL", "Anchor Text", "Nofollow"])
        for p in pages:
            for link in p.external_links:
                w.writerow([p.url, link["href"], link["text"], link["nofollow"]])

    # 7. Images
    with open(os.path.join(output_dir, "images.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Page URL", "Image URL", "Alt Text", "Has Alt", "Has Alt Attr", "Width", "Height"])
        for p in pages:
            for img in p.images:
                w.writerow([p.url, img["src"], img["alt"], img["has_alt"],
                           img["has_alt_attr"], img["width"], img["height"]])

    # 8. Response Codes
    with open(os.path.join(output_dir, "response-codes.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["URL", "Status Code", "Content Type", "Load Time (ms)", "Error"])
        for p in pages:
            w.writerow([p.url, p.status_code, p.content_type, p.load_time_ms, p.error])

    # 9. Structured Data
    with open(os.path.join(output_dir, "structured-data.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["URL", "Structured Data Type", "Valid JSON"])
        for p in pages:
            for sd in p.structured_data:
                sd_type = sd.get("@type", sd.get("type", "Unknown"))
                w.writerow([p.url, sd_type, "Yes"])

    # 10. Directives / Meta
    with open(os.path.join(output_dir, "directives.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["URL", "Canonical", "Robots Directives", "HTML Lang",
                    "Has Viewport", "Has Favicon", "Word Count"])
        for p in pages:
            w.writerow([p.url, p.canonical, ",".join(p.robots_directives),
                       p.html_lang, p.has_viewport, p.has_favicon, p.word_count])

    # 11. Open Graph / Social
    with open(os.path.join(output_dir, "social-tags.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["URL", "Tag Type", "Tag Name", "Tag Value"])
        for p in pages:
            for k, v in p.og_tags.items():
                w.writerow([p.url, "og", k, v])
            for k, v in p.twitter_tags.items():
                w.writerow([p.url, "twitter", k, v])

    # 12. Crawl Summary
    with open(os.path.join(output_dir, "crawl-summary.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Metric", "Value"])
        w.writerow(["Start URL", start_url])
        w.writerow(["Pages Crawled", len(pages)])
        w.writerow(["Status 2xx", sum(1 for p in pages if 200 <= p.status_code < 300)])
        w.writerow(["Status 3xx", sum(1 for p in pages if 300 <= p.status_code < 400)])
        w.writerow(["Status 4xx", sum(1 for p in pages if 400 <= p.status_code < 500)])
        w.writerow(["Status 5xx", sum(1 for p in pages if 500 <= p.status_code < 600)])
        w.writerow(["Errors/Timeouts", sum(1 for p in pages if p.error)])
        w.writerow(["Total Internal Links", sum(len(p.internal_links) for p in pages)])
        w.writerow(["Total External Links", sum(len(p.external_links) for p in pages)])
        w.writerow(["Total Images", sum(len(p.images) for p in pages)])
        w.writerow(["Avg Load Time (ms)",
                    round(sum(p.load_time_ms for p in pages) / max(len(pages), 1), 2)])

    log.info(f"Exported {len(os.listdir(output_dir))} CSV files to {output_dir}")


# ─── Main ───────────────────────────────────────────────────────────────────

async def run_crawl(start_url: str, output_dir: str, max_urls: int = 100, max_depth: int = 3):
    cfg = CrawlConfig(
        start_url=start_url,
        max_urls=max_urls,
        max_depth=max_depth,
        output_dir=output_dir,
    )
    crawler = SEOCrawler(cfg)
    pages = await crawler.crawl()
    export_csvs(pages, output_dir, start_url)
    return pages


# ─── Screaming Frog Backend ────────────────────────────────────────────────

FROG_EXPORT_TABS = (
    "Page Titles:All,Meta Description:All,H1:All,H2:All,"
    "Internal:HTML,External:HTML,Images:All,Response Codes:All,"
    "Directives:All,Structured Data:All"
)


def _normalise_csv_name(value: str) -> str:
    """Return a filename/header comparison key without punctuation."""
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _read_frog_csv(path: Path) -> list[dict[str, str]]:
    """Read a Screaming Frog CSV, tolerating its common encodings."""
    last_error: Optional[Exception] = None
    for encoding in ("utf-8-sig", "utf-16", "latin-1"):
        try:
            with path.open("r", newline="", encoding=encoding) as handle:
                return [dict(row) for row in csv.DictReader(handle)]
        except (UnicodeError, csv.Error) as exc:
            last_error = exc
    raise ValueError(f"Unable to read Screaming Frog CSV {path}: {last_error}")


def _find_frog_export(export_root: Path, *names: str) -> Optional[Path]:
    """Find an export by normalized filename, including timestamped folders."""
    wanted = {_normalise_csv_name(name) for name in names}
    candidates = [path for path in export_root.rglob("*.csv") if path.is_file()]
    for candidate in sorted(candidates):
        if _normalise_csv_name(candidate.stem) in wanted:
            return candidate
    # Frog has changed separators in export names across releases, so use a
    # conservative prefix match after trying the exact names above.
    for candidate in sorted(candidates):
        stem = _normalise_csv_name(candidate.stem)
        if any(stem.startswith(name) or name.startswith(stem) for name in wanted):
            return candidate
    return None


def _frog_value(row: dict[str, str], *headers: str, default: str = "") -> str:
    """Return the first non-empty value whose header matches a known alias."""
    normalised = {_normalise_csv_name(key): value for key, value in row.items()}
    for header in headers:
        value = normalised.get(_normalise_csv_name(header), "")
        if value not in (None, ""):
            return str(value).strip()
    return default


def _frog_bool(value: str) -> bool:
    """Parse Frog's yes/no and true/false values without truthiness traps."""
    return value.strip().lower() in {"1", "true", "yes", "y"}


def _frog_int(value: str, default: int = 0) -> int:
    """Parse a numeric Frog field, returning a safe default for blanks."""
    try:
        return int(re.sub(r"[^0-9-]", "", value)) if value else default
    except ValueError:
        return default


def _frog_prefixed_values(row: dict[str, str], prefix: str) -> list[str]:
    """Collect numbered Screaming Frog columns such as H1-1 and H1-2."""
    prefix_key = _normalise_csv_name(prefix)
    values = []
    for header, value in row.items():
        key = _normalise_csv_name(header)
        if key.startswith(prefix_key) and value and str(value).strip():
            # Exclude length/pixel/count companion columns.
            if any(token in key for token in ("length", "pixel", "count")):
                continue
            values.append(str(value).strip())
    return values


def _frog_page(pages: dict[str, PageData], row: dict[str, str]) -> Optional[PageData]:
    """Get or create a PageData record for one Frog row."""
    url = _frog_value(row, "Address", "URL", "Source URL", "Page URL")
    if not url:
        return None
    page = pages.get(url)
    if page is None:
        page = PageData(url=url)
        pages[url] = page
    return page


def _frog_existing_page(pages: dict[str, PageData], row: dict[str, str]) -> Optional[PageData]:
    """Resolve a resource row to a crawled page without inventing page URLs."""
    url = _frog_value(row, "Source URL", "Page URL", "From", "Source", "Address", "URL")
    return pages.get(url) if url else None


def _frog_resource_page(
    pages: dict[str, PageData], row: dict[str, str], fallback_url: str
) -> Optional[PageData]:
    """Resolve a resource row, falling back to the crawl's seed page."""
    return _frog_existing_page(pages, row) or pages.get(fallback_url) or next(iter(pages.values()), None)


def _map_frog_exports(export_dir: Path, output_dir: str, start_url: str) -> list[PageData]:
    """Map Screaming Frog exports to the pipeline's stable CSV contract."""
    file_aliases = {
        "titles": ("page_titles", "page-titles", "Page Titles"),
        "meta": ("meta_description", "meta-descriptions", "Meta Description"),
        "h1": ("h1", "h1_headings", "H1"),
        "h2": ("h2", "h2_headings", "H2"),
        "internal": ("internal_html", "internal", "Internal"),
        "external": ("external_html", "external", "External"),
        "images": ("images", "image", "Images"),
        "response": ("response_codes", "response-codes", "Response Codes"),
        "directives": ("directives", "Directives"),
        "structured": ("structured_data", "structured-data", "Structured Data"),
    }
    exports = {
        key: _find_frog_export(export_dir, *aliases)
        for key, aliases in file_aliases.items()
    }
    rows = {
        key: (_read_frog_csv(path) if path else [])
        for key, path in exports.items()
    }
    pages: dict[str, PageData] = {}

    # Start with the page-title export, then use response/meta exports when a
    # site omits titles entirely. This preserves one page record per URL.
    for key in ("titles", "response", "meta"):
        for row in rows[key]:
            page = _frog_page(pages, row)
            if page is None:
                continue
            status_code = _frog_value(row, "Status Code")
            if status_code:
                page.status_code = _frog_int(status_code)
            content_type = _frog_value(row, "Content Type")
            if content_type:
                page.content_type = content_type
            page.title = _frog_value(row, "Title 1", "Title") or page.title
            page.title_length = len(page.title)
            page.meta_description = (
                _frog_value(row, "Meta Description 1", "Meta Description")
                or page.meta_description
            )
            page.meta_description_length = len(page.meta_description)
            load_time = _frog_value(row, "Response Time", "Response Time (ms)")
            if load_time:
                try:
                    page.load_time_ms = float(re.sub(r"[^0-9.]", "", load_time))
                except ValueError:
                    pass

    for row in rows["h1"]:
        page = _frog_page(pages, row)
        if page is not None:
            page.h1s.extend(_frog_prefixed_values(row, "H1"))
    for row in rows["h2"]:
        page = _frog_page(pages, row)
        if page is not None:
            page.h2s.extend(_frog_prefixed_values(row, "H2"))

    for row in rows["directives"]:
        page = _frog_page(pages, row)
        if page is None:
            continue
        page.canonical = _frog_value(row, "Canonical Link Element 1", "Canonical")
        robots = _frog_value(row, "Meta Robots 1", "X-Robots-Tag")
        page.robots_directives = [item.strip() for item in robots.split(",") if item.strip()]
        page.html_lang = _frog_value(row, "Language", "HTML Lang")
        page.word_count = _frog_int(_frog_value(row, "Word Count"))
        page.has_viewport = _frog_bool(_frog_value(row, "Viewport", "Meta Viewport"))

    for row in rows["internal"]:
        page = _frog_resource_page(pages, row, start_url)
        if page is not None:
            nofollow = _frog_value(row, "Nofollow")
            follows = not _frog_bool(nofollow) if nofollow else _frog_value(row, "Follow").lower() not in {"false", "no", "0"}
            page.internal_links.append({
                "href": _frog_value(row, "Address", "Target URL", "URL"),
                "text": _frog_value(row, "Anchor Text"),
                "nofollow": not follows,
            })
    for row in rows["external"]:
        page = _frog_resource_page(pages, row, start_url)
        if page is not None:
            nofollow = _frog_value(row, "Nofollow")
            follows = not _frog_bool(nofollow) if nofollow else _frog_value(row, "Follow").lower() not in {"false", "no", "0"}
            page.external_links.append({
                "href": _frog_value(row, "Address", "Target URL", "URL"),
                "text": _frog_value(row, "Anchor Text"),
                "nofollow": not follows,
            })
    for row in rows["images"]:
        page = _frog_resource_page(pages, row, start_url)
        if page is not None:
            alt = _frog_value(row, "Alt Text")
            page.images.append({
                "src": _frog_value(row, "Address", "Image URL", "URL"),
                "alt": alt,
                "has_alt": bool(alt),
                "has_alt_attr": _frog_bool(_frog_value(row, "Alt Attribute")) or bool(alt),
                "width": _frog_value(row, "Width"),
                "height": _frog_value(row, "Height"),
            })
    for row in rows["structured"]:
        page = _frog_page(pages, row)
        if page is not None:
            page.structured_data.append({
                "@type": _frog_value(row, "Type", "Structured Data Type", default="Unknown")
            })

    # export_csvs supplies the exact filenames/headers consumed by the report
    # generator, while keeping Frog-specific column parsing in this adapter.
    export_csvs(list(pages.values()), output_dir, start_url)
    return list(pages.values())


def _find_frog_export_dir(output_root: Path) -> Path:
    """Return the newest timestamped Frog folder containing CSV exports."""
    csv_files = [path for path in output_root.rglob("*.csv") if path.is_file()]
    if not csv_files:
        raise RuntimeError(f"Screaming Frog produced no CSV exports in {output_root}")
    nested_dirs = {path.parent for path in csv_files if path.parent != output_root}
    if nested_dirs:
        return max(nested_dirs, key=lambda path: path.stat().st_mtime)
    return output_root


def run_frog_crawl(
    start_url: str,
    output_dir: str,
    max_urls: int = 100,
    max_depth: int = 3,
    executable: str = "screamingfrogseospider",
    config_path: Optional[str] = None,
) -> list[PageData]:
    """Run Screaming Frog headlessly and adapt its CSV exports.

    Args:
        start_url: Website URL to crawl.
        output_dir: Stable pipeline crawl directory for normalized CSVs.
        max_urls: Maximum URLs; the supplied Frog config remains authoritative.
        max_depth: Maximum crawl depth; the supplied Frog config remains authoritative.
        executable: Screaming Frog executable, injectable for tests.
        config_path: Optional path to a Screaming Frog config file.

    Returns:
        Page records represented by the normalized crawl exports.

    Raises:
        RuntimeError: If Frog is unavailable, fails, or emits no CSV exports.
    """
    del max_urls, max_depth  # The checked-in config owns the free-tier limits.
    output_root = Path(output_dir)
    output_root.mkdir(parents=True, exist_ok=True)
    config = Path(config_path) if config_path else Path(__file__).resolve().parents[1] / ".ScreamingFrogSEOSpider" / "free-audit.seospiderconfig"
    if not config.is_file():
        raise RuntimeError(f"Screaming Frog config not found: {config}")
    if shutil.which(executable) is None and not Path(executable).is_file():
        raise RuntimeError(f"Screaming Frog executable not found: {executable}")

    command = [
        executable, "--headless", "--crawl", start_url, "--config", str(config),
        "--output-folder", str(output_root), "--export-format", "csv",
        "--timestamped-output", "--overwrite", "--export-tabs", FROG_EXPORT_TABS,
    ]
    try:
        completed = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except OSError as exc:
        raise RuntimeError(f"Unable to start Screaming Frog: {exc}") from exc
    if completed.returncode != 0:
        details = (completed.stdout or "").strip()
        raise RuntimeError(
            f"Screaming Frog failed with exit code {completed.returncode}"
            + (f": {details[-2000:]}" if details else "")
        )
    export_dir = _find_frog_export_dir(output_root)
    return _map_frog_exports(export_dir, str(output_root), start_url)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Covered On SEO Crawler")
    parser.add_argument("url", help="URL to crawl")
    parser.add_argument("--output", "-o", default="./crawl-output", help="Output directory")
    parser.add_argument("--max-urls", type=int, default=100, help="Max pages to crawl")
    parser.add_argument("--max-depth", type=int, default=3, help="Max crawl depth")
    args = parser.parse_args()

    pages = asyncio.run(run_crawl(args.url, args.output, args.max_urls, args.max_depth))
    print(f"\n✓ Crawl complete: {len(pages)} pages crawled")
    print(f"  Output: {args.output}")
