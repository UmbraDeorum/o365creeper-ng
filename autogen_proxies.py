import requests
from bs4 import BeautifulSoup
import concurrent.futures
import sys
import argparse
import time
import json
import ipaddress
import re
import base64
import random

PROXYCHAINS_HEADER = """# proxychains.conf  VER 3.1
#
#        HTTP, SOCKS4, SOCKS5 tunneling proxifier with DNS.
#
random_chain
chain_len = 3
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
"""

# Try to import PySocks for SOCKS testing
try:
    import socks

    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False
    print("Warning: PySocks not installed. SOCKS5 testing will be unavailable.")
    print("Install with: pip install PySocks")


def resolve_countries(proxies):
    """Resolve country for every proxy via ip-api.com's batch endpoint.

    Uses the batch endpoint (up to 100 IPs per request) and paces requests
    to stay under ip-api's free-tier rate limit (~15 batch req/min).
    Overwrites the 'country' field so naming is consistent across sources
    (some sources return ISO codes, others full names).
    """
    if not proxies:
        return
    print(f"\nResolving country info for {len(proxies)} proxies via ip-api.com...")
    for i in range(0, len(proxies), 100):
        chunk = proxies[i : i + 100]
        try:
            payload = [
                {"query": p["ip"], "fields": "status,country,query"} for p in chunk
            ]
            resp = requests.post("http://ip-api.com/batch", json=payload, timeout=20)
            if resp.status_code == 200:
                results = resp.json()
                by_ip = {
                    r.get("query"): r.get("country", "Unknown")
                    for r in results
                    if r.get("status") == "success"
                }
                for p in chunk:
                    p["country"] = by_ip.get(p["ip"], p.get("country", "Unknown"))
            else:
                print(f"  ip-api returned HTTP {resp.status_code} for a batch")
        except Exception as e:
            print(f"  Country resolution failed for a batch: {e}")
        if i + 100 < len(proxies):
            time.sleep(4)  # respect ip-api batch rate limit


# --- gfpcom/free-proxy-list raw lists ------------------------------------
# These are large, frequently-refreshed plain "ip:port" lists, one protocol
# per file. They're reliable and simple, so they're the primary source for
# each protocol. Because they can hold tens of thousands of entries, we take
# a uniform random sample by default rather than test all of them.
GFP_LISTS = {
    "http": "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/http.txt",
    "https": "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/https.txt",
    "socks5": "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/socks5.txt",
}


def get_gfpcom_proxies(protocol, sample_size=1000):
    """Fetch one gfpcom raw list and return a uniform random sample of it.

    `sample_size` is the number of DISTINCT random lines to keep (not the
    first/last N, not a random contiguous block): the whole list is parsed,
    then random.sample draws `sample_size` lines uniformly at random. Pass
    0 (or None) to keep every entry.
    """
    url = GFP_LISTS[protocol]
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    proxies = []
    try:
        print(f"Fetching from gfpcom free-proxy-list ({protocol})...")
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code != 200:
            print(f"  gfpcom returned HTTP {response.status_code}")
            return proxies

        # Collect valid "ip:port" entries first, then sample from that pool.
        # Lines may be bare "ip:port" or scheme-prefixed ("http://ip:port"),
        # so we extract with a regex rather than a strict split.
        lines = []
        raw_nonempty = 0
        for line in response.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            raw_nonempty += 1
            match = _IP_PORT_RE.search(line)
            if not match:
                continue
            ip, port = match.group(1), int(match.group(2))
            if not (0 < port <= 65535):
                continue
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            lines.append((ip, port))

        total = len(lines)
        if total == 0 and raw_nonempty:
            # 200 OK with content, but nothing matched — surface it so an
            # unexpected list format is diagnosable instead of silently empty.
            print(
                f"  gfpcom: received {raw_nonempty} lines but none parsed as "
                f"ip:port (unexpected format?)"
            )
            return proxies

        if sample_size and total > sample_size:
            lines = random.sample(lines, sample_size)  # uniform, distinct
            print(f"  Found {total}; sampled {len(lines)} at random")
        else:
            print(f"  Found {total} proxies from gfpcom")

        for ip, port in lines:
            proxies.append(
                {
                    "ip": ip,
                    "port": port,
                    "country": "Unknown",
                    "protocol": protocol,
                    "source": "gfpcom",
                }
            )
    except Exception as e:
        print(f"  gfpcom ({protocol}) failed: {e}")
    return proxies


def get_socks5_proxies(sample_size=1000):
    """Fetch SOCKS5 proxies from multiple sources."""
    proxies = []
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    # Source 1: ProxyScrape API
    try:
        print("Fetching from ProxyScrape API...")
        url = (
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5"
            "&timeout=10000&country=all&ssl=all&anonymity=all"
        )
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            for line in response.text.strip().split("\n"):
                line = line.strip()
                if ":" in line and line.count(":") == 1:
                    try:
                        ip, port = line.split(":")
                        proxies.append(
                            {
                                "ip": ip.strip(),
                                "port": int(port.strip()),
                                "country": "Unknown",
                                "protocol": "socks5",
                                "source": "proxyscrape",
                            }
                        )
                    except ValueError:
                        continue
        print(f"  Found {len(proxies)} proxies from ProxyScrape")
    except Exception as e:
        print(f"  ProxyScrape failed: {e}")

    # Source 2: OpenProxyList
    try:
        print("Fetching from OpenProxyList...")
        url = "https://openproxylist.xyz/socks5.txt"
        response = requests.get(url, headers=headers, timeout=15)
        count_before = len(proxies)
        if response.status_code == 200:
            for line in response.text.strip().split("\n"):
                line = line.strip()
                if ":" in line and line.count(":") == 1:
                    try:
                        ip, port = line.split(":")
                        proxies.append(
                            {
                                "ip": ip.strip(),
                                "port": int(port.strip()),
                                "country": "Unknown",
                                "protocol": "socks5",
                                "source": "openproxylist",
                            }
                        )
                    except ValueError:
                        continue
        print(f"  Found {len(proxies) - count_before} proxies from OpenProxyList")
    except Exception as e:
        print(f"  OpenProxyList failed: {e}")

    # Source 3: GeoNode
    try:
        print("Fetching from GeoNode...")
        url = (
            "https://proxylist.geonode.com/api/proxy-list?protocols=socks5"
            "&limit=500&page=1&sort_by=lastChecked&sort_type=desc"
        )
        response = requests.get(url, headers=headers, timeout=15)
        count_before = len(proxies)
        if response.status_code == 200:
            data = response.json()
            for proxy in data.get("data", []):
                proxies.append(
                    {
                        "ip": proxy["ip"],
                        "port": int(proxy["port"]),
                        "country": proxy.get("country", "Unknown"),
                        "protocol": "socks5",
                        "source": "geonode",
                    }
                )
        print(f"  Found {len(proxies) - count_before} proxies from GeoNode")
    except Exception as e:
        print(f"  GeoNode failed: {e}")

    # Source 4: gfpcom free-proxy-list (SOCKS5)
    proxies.extend(get_gfpcom_proxies("socks5", sample_size))

    # Source 5: advanced.name (SOCKS5 subset)
    try:
        count_before = len(proxies)
        proxies.extend(
            p for p in get_advanced_name_proxies() if p["protocol"] == "socks5"
        )
        print(f"  Added {len(proxies) - count_before} SOCKS5 from advanced.name")
    except Exception as e:
        print(f"  advanced.name failed: {e}")

    return remove_duplicates(proxies)


def get_http_proxies(sample_size=1000):
    """Fetch HTTP proxies from multiple sources.

    HTTPS-capable proxies are fetched separately by get_https_proxies and
    tagged 'https'; this function returns plain 'http' proxies.
    """
    proxies = []
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    # Source 1: ProxyScrape API for HTTP
    try:
        print("Fetching from ProxyScrape API (HTTP)...")
        url = (
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http"
            "&timeout=10000&country=all&ssl=all&anonymity=all"
        )
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            for line in response.text.strip().split("\n"):
                line = line.strip()
                if ":" in line and line.count(":") == 1:
                    try:
                        ip, port = line.split(":")
                        proxies.append(
                            {
                                "ip": ip.strip(),
                                "port": int(port.strip()),
                                "country": "Unknown",
                                "protocol": "http",
                                "source": "proxyscrape",
                            }
                        )
                    except ValueError:
                        continue
        print(f"  Found {len(proxies)} proxies from ProxyScrape")
    except Exception as e:
        print(f"  ProxyScrape failed: {e}")

    # Source 2: GeoNode HTTP/HTTPS
    try:
        print("Fetching from GeoNode (HTTP)...")
        url = (
            "https://proxylist.geonode.com/api/proxy-list?protocols=http"
            "&limit=500&page=1&sort_by=lastChecked&sort_type=desc"
        )
        response = requests.get(url, headers=headers, timeout=15)
        count_before = len(proxies)
        if response.status_code == 200:
            data = response.json()
            for proxy in data.get("data", []):
                proxies.append(
                    {
                        "ip": proxy["ip"],
                        "port": int(proxy["port"]),
                        "country": proxy.get("country", "Unknown"),
                        "protocol": "http",
                        "source": "geonode",
                    }
                )
        print(f"  Found {len(proxies) - count_before} proxies from GeoNode")
    except Exception as e:
        print(f"  GeoNode failed: {e}")

    # Source 3: Free Proxy List
    try:
        print("Fetching from Free-Proxy-List.net...")
        url = "https://free-proxy-list.net/"
        response = requests.get(url, headers=headers, timeout=15)
        count_before = len(proxies)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            table = soup.find("table", {"class": "table"})
            if table:
                rows = table.find("tbody").find_all("tr")
                for row in rows:
                    cols = row.find_all("td")
                    if len(cols) >= 7:
                        ip = cols[0].text.strip()
                        port = cols[1].text.strip()
                        country = cols[3].text.strip()
                        https = cols[6].text.strip()

                        if https == "yes":  # only proxies flagged HTTPS-capable
                            try:
                                proxies.append(
                                    {
                                        "ip": ip,
                                        "port": int(port),
                                        "country": country,
                                        "protocol": "http",
                                        "source": "free-proxy-list",
                                    }
                                )
                            except ValueError:
                                continue
        print(f"  Found {len(proxies) - count_before} proxies from Free-Proxy-List")
    except Exception as e:
        print(f"  Free-Proxy-List failed: {e}")

    # Source 4: gfpcom free-proxy-list (HTTP)
    proxies.extend(get_gfpcom_proxies("http", sample_size))

    # Source 5: advanced.name (HTTP subset)
    try:
        count_before = len(proxies)
        proxies.extend(
            p for p in get_advanced_name_proxies() if p["protocol"] == "http"
        )
        print(f"  Added {len(proxies) - count_before} HTTP from advanced.name")
    except Exception as e:
        print(f"  advanced.name failed: {e}")

    return remove_duplicates(proxies)


def get_https_proxies(sample_size=1000):
    """Fetch HTTPS-capable proxies from multiple sources.

    These are tagged 'https' and are always validated with a real TLS
    (CONNECT) tunnel by test_proxy, which is what distinguishes them from
    plain 'http' proxies.
    """
    proxies = []
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    # Source 1: gfpcom free-proxy-list (HTTPS)
    proxies.extend(get_gfpcom_proxies("https", sample_size))

    # Source 2: GeoNode (HTTPS only)
    try:
        print("Fetching from GeoNode (HTTPS)...")
        url = (
            "https://proxylist.geonode.com/api/proxy-list?protocols=https"
            "&limit=500&page=1&sort_by=lastChecked&sort_type=desc"
        )
        response = requests.get(url, headers=headers, timeout=15)
        count_before = len(proxies)
        if response.status_code == 200:
            data = response.json()
            for proxy in data.get("data", []):
                proxies.append(
                    {
                        "ip": proxy["ip"],
                        "port": int(proxy["port"]),
                        "country": proxy.get("country", "Unknown"),
                        "protocol": "https",
                        "source": "geonode",
                    }
                )
        print(f"  Found {len(proxies) - count_before} proxies from GeoNode")
    except Exception as e:
        print(f"  GeoNode failed: {e}")

    # Source 3: advanced.name (HTTPS subset)
    try:
        count_before = len(proxies)
        proxies.extend(
            p for p in get_advanced_name_proxies() if p["protocol"] == "https"
        )
        print(f"  Added {len(proxies) - count_before} HTTPS from advanced.name")
    except Exception as e:
        print(f"  advanced.name failed: {e}")

    return remove_duplicates(proxies)


def remove_duplicates(proxies):
    """Remove duplicates keyed on (ip, port, protocol)."""
    unique_proxies = []
    seen = set()
    for proxy in proxies:
        key = (proxy["ip"], proxy["port"], proxy["protocol"])
        if key not in seen:
            seen.add(key)
            unique_proxies.append(proxy)
    return unique_proxies


# --- advanced.name free proxy source -------------------------------------
# The IP and Port columns are base64-encoded in the page to deter scrapers;
# everything else (protocol, country, pagination) is plain HTML.

ADVANCED_NAME_BASE = "https://advanced.name/freeproxy"

# advanced.name lists protocol AND anonymity tokens in the same column.
# We only map the transport protocols this script can actually test.
# SOCKS4 and the anonymity tokens (anon/elite/transparent) are ignored.
_ADV_PROTOCOL_MAP = {"http": "http", "https": "https", "socks5": "socks5"}

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
# Matches an IPv4:port anywhere in a line, tolerating a scheme prefix
# (http://, socks5://, …) and any trailing tokens the list might carry.
_IP_PORT_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})")

_advanced_name_cache = None


def _b64_decode_text(raw):
    """Return the base64-decoded text of `raw`, or None if it isn't base64."""
    s = "".join((raw or "").split())  # drop any embedded whitespace/newlines
    if len(s) < 4 or len(s) % 4 != 0 or not _B64_RE.match(s):
        return None
    try:
        return base64.b64decode(s).decode("utf-8", "ignore").strip() or None
    except Exception:
        return None


def _cell_value_candidates(td):
    """Yield plausible IP/port strings from a table cell.

    Looks at the cell text and common data-* attributes, yielding both the
    raw value and its base64 decoding (when it decodes). Deduped, order
    preserved. This tolerates advanced.name serving plaintext, base64, or
    attribute-embedded values across markup revisions.
    """
    seen = set()
    raw_values = []
    text = td.get_text(strip=True)
    if text:
        raw_values.append(text)
    for attr in ("data-ip", "data-port", "data-value", "data-original", "title"):
        val = td.get(attr)
        if val:
            raw_values.append(val.strip())

    for raw in raw_values:
        for cand in (raw, _b64_decode_text(raw)):
            if cand and cand not in seen:
                seen.add(cand)
                yield cand


def parse_advanced_name_page(html):
    """Parse one advanced.name page.

    Returns (rows, page_numbers) where each row is a dict with keys
    ip, port, protocols (a set), country. page_numbers are the pagination
    targets discovered on the page (used to drive pagination).
    """
    soup = BeautifulSoup(html, "html.parser")
    rows = []

    table = soup.find("table")
    body = table.find("tbody") if table else None
    row_scope = body if body else (table if table else soup)

    for tr in row_scope.find_all("tr"):
        cells = tr.find_all("td")
        if len(cells) < 4:
            continue  # header / decorative rows

        ip = None
        port = None
        for td in cells:
            # The site has historically base64-encoded the IP/port cells, but
            # markup shifts over time (plaintext, or values tucked into
            # data-* attributes). Gather every candidate string per cell and
            # accept the first that looks like an IP / a port, trying both the
            # raw value and its base64 decoding.
            for cand in _cell_value_candidates(td):
                if ip is None and _IPV4_RE.match(cand):
                    ip = cand
                # Port only once the IP is seen: the IP column always precedes
                # the port column, so this skips the leading index number and
                # any trailing plain-number columns (e.g. speed).
                elif ip is not None and port is None and cand.isdigit() and 0 < int(cand) <= 65535:
                    port = int(cand)

        if not ip or port is None:
            continue

        protocols = set()
        for a in tr.select('a[href*="type="]'):
            m = re.search(r"type=(\w+)", a.get("href", ""))
            if m:
                protocols.add(m.group(1).lower())

        country = "Unknown"
        country_link = tr.select_one('a[href*="country="]')
        if country_link:
            m = re.search(r"country=(\w+)", country_link.get("href", ""))
            if m:
                country = m.group(1).upper()

        rows.append(
            {"ip": ip, "port": port, "protocols": protocols, "country": country}
        )

    page_numbers = set()
    for a in soup.select('a[href*="page="]'):
        m = re.search(r"page=(\d+)", a.get("href", ""))
        if m:
            page_numbers.add(int(m.group(1)))

    return rows, sorted(page_numbers)


def get_advanced_name_proxies(fetch_fn=None, max_pages=4):
    """Fetch and expand advanced.name proxies into this script's schema.

    `fetch_fn(url) -> html` is injectable for testing; when None, a real
    HTTP GET is used and the result is cached for the process (both the
    SOCKS5 and HTTP fetchers pull from the same site).
    """
    global _advanced_name_cache

    live = fetch_fn is None
    if live and _advanced_name_cache is not None:
        return _advanced_name_cache

    if fetch_fn is None:

        def fetch_fn(url):
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            }
            r = requests.get(url, headers=headers, timeout=15)
            r.raise_for_status()
            return r.text

    print("Fetching from advanced.name...")
    try:
        first_html = fetch_fn(ADVANCED_NAME_BASE)
    except Exception as e:
        print(f"  advanced.name failed: {e}")
        return []

    all_rows, page_numbers = parse_advanced_name_page(first_html)

    # Follow pagination for the remaining pages (page 1 is already parsed).
    for page in [p for p in page_numbers if p >= 2][: max_pages - 1]:
        try:
            html = fetch_fn(f"{ADVANCED_NAME_BASE}/?page={page}")
            page_rows, _ = parse_advanced_name_page(html)
            all_rows.extend(page_rows)
        except Exception as e:
            print(f"  advanced.name page {page} failed: {e}")

    # Expand each row into one proxy per supported protocol.
    proxies = []
    for row in all_rows:
        for proto in row["protocols"]:
            bucket = _ADV_PROTOCOL_MAP.get(proto)
            if not bucket:
                continue
            proxies.append(
                {
                    "ip": row["ip"],
                    "port": row["port"],
                    "country": row["country"],
                    "protocol": bucket,
                    "source": "advanced.name",
                }
            )

    proxies = remove_duplicates(proxies)
    print(f"  Found {len(proxies)} proxies from advanced.name")

    if live:
        _advanced_name_cache = proxies
    return proxies


# Our own public IP, resolved once at startup. Used to reject transparent
# proxies that leak the real address. None if it could not be determined.
REAL_IP = None


def _extract_ip(text):
    """Pull a valid IP address out of a JSON or plain-text response body."""
    text = (text or "").strip()
    if not text:
        return None

    # Try JSON first (different providers use different keys).
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            for key in ("origin", "ip", "query", "address"):
                val = data.get(key)
                if val:
                    candidate = str(val).split(",")[0].strip()
                    try:
                        ipaddress.ip_address(candidate)
                        return candidate
                    except ValueError:
                        continue
    except (ValueError, TypeError):
        pass

    # Fall back to plain text (e.g. icanhazip, ifconfig.me, checkip).
    candidate = text.split(",")[0].strip().splitlines()[0].strip()
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        return None


def get_real_ip(timeout=10):
    """Resolve our own public IP directly (no proxy), trying several providers.

    Returns None only if every provider fails. Uses a curl-like User-Agent so
    services like icanhazip/ifconfig.me return plain text rather than HTML.
    """
    endpoints = (
        "https://api.ipify.org?format=json",
        "https://checkip.amazonaws.com",
        "https://icanhazip.com",
        "https://ifconfig.me/ip",
        "http://ip-api.com/json/?fields=query",
        "https://httpbin.org/ip",
    )
    headers = {"User-Agent": "curl/8.0.0"}
    for url in endpoints:
        try:
            r = requests.get(url, headers=headers, timeout=timeout)
            if r.status_code == 200:
                ip = _extract_ip(r.text)
                if ip:
                    return ip
        except Exception:
            continue
    return None


def _proxy_url(proxy_info):
    """Build the proxy URL. socks5h keeps DNS resolution on the proxy side."""
    ip, port = proxy_info["ip"], proxy_info["port"]
    if proxy_info["protocol"] == "socks5":
        return f"socks5h://{ip}:{port}"
    return f"http://{ip}:{port}"


def _exit_ip_via(proxy_url, timeout):
    """Route one request through the proxy and return its apparent exit IP.

    Returns the exit IP string on success, or None. This is the cheap,
    default check: it costs a single request but confirms (a) HTTP 200,
    (b) a parseable body, and (c) that our real IP is not leaking through.
    """
    proxies = {"http": proxy_url, "https": proxy_url}
    try:
        r = requests.get("http://httpbin.org/ip", proxies=proxies, timeout=timeout)
        if r.status_code != 200:
            return None
        origin = r.json().get("origin", "")
    except Exception:
        return None

    exit_ips = [ip.strip() for ip in origin.split(",") if ip.strip()]
    if not exit_ips:
        return None
    # Transparent proxy: our real address appears in the forwarded chain.
    if REAL_IP and REAL_IP in exit_ips:
        return None
    return exit_ips[-1]


def _https_ok(proxy_url, timeout):
    """Strict, opt-in check: confirm the proxy can tunnel TLS (CONNECT)."""
    proxies = {"http": proxy_url, "https": proxy_url}
    try:
        r = requests.get("https://httpbin.org/ip", proxies=proxies, timeout=timeout)
        return r.status_code == 200
    except Exception:
        return False


def test_proxy(proxy_info, timeout=8, https_check=False):
    """Validate a proxy. Returns the (annotated) proxy_info if it works.

    Default (balanced): one request, verifying status 200 + exit IP changed.
    Strict (https_check=True): additionally require a working HTTPS tunnel,
    a second request run only on proxies that already passed the cheap check.
    """
    if proxy_info["protocol"] == "socks5" and not SOCKS_AVAILABLE:
        return None

    proxy_url = _proxy_url(proxy_info)

    exit_ip = _exit_ip_via(proxy_url, timeout)
    if not exit_ip:
        return None

    # 'https' proxies are defined by their ability to tunnel TLS, so always
    # verify CONNECT for them. --strict (-s) extends the same check to http.
    if (https_check or proxy_info["protocol"] == "https") and not _https_ok(
        proxy_url, timeout
    ):
        return None

    proxy_info["exit_ip"] = exit_ip
    return proxy_info


def find_working_proxies(
    types,
    max_workers=30,
    limit=None,
    timeout=8,
    https_check=False,
    working_proxies=None,
    out_name="output",
    sample=1000,
):
    """Fetch proxies for the requested types and test them concurrently.

    If `limit` is set, testing stops as soon as `limit` working proxies
    have been found (pending, not-yet-started tasks are cancelled).

    `working_proxies` is the caller-owned accumulator: verified proxies are
    appended to it as they are found, so the caller still has the partial
    results if the run is interrupted with Ctrl+C. `out_name` is only used
    for the interrupt message.
    """
    if working_proxies is None:
        working_proxies = []

    all_proxies = []
    for t in types:
        print(f"\nFetching {t.upper()} proxy lists from multiple sources...")
        if t == "socks5":
            if not SOCKS_AVAILABLE:
                print("  Skipping SOCKS5: PySocks not installed.")
                continue
            fetched = get_socks5_proxies(sample)
        elif t == "https":
            fetched = get_https_proxies(sample)
        else:
            fetched = get_http_proxies(sample)
        print(f"  {len(fetched)} unique {t.upper()} proxies fetched")
        all_proxies.extend(fetched)

    all_proxies = remove_duplicates(all_proxies)

    if not all_proxies:
        print("No proxies found from available sources.")
        return working_proxies

    print(f"\nTotal {len(all_proxies)} unique proxies to test")
    if limit:
        print(f"Will stop early after finding {limit} working proxies")
    print(f"Testing with {max_workers} concurrent workers...\n")

    tested = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_proxy = {
            executor.submit(test_proxy, p, timeout, https_check): p for p in all_proxies
        }
        try:
            for future in concurrent.futures.as_completed(future_to_proxy):
                try:
                    result = future.result()
                except concurrent.futures.CancelledError:
                    continue
                tested += 1
                if result:
                    working_proxies.append(result)

                print(
                    f"\rProgress: {tested}/{len(all_proxies)} tested | "
                    f"{len(working_proxies)} working",
                    end="",
                    flush=True,
                )

                if limit and len(working_proxies) >= limit:
                    print(
                        f"\n\nReached limit of {limit} working proxies. "
                        f"Cancelling remaining tests..."
                    )
                    for f in future_to_proxy:
                        f.cancel()
                    break
        except KeyboardInterrupt:
            # Stop scheduling new work, tell the user we're finishing up, then
            # let the executor drain running threads before we return partials.
            print(f"\n\nCaught Keyboard Interrupt: Please wait for {out_name}...")
            for f in future_to_proxy:
                f.cancel()

    print(f"\nTesting complete. Found {len(working_proxies)} working proxies.")
    return working_proxies


def filter_by_country(working_proxies):
    """Resolve countries, present a sorted/deduplicated list, and filter."""
    if not working_proxies:
        return working_proxies

    resolve_countries(working_proxies)

    countries = sorted(
        {
            p["country"]
            for p in working_proxies
            if p.get("country") and p["country"] != "Unknown"
        }
    )

    if not countries:
        print("\nNo country information available; skipping country filter.")
        return working_proxies

    print("\nAvailable countries:")
    for idx, c in enumerate(countries, 1):
        count = sum(1 for p in working_proxies if p.get("country") == c)
        print(f"  [{idx}] {c} ({count})")

    while True:
        choice = input(
            "\nEnter country ID(s) to keep (comma-separated), or 'all': "
        ).strip()

        if not choice:
            print("Invalid selection. Try again.")
            continue

        if choice.lower() == "all":
            return working_proxies

        try:
            ids = [int(x) for x in choice.split(",") if x.strip()]
        except ValueError:
            print("Invalid selection. Enter numbers only. Try again.")
            continue

        selected = {countries[i - 1] for i in ids if 1 <= i <= len(countries)}
        if not selected:
            print("No valid country IDs entered. Try again.")
            continue

        filtered = [p for p in working_proxies if p.get("country") in selected]
        print(f"\nSelected: {', '.join(sorted(selected))} -> {len(filtered)} proxies")
        return filtered


def output_filename(types, output_format="proxychains"):
    """Return the file path save_proxies will write for the given options."""
    if output_format == "proxychains":
        return "proxychains.conf"
    return f"{types[0]}_proxies.txt" if len(types) == 1 else "proxies.txt"


def save_proxies(working_proxies, types, output_format="proxychains"):
    """Save proxies in the requested format (handles mixed protocols)."""
    if not working_proxies:
        print("\nNo working proxies to save.")
        return

    filename = output_filename(types, output_format)

    if output_format == "proxychains":
        with open(filename, "w") as f:
            f.write(PROXYCHAINS_HEADER)
            print("\nWorking Proxies:")
            print("=" * 60)
            for p in working_proxies:
                country = p.get("country", "Unknown")
                # proxychains only understands http/socks4/socks5; an 'https'
                # proxy is spoken to as an http proxy (it just also tunnels TLS).
                pc_type = "socks5" if p["protocol"] == "socks5" else "http"
                line = f"{pc_type} {p['ip']} {p['port']} # {country} ({p['protocol']})"
                print(line)
                f.write(line + "\n")
        print(f"\n{len(working_proxies)} proxies saved to: {filename}")
    else:
        with open(filename, "w") as f:
            print("\nWorking Proxies:")
            print("=" * 60)
            for p in working_proxies:
                country = p.get("country", "Unknown")
                print(f"{p['protocol']} {p['ip']}:{p['port']} # {country}")
                f.write(f"{p['ip']}:{p['port']}\n")
        print(f"\n{len(working_proxies)} proxies saved to: {filename}")


def parse_types(parser, raw):
    """Parse and normalize the comma-separated --type value."""
    valid = {"socks5", "http", "https"}
    raw_types = [t.strip().lower() for t in raw.split(",") if t.strip()]

    if not raw_types:
        parser.error("no proxy type provided to --type")

    invalid = [t for t in raw_types if t not in valid]
    if invalid:
        parser.error(
            f"invalid proxy type(s): {', '.join(invalid)} "
            f"(choose from: socks5, http, https)"
        )

    # http, https, socks5 are each fetched and validated distinctly.
    # Dedupe while preserving the order the user gave them.
    types = []
    for t in raw_types:
        if t not in types:
            types.append(t)
    return types


def main():
    parser = argparse.ArgumentParser(
        description="Find and test working proxy servers.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python proxy_finder.py -t socks5                 # Find SOCKS5 proxies
  python proxy_finder.py -t http                   # Find plain HTTP proxies
  python proxy_finder.py -t https                  # Find TLS-tunneling (HTTPS) proxies
  python proxy_finder.py -t http,https,socks5      # All three types in one run
  python proxy_finder.py -t socks5 -w 50           # Use 50 concurrent workers
  python proxy_finder.py -t http -f list           # Save as a simple ip:port list
  python proxy_finder.py -t https --sample 2000    # Sample 2000 random gfpcom entries
  python proxy_finder.py -t http --sample 0        # Test every gfpcom entry (no sampling)
  python proxy_finder.py -t socks5,http -l 20      # Stop after 20 working proxies
  python proxy_finder.py -t socks5 -c              # Interactively filter by country
  python proxy_finder.py -t http -s                # Strict: also require HTTPS tunneling
  python proxy_finder.py -t socks5 --timeout 5     # Tighter per-proxy timeout

Note: --limit and --country cannot be used together (see above).
        """,
    )

    parser.add_argument(
        "--type",
        "-t",
        default="socks5",
        metavar="TYPES",
        help="Comma-separated proxy type(s) to fetch from socks5, http, https "
        "(default: socks5). Example: -t socks5,http",
    )

    parser.add_argument(
        "--workers",
        "-w",
        type=int,
        default=30,
        help="Number of concurrent workers (default: 30)",
    )

    parser.add_argument(
        "--format",
        "-f",
        choices=["proxychains", "list"],
        default="proxychains",
        help="Output format (default: proxychains)",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=8.0,
        metavar="SECONDS",
        help="Per-proxy request timeout in seconds (default: 8). "
        "Lower is faster but drops slow-but-working proxies.",
    )

    parser.add_argument(
        "--sample",
        type=int,
        default=1000,
        metavar="N",
        help="For the large gfpcom raw lists (http/https/socks5), keep N "
        "randomly-chosen entries per list (default: 1000; 0 = keep all). "
        "The sample is drawn uniformly at random across the whole list.",
    )

    parser.add_argument(
        "--strict",
        "-s",
        action="store_true",
        help="Also require a working HTTPS (CONNECT) tunnel. Fewer false "
        "positives for real-world use, at the cost of a second request "
        "per passing proxy.",
    )

    # --limit and --country are mutually exclusive. argparse enforces this,
    # prints a message, and exits; the exclusivity is also shown in -h usage.
    exclusive = parser.add_mutually_exclusive_group()
    exclusive.add_argument(
        "--limit",
        "-l",
        type=int,
        default=None,
        metavar="N",
        help="Stop testing once N working proxies are found. "
        "Cannot be combined with --country.",
    )
    exclusive.add_argument(
        "--country",
        "-c",
        action="store_true",
        help="After testing, list the countries found (sorted, deduplicated) "
        "and keep only proxies from the chosen country ID(s). "
        "Cannot be combined with --limit.",
    )

    args = parser.parse_args()

    types = parse_types(parser, args.type)

    if args.limit is not None and args.limit <= 0:
        parser.error("--limit must be a positive integer")
    if args.workers <= 0:
        parser.error("--workers must be a positive integer")
    if args.timeout <= 0:
        parser.error("--timeout must be a positive number")
    if args.sample < 0:
        parser.error("--sample must be 0 (keep all) or a positive integer")

    print("=" * 60)
    print("PROXY FINDER - Enhanced Version")
    print("=" * 60)
    print("\nConfiguration:")
    print(f"  Proxy Type(s):  {', '.join(t.upper() for t in types)}")
    print(f"  Workers:        {args.workers}")
    print(f"  Output Format:  {args.format}")
    print(f"  Timeout:        {args.timeout}s")
    print(
        f"  Validation:     {'strict (HTTP 200 + IP change + HTTPS)' if args.strict else 'balanced (HTTP 200 + IP change)'}"
    )
    print(f"  Limit:          {args.limit if args.limit else 'none'}")
    print(f"  gfpcom Sample:  {args.sample if args.sample else 'all'} per list")
    print(f"  Country Filter: {'yes' if args.country else 'no'}")

    if "socks5" in types and not SOCKS_AVAILABLE:
        if types == ["socks5"]:
            print("\nERROR: PySocks is required for SOCKS5 proxy testing.")
            print("Install it with: pip install PySocks")
            sys.exit(1)
        else:
            print("\nWarning: PySocks not installed; SOCKS5 will be skipped.")

    global REAL_IP
    REAL_IP = get_real_ip()
    if REAL_IP:
        print(f"\nYour public IP: {REAL_IP} (proxies exposing this will be rejected)")
    else:
        print(
            "\nWarning: could not determine your public IP; the leak check "
            "will be skipped (a proxy still must return HTTP 200 with a valid body)."
        )

    out_name = output_filename(types, args.format)
    working_proxies = []
    interrupted = False

    try:
        find_working_proxies(
            types,
            args.workers,
            args.limit,
            args.timeout,
            args.strict,
            working_proxies=working_proxies,
            out_name=out_name,
            sample=args.sample,
        )
        if working_proxies and args.country:
            working_proxies = filter_by_country(working_proxies)
    except KeyboardInterrupt:
        # Safety net: interrupt during fetching, executor shutdown, or the
        # country prompt. find_working_proxies prints its own message when the
        # interrupt lands mid-test, so only announce here if it didn't.
        interrupted = True
        print(f"\n\nCaught Keyboard Interrupt: Please wait for {out_name}...")

    if working_proxies:
        save_proxies(working_proxies, types, args.format)
        if interrupted:
            print("(Partial results saved after interrupt.)")
    elif interrupted:
        print(
            f"\nNo verified proxies were collected before the interrupt; "
            f"{out_name} was not written."
        )
    else:
        print("\nNo working proxies found.")
        print("\nPossible reasons:")
        print("- Free proxies are often unstable and go down frequently")
        print("- Network connectivity issues")
        print("- Firewall blocking connections")
        print("\nTry:")
        print("- Running the script again later")
        print("- Using more workers: --workers 50")
        print("- Checking your internet connection")


if __name__ == "__main__":
    main()
