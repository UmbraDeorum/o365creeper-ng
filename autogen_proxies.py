import requests
from bs4 import BeautifulSoup
import socket
import concurrent.futures
import sys
import re
import argparse
import time

FORCE_GET_COUNTRY_BY_IP = False
PROXYCHAINS_HEADER = '''# proxychains.conf  VER 3.1
#
#        HTTP, SOCKS4, SOCKS5 tunneling proxifier with DNS.
#
random_chain
chain_len = 3
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
'''

# Try to import PySocks for SOCKS testing
try:
    import socks
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False
    print("Warning: PySocks not installed. SOCKS5 testing will be limited.")
    print("Install with: pip install PySocks")

def get_country_by_ip(ip):
    """Get country for an IP address using ip-api.com"""
    try:
        if FORCE_GET_COUNTRY_BY_IP:
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data['status'] == 'success':
                    return data.get('country', 'Unknown')
    except Exception:
        pass
    return 'Unknown'

def get_socks5_proxies():
    """Fetch SOCKS5 proxies from multiple working sources"""
    proxies = []
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    # Source 1: ProxyScrape API (Most reliable)
    try:
        print("Fetching from ProxyScrape API...")
        url = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all&ssl=all&anonymity=all"
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            for line in response.text.strip().split('\n'):
                line = line.strip()
                if ':' in line and line.count(':') == 1:
                    try:
                        ip, port = line.split(':')
                        proxies.append({
                            'ip': ip.strip(),
                            'port': int(port.strip()),
                            'country': 'Unknown',
                            'source': 'proxyscrape'
                        })
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
            for line in response.text.strip().split('\n'):
                line = line.strip()
                if ':' in line and line.count(':') == 1:
                    try:
                        ip, port = line.split(':')
                        proxies.append({
                            'ip': ip.strip(),
                            'port': int(port.strip()),
                            'country': 'Unknown',
                            'source': 'openproxylist'
                        })
                    except ValueError:
                        continue
        print(f"  Found {len(proxies) - count_before} proxies from OpenProxyList")
    except Exception as e:
        print(f"  OpenProxyList failed: {e}")

    # Source 3: GeoNode
    try:
        print("Fetching from GeoNode...")
        url = "https://proxylist.geonode.com/api/proxy-list?protocols=socks5&limit=500&page=1&sort_by=lastChecked&sort_type=desc"
        response = requests.get(url, headers=headers, timeout=15)
        count_before = len(proxies)
        if response.status_code == 200:
            data = response.json()
            for proxy in data.get('data', []):
                proxies.append({
                    'ip': proxy['ip'],
                    'port': int(proxy['port']),
                    'country': proxy.get('country', 'Unknown'),
                    'source': 'geonode'
                })
        print(f"  Found {len(proxies) - count_before} proxies from GeoNode")
    except Exception as e:
        print(f"  GeoNode failed: {e}")

    # Source 4: ProxyList.to
    try:
        print("Fetching from ProxyList.to...")
        url = "https://www.proxylist.to/socks5.txt"
        response = requests.get(url, headers=headers, timeout=15)
        count_before = len(proxies)
        if response.status_code == 200:
            for line in response.text.strip().split('\n'):
                line = line.strip()
                if ':' in line and line.count(':') == 1:
                    try:
                        ip, port = line.split(':')
                        proxies.append({
                            'ip': ip.strip(),
                            'port': int(port.strip()),
                            'country': 'Unknown',
                            'source': 'proxylist.to'
                        })
                    except ValueError:
                        continue
        print(f"  Found {len(proxies) - count_before} proxies from ProxyList.to")
    except Exception as e:
        print(f"  ProxyList.to failed: {e}")

    return remove_duplicates(proxies)

def get_http_proxies():
    """Fetch HTTP/HTTPS proxies from multiple working sources"""
    proxies = []
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    # Source 1: ProxyScrape API for HTTP
    try:
        print("Fetching from ProxyScrape API (HTTP)...")
        url = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all"
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            for line in response.text.strip().split('\n'):
                line = line.strip()
                if ':' in line and line.count(':') == 1:
                    try:
                        ip, port = line.split(':')
                        proxies.append({
                            'ip': ip.strip(),
                            'port': int(port.strip()),
                            'country': 'Unknown',
                            'source': 'proxyscrape'
                        })
                    except ValueError:
                        continue
        print(f"  Found {len(proxies)} proxies from ProxyScrape")
    except Exception as e:
        print(f"  ProxyScrape failed: {e}")

    # Source 2: GeoNode HTTP/HTTPS
    try:
        print("Fetching from GeoNode (HTTP/HTTPS)...")
        url = "https://proxylist.geonode.com/api/proxy-list?protocols=http%2Chttps&limit=500&page=1&sort_by=lastChecked&sort_type=desc"
        response = requests.get(url, headers=headers, timeout=15)
        count_before = len(proxies)
        if response.status_code == 200:
            data = response.json()
            for proxy in data.get('data', []):
                proxies.append({
                    'ip': proxy['ip'],
                    'port': int(proxy['port']),
                    'country': proxy.get('country', 'Unknown'),
                    'source': 'geonode'
                })
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
            soup = BeautifulSoup(response.text, 'html.parser')
            table = soup.find('table', {'class': 'table'})
            if table:
                rows = table.find('tbody').find_all('tr')
                for row in rows:
                    cols = row.find_all('td')
                    if len(cols) >= 7:
                        ip = cols[0].text.strip()
                        port = cols[1].text.strip()
                        country = cols[3].text.strip()
                        https = cols[6].text.strip()
                        
                        if https == 'yes':  # Only high anonymity
                            try:
                                proxies.append({
                                    'ip': ip,
                                    'port': int(port),
                                    'country': country,
                                    'source': 'free-proxy-list'
                                })
                            except ValueError:
                                continue
        print(f"  Found {len(proxies) - count_before} proxies from Free-Proxy-List")
    except Exception as e:
        print(f"  Free-Proxy-List failed: {e}")

    # Source 4: ProxyList.to HTTP
    try:
        print("Fetching from ProxyList.to (HTTP)...")
        url = "https://www.proxylist.to/http.txt"
        response = requests.get(url, headers=headers, timeout=15)
        count_before = len(proxies)
        if response.status_code == 200:
            for line in response.text.strip().split('\n'):
                line = line.strip()
                if ':' in line and line.count(':') == 1:
                    try:
                        ip, port = line.split(':')
                        proxies.append({
                            'ip': ip.strip(),
                            'port': int(port.strip()),
                            'country': 'Unknown',
                            'source': 'proxylist.to'
                        })
                    except ValueError:
                        continue
        print(f"  Found {len(proxies) - count_before} proxies from ProxyList.to")
    except Exception as e:
        print(f"  ProxyList.to failed: {e}")

    return remove_duplicates(proxies)

def remove_duplicates(proxies):
    """Remove duplicate proxies based on IP:Port combination"""
    unique_proxies = []
    seen = set()
    for proxy in proxies:
        key = (proxy['ip'], proxy['port'])
        if key not in seen:
            seen.add(key)
            unique_proxies.append(proxy)
    return unique_proxies

def test_socks5_proxy(proxy_info, timeout=8):
    """Tests a SOCKS5 proxy"""
    if not SOCKS_AVAILABLE:
        return None
        
    ip = proxy_info['ip']
    port = proxy_info['port']
    
    try:
        socks.set_default_proxy(socks.SOCKS5, ip, port)
        socket.socket = socks.socksocket
        
        test_socket = socks.socksocket()
        test_socket.settimeout(timeout)
        test_socket.connect(('httpbin.org', 80))
        test_socket.send(b"GET /ip HTTP/1.1\r\nHost: httpbin.org\r\n\r\n")
        
        response = test_socket.recv(1024)
        test_socket.close()
        
        socks.set_default_proxy()
        
        if response and b'HTTP' in response:
            return proxy_info
            
    except Exception:
        socks.set_default_proxy()
        pass
    
    return None

def test_http_proxy(proxy_info, timeout=8):
    """Tests an HTTP/HTTPS proxy"""
    ip = proxy_info['ip']
    port = proxy_info['port']
    
    proxy_url = f"http://{ip}:{port}"
    proxies = {
        'http': proxy_url,
        'https': proxy_url
    }
    
    try:
        # Test with httpbin
        response = requests.get('http://httpbin.org/ip', 
                              proxies=proxies, 
                              timeout=timeout)
        
        if response.status_code == 200:
            return proxy_info
            
    except Exception:
        pass
    
    return None

def find_working_proxies(proxy_type='socks5', max_workers=30):
    """Main function to find working proxies"""
    print(f"\nFetching {proxy_type.upper()} proxy lists from multiple sources...")
    
    if proxy_type == 'socks5':
        all_proxies = get_socks5_proxies()
        test_function = test_socks5_proxy
    else:  # http/https
        all_proxies = get_http_proxies()
        test_function = test_http_proxy
    
    if not all_proxies:
        print("No proxies found from available sources.")
        return []
    
    print(f"\nFound {len(all_proxies)} unique {proxy_type.upper()} proxies")
    print(f"Testing proxies with {max_workers} concurrent workers...")
    
    working_proxies = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        count_proxies = 0
        future_to_proxy = {
            executor.submit(test_function, proxy): proxy 
            for proxy in all_proxies
        }
        
        for future in concurrent.futures.as_completed(future_to_proxy):
            result = future.result()
            count_proxies += 1
            
            if result:
                working_proxies.append(result)
            
            print(f"\rProgress: {count_proxies}/{len(all_proxies)} tested | {len(working_proxies)} working", end="", flush=True)
    
    print(f"\n\nTesting complete. Found {len(working_proxies)} working proxies.")
    return working_proxies

def save_proxies(working_proxies, proxy_type, output_format='proxychains'):
    """Save proxies to file in specified format"""
    if not working_proxies:
        print("\nNo working proxies to save.")
        return
    
    if proxy_type == 'socks5' and output_format == 'proxychains':
        filename = "proxychains.conf"
        with open(filename, "w") as f:
            f.write(PROXYCHAINS_HEADER)
            
            print(f"\nWorking {proxy_type.upper()} Proxies:")
            print("=" * 60)
            for proxy in working_proxies:
                country = proxy.get('country', 'Unknown')
                line = f"socks5 {proxy['ip']} {proxy['port']} # {country}"
                print(line)
                f.write(line + "\n")
        
        print(f"\nProxies saved to: {filename}")
    
    else:
        # Generic format: IP:PORT
        filename = f"{proxy_type}_proxies.txt"
        with open(filename, "w") as f:
            print(f"\nWorking {proxy_type.upper()} Proxies:")
            print("=" * 60)
            for proxy in working_proxies:
                country = proxy.get('country', 'Unknown')
                line = f"{proxy['ip']}:{proxy['port']} # {country}"
                print(line)
                f.write(f"{proxy['ip']}:{proxy['port']}\n")
        
        print(f"\nProxies saved to: {filename}")

def main():
    parser = argparse.ArgumentParser(
        description='Find and test working proxy servers',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python script.py --type socks5                  # Find SOCKS5 proxies
  python script.py --type http                    # Find HTTP/HTTPS proxies
  python script.py --type socks5 --workers 50     # Use 50 concurrent workers
  python script.py --type http --format list      # Save as simple list
        """
    )
    
    parser.add_argument('--type', '-t', 
                       choices=['socks5', 'http', 'https'],
                       default='socks5',
                       help='Type of proxy to fetch (default: socks5)')
    
    parser.add_argument('--workers', '-w',
                       type=int,
                       default=30,
                       help='Number of concurrent workers (default: 30)')
    
    parser.add_argument('--format', '-f',
                       choices=['proxychains', 'list'],
                       default='proxychains',
                       help='Output format (default: proxychains)')
    
    args = parser.parse_args()
    
    # Normalize http/https to just 'http' for processing
    proxy_type = 'http' if args.type in ['http', 'https'] else 'socks5'
    
    print("=" * 60)
    print("PROXY FINDER - Enhanced Version")
    print("=" * 60)
    print(f"\nConfiguration:")
    print(f"  Proxy Type: {proxy_type.upper()}")
    print(f"  Workers: {args.workers}")
    print(f"  Output Format: {args.format}")
    
    if proxy_type == 'socks5' and not SOCKS_AVAILABLE:
        print("\nERROR: PySocks is required for SOCKS5 proxy testing")
        print("Install it with: pip install PySocks")
        sys.exit(1)
    
    working_proxies = find_working_proxies(proxy_type, args.workers)
    
    if working_proxies:
        save_proxies(working_proxies, proxy_type, args.format)
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