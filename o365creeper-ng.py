#!/usr/bin/env python3

# Created by Korey McKinley, Senior Security Consultant at LMG Security
# https://lmgsecurity.com
# Modified for Python 3 with improved logic flow by UmbraDeorum
# Robustness fixes: JSON-based parsing, HTTP status handling, safe body
# encoding, IfExistsResult 5/6 handling, bounded retry loop, dead code removed.
#
# Intended for authorized security testing only. Enumerating users against a
# tenant you do not own or lack written authorization to test may be unlawful.

import requests as req
import argparse
import json
import time
import sys


# IfExistsResult reference (community-derived, not officially documented):
#   -1 unknown error | 0 exists | 1 not exist | 2 throttled | 4 server error
#    5 exists (different IdP) | 6 exists (domain + additional IdP)
VALID_CODES = (0, 5, 6)
INVALID_CODES = (1,)


def build_body(email):
    """Build the request body safely so odd characters can't break the JSON."""
    return json.dumps({"Username": email})


def interpret_response(status_code, response_text):
    """
    Pure classification of an O365 GetCredentialType reply.

    Returns one of: 'valid', 'invalid', 'throttled', 'unknown'.
    This is deliberately side-effect free so it can be unit tested without
    any network access.
    """
    # HTTP-level throttling / errors are surfaced as status codes, not body fields.
    if status_code == 429:
        return "throttled"
    if status_code != 200:
        return "unknown"

    try:
        data = json.loads(response_text)
    except (ValueError, TypeError):
        return "unknown"

    if not isinstance(data, dict):
        return "unknown"

    # ThrottleStatus is authoritative for throttling when present and non-zero.
    throttle = data.get("ThrottleStatus", 0)
    try:
        if int(throttle) != 1:
            return "throttled"
    except (ValueError, TypeError):
        pass

    if "IfExistsResult" not in data:
        return "unknown"

    try:
        ifexists = int(data["IfExistsResult"])
    except (ValueError, TypeError):
        return "unknown"

    if ifexists in VALID_CODES:
        return "valid"
    if ifexists in INVALID_CODES:
        return "invalid"
    if ifexists == 2:
        return "throttled"
    # -1 (unknown error) and 4 (server error) and anything unexpected
    return "unknown"


def load_proxies(proxy_file):
    """
    Load proxies from a newline-separated file.
    Returns a list of proxy dictionaries (empty list on failure).
    """
    proxies = []
    try:
        with open(proxy_file, "r") as f:
            for line_num, line in enumerate(f, 1):
                proxy = line.strip()
                if not proxy or proxy.startswith("#"):
                    continue

                if not proxy.startswith(
                    ("http://", "https://", "socks4://", "socks5://")
                ):
                    proxy = "http://" + proxy

                if "://" in proxy:
                    proxies.append({"http": proxy, "https": proxy})
                else:
                    print(
                        f"WARNING: Skipping invalid proxy on line {line_num}: {proxy}",
                        file=sys.stderr,
                    )

        print(f"Loaded {len(proxies)} proxies from {proxy_file}", file=sys.stderr)
        return proxies
    except Exception as e:
        print(f"ERROR loading proxies: {e}", file=sys.stderr)
        return []


def validate_email(
    email, url, session, proxies=None, proxy_index=0, verbose=False, failed_proxies=None
):
    """
    Validate a single email against Office 365.
    Returns (result, proxy_index, should_rotate) where result is True/False/None.
    """
    if failed_proxies is None:
        failed_proxies = set()

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    }
    body = build_body(email)

    current_proxy = None
    current_proxy_str = "direct connection"
    if proxies:
        current_proxy = proxies[proxy_index % len(proxies)]
        current_proxy_str = current_proxy["http"]
        if current_proxy_str in failed_proxies:
            if verbose:
                print(f"Skipping known bad proxy: {current_proxy_str}", file=sys.stderr)
            return None, proxy_index, True

    max_retries = 3
    retry_count = 0

    while retry_count < max_retries:
        try:
            if verbose:
                print(f"Trying proxy: {current_proxy_str}", file=sys.stderr)

            response = session.post(
                url, data=body, headers=headers, proxies=current_proxy, timeout=20
            )

            if verbose:
                print(f"Debug - {email} HTTP {response.status_code}:", file=sys.stderr)
                print(response.text[:200], file=sys.stderr)

            kind = interpret_response(response.status_code, response.text)

            if kind == "throttled":
                if verbose:
                    print(
                        f"{email} - THROTTLED on {current_proxy_str}", file=sys.stderr
                    )
                return None, proxy_index, True
            if kind == "valid":
                return True, proxy_index, False
            if kind == "invalid":
                return False, proxy_index, False

            # kind == "unknown": retry a couple of times before giving up
            if verbose:
                print(f"{email} - UNKNOWN response", file=sys.stderr)
            retry_count += 1
            if retry_count < max_retries:
                time.sleep(1)
                continue
            return None, proxy_index, True

        except (
            req.exceptions.ProxyError,
            req.exceptions.ConnectionError,
            req.exceptions.SSLError,
        ):
            retry_count += 1
            if retry_count >= max_retries:
                if current_proxy:
                    failed_proxies.add(current_proxy_str)
                return None, proxy_index, True
            time.sleep(0.5)
            continue

        except req.exceptions.Timeout:
            retry_count += 1
            if retry_count >= max_retries:
                return None, proxy_index, True
            time.sleep(0.5)
            continue

        except Exception as e:
            if verbose:
                print(
                    f"{email} - ERROR: {type(e).__name__}: {str(e)[:100]}",
                    file=sys.stderr,
                )
            retry_count += 1
            if retry_count < max_retries:
                time.sleep(1)
                continue
            return None, proxy_index, True

    return None, proxy_index, True


def process_email(
    email,
    url,
    session,
    output_file=None,
    delay=0,
    proxies=None,
    proxy_index=0,
    verbose=False,
    failed_proxies=None,
):
    """Process a single email: validate it and optionally record it."""
    if failed_proxies is None:
        failed_proxies = set()

    email = email.strip()
    if not email:
        return proxy_index, failed_proxies

    # Bounded so one unresolvable address can't spin indefinitely.
    max_attempts = min(len(proxies) * 2, 40) if proxies else 10
    attempts = 0
    starting_proxy_index = proxy_index
    rotation_count = 0
    result = None

    while attempts < max_attempts:
        attempts += 1
        result, current_proxy_index, should_rotate = validate_email(
            email, url, session, proxies, proxy_index, verbose, failed_proxies
        )

        if result is not None:
            proxy_index = current_proxy_index
            if proxies:
                working_proxy = proxies[proxy_index % len(proxies)]["http"]
                print(
                    f'{email} - {"VALID" if result else "INVALID"} (via {working_proxy})'
                )
            else:
                print(f'{email} - {"VALID" if result else "INVALID"}')

            if result and output_file:
                output_file.write(email + "\n")
                output_file.flush()
            break

        if should_rotate and proxies:
            proxy_index = (current_proxy_index + 1) % len(proxies)
            rotation_count += 1
            if rotation_count % 10 == 0:
                working = len(proxies) - len(failed_proxies)
                print(
                    f"{email} - Rotating proxies... (attempt {rotation_count}, "
                    f"{working}/{len(proxies)} working)",
                    file=sys.stderr,
                )
            if proxy_index == starting_proxy_index and len(failed_proxies) >= len(
                proxies
            ):
                print(
                    f"{email} - All proxies exhausted, clearing failed list and retrying...",
                    file=sys.stderr,
                )
                failed_proxies.clear()
                time.sleep(5)
        elif not proxies:
            if attempts % 3 == 0:
                print(
                    f"{email} - Retrying (attempt {attempts}/{max_attempts})...",
                    file=sys.stderr,
                )
            time.sleep(3)

    if result is None:
        print(
            f"{email} - WARNING: Could not validate after {max_attempts} attempts. "
            f"Trying once more without proxy...",
            file=sys.stderr,
        )
        result, _, _ = validate_email(
            email, url, session, proxies=None, proxy_index=0, verbose=verbose
        )
        if result is not None:
            print(f'{email} - {"VALID" if result else "INVALID"} (direct connection)')
            if result and output_file:
                output_file.write(email + "\n")
                output_file.flush()
        else:
            print(f"{email} - COULD NOT VALIDATE (all methods exhausted)")

    if delay > 0:
        time.sleep(delay)

    return proxy_index, failed_proxies


def main():
    parser = argparse.ArgumentParser(
        description="Enumerates valid email addresses from Office 365 without submitting login attempts."
    )
    parser.add_argument("-e", "--email", help="Single email address to validate.")
    parser.add_argument("-f", "--file", help="List of email addresses, one per line.")
    parser.add_argument(
        "-o", "--output", help="Output valid email addresses to this file."
    )
    parser.add_argument(
        "-d",
        "--delay",
        type=float,
        default=0.5,
        help="Delay in seconds between requests (default: 0.5).",
    )
    parser.add_argument(
        "-p", "--proxy-file", help="File of HTTP/HTTPS proxies, one per line."
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show debug info.")
    args = parser.parse_args()

    url = "https://login.microsoftonline.com/common/GetCredentialType"

    if not args.email and not args.file:
        parser.error("You must specify either -e/--email or -f/--file")
        return

    proxies = None
    if args.proxy_file:
        loaded = load_proxies(args.proxy_file)
        proxies = loaded if loaded else None  # normalize empty -> None
        if proxies is None:
            print(
                "WARNING: No valid proxies loaded, continuing without proxy",
                file=sys.stderr,
            )

    session = req.Session()
    proxy_index = 0
    output_file = open(args.output, "a") if args.output else None

    try:
        if args.file:
            proxy_msg = (
                f" with {len(proxies)} proxies (auto-rotation on throttle/error)"
                if proxies
                else ""
            )
            print(
                f"Processing file with {args.delay}s delay between requests{proxy_msg}...",
                file=sys.stderr,
            )
            failed_proxies = set()
            with open(args.file, "r") as fh:
                for line in fh:
                    proxy_index, failed_proxies = process_email(
                        line,
                        url,
                        session,
                        output_file,
                        args.delay,
                        proxies,
                        proxy_index,
                        args.verbose,
                        failed_proxies,
                    )
        elif args.email:
            process_email(
                args.email,
                url,
                session,
                output_file,
                proxies=proxies,
                proxy_index=0,
                verbose=args.verbose,
                failed_proxies=set(),
            )
    finally:
        if output_file:
            output_file.close()
        session.close()


if __name__ == "__main__":
    main()
