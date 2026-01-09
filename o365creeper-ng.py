#!/usr/bin/env python3

# Created by Korey McKinley, Senior Security Consultant at LMG Security
# https://lmgsecurity.com
# Modified for Python 3 with improved logic flow by UmbraDeorum

# This tool will query the Microsoft Office 365 web server to determine
# if an email account is valid or not. It does not need a password and
# should not show up in the logs of a client's O365 tenant.

# Note: Microsoft has implemented some throttling on this service, so
# quick, repeated attempts to validate the same username over and over
# may produce false positives. This tool is best run after you've gathered
# as many email addresses as possible through OSINT in a list with the
# -f argument.

import requests as req
import argparse
import re
import time
import sys
import random


def load_proxies(proxy_file):
    """
    Load proxies from a newline-separated file.
    Returns a list of proxy dictionaries.
    """
    proxies = []
    try:
        with open(proxy_file, "r") as f:
            for line_num, line in enumerate(f, 1):
                proxy = line.strip()
                if not proxy or proxy.startswith("#"):
                    continue

                # Support various formats
                if not proxy.startswith(
                    ("http://", "https://", "socks4://", "socks5://")
                ):
                    proxy = "http://" + proxy

                # Basic validation
                try:
                    # Check if proxy format is valid
                    if "://" in proxy:
                        proxies.append({"http": proxy, "https": proxy})
                    else:
                        print(
                            f"WARNING: Skipping invalid proxy on line {line_num}: {proxy}",
                            file=sys.stderr,
                        )
                except Exception as e:
                    print(
                        f"WARNING: Error parsing proxy on line {line_num}: {e}",
                        file=sys.stderr,
                    )

        print(f"Loaded {len(proxies)} proxies from {proxy_file}", file=sys.stderr)
        return proxies
    except Exception as e:
        print(f"ERROR loading proxies: {e}", file=sys.stderr)
        return []


def get_next_proxy(proxies, proxy_index, rotate=True):
    """
    DEPRECATED: This function is no longer used.
    Proxy rotation is now handled automatically based on throttling detection.
    """
    if not proxies:
        return None, proxy_index

    if rotate:
        proxy = proxies[proxy_index % len(proxies)]
        return proxy, (proxy_index + 1) % len(proxies)
    else:
        return random.choice(proxies), proxy_index


def validate_email(
    email, url, session, proxies=None, proxy_index=0, verbose=False, failed_proxies=None
):
    """
    Validates a single email address against Office 365.
    Returns (result, new_proxy_index, should_rotate) where:
    - result is True/False/None
    - new_proxy_index is the current proxy index
    - should_rotate indicates if we should switch proxies due to throttling
    """
    if failed_proxies is None:
        failed_proxies = set()

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    }
    body = '{"Username":"%s"}' % email

    # Get current proxy if available
    current_proxy = None
    current_proxy_str = "direct connection"
    if proxies:
        current_proxy = proxies[proxy_index % len(proxies)]
        current_proxy_str = current_proxy["http"]

        # Skip if this proxy has failed too many times
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
            response_text = response.text

            if verbose:
                print(f"Debug - Response for {email}:", file=sys.stderr)
                print(response_text[:200], file=sys.stderr)

            # Check throttle status
            throttle_match = re.search(r'"ThrottleStatus":(\d+)', response_text)
            if throttle_match and throttle_match.group(1) != "0":
                if verbose:
                    print(
                        f"{email} - THROTTLED on {current_proxy_str}", file=sys.stderr
                    )
                return None, proxy_index, True

            # Check for valid email (IfExistsResult:0)
            if re.search(r'"IfExistsResult":0', response_text):
                return True, proxy_index, False
            # Check for invalid email (IfExistsResult:1)
            elif re.search(r'"IfExistsResult":1', response_text):
                return False, proxy_index, False
            else:
                if verbose:
                    print(f"{email} - UNKNOWN response", file=sys.stderr)
                retry_count += 1
                if retry_count < max_retries:
                    time.sleep(1)
                    continue
                else:
                    return None, proxy_index, True

        except (
            req.exceptions.ProxyError,
            req.exceptions.ConnectionError,
            req.exceptions.SSLError,
        ) as e:
            retry_count += 1

            if retry_count >= max_retries:
                # Mark this proxy as problematic after max retries
                if current_proxy:
                    failed_proxies.add(current_proxy_str)
                return None, proxy_index, True
            else:
                time.sleep(0.5)
                continue

        except req.exceptions.Timeout as e:
            retry_count += 1
            if retry_count >= max_retries:
                return None, proxy_index, True
            else:
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
            else:
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
    """
    Process a single email: validate it and optionally write to output file.
    This function will NEVER skip an email - it will keep trying until it gets a definitive result.
    Returns the new proxy_index.
    """
    if failed_proxies is None:
        failed_proxies = set()

    email = email.strip()
    if not email:
        return proxy_index, failed_proxies

    # Keep trying until we get a definitive answer (True or False)
    max_attempts = len(proxies) * 2 if proxies else 10
    attempts = 0
    starting_proxy_index = proxy_index
    rotation_count = 0

    while attempts < max_attempts:
        attempts += 1
        result, current_proxy_index, should_rotate = validate_email(
            email, url, session, proxies, proxy_index, verbose, failed_proxies
        )

        # If we got a definitive result (True or False), we're done
        if result is not None:
            proxy_index = current_proxy_index
            # Show which proxy worked
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

        # If we should rotate proxy (due to throttling or errors)
        if should_rotate and proxies:
            old_index = proxy_index
            proxy_index = (current_proxy_index + 1) % len(proxies)
            rotation_count += 1

            # Show rotation status periodically
            if rotation_count % 10 == 0:
                working = len(proxies) - len(failed_proxies)
                print(
                    f"{email} - Rotating proxies... (attempt {rotation_count}, {working}/{len(proxies)} working)",
                    file=sys.stderr,
                )

            # Check if we've cycled through all proxies
            if proxy_index == starting_proxy_index:
                working = len(proxies) - len(failed_proxies)

                if len(failed_proxies) >= len(proxies):
                    print(
                        f"{email} - All proxies exhausted, clearing failed list and retrying...",
                        file=sys.stderr,
                    )
                    failed_proxies.clear()
                    time.sleep(5)
        elif not proxies:
            # No proxies available, just wait and retry
            if attempts % 3 == 0:
                print(
                    f"{email} - Retrying (attempt {attempts}/{max_attempts})...",
                    file=sys.stderr,
                )
            time.sleep(3)

    # Check if we got a result
    if result is None:
        print(
            f"{email} - WARNING: Could not validate after {max_attempts} attempts. Trying once more without proxy...",
            file=sys.stderr,
        )
        # Final attempt without proxy
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

    # Add delay between requests
    if delay > 0:
        time.sleep(delay)

    return proxy_index, failed_proxies


def main():
    parser = argparse.ArgumentParser(
        description="Enumerates valid email addresses from Office 365 without submitting login attempts."
    )
    parser.add_argument("-e", "--email", help="Single email address to validate.")
    parser.add_argument(
        "-f", "--file", help="List of email addresses to validate, one per line."
    )
    parser.add_argument(
        "-o", "--output", help="Output valid email addresses to the specified file."
    )
    parser.add_argument(
        "-d",
        "--delay",
        type=float,
        default=0.5,
        help="Delay in seconds between requests (default: 0.5, can be 0 when using proxies)",
    )
    parser.add_argument(
        "-p", "--proxy-file", help="File containing HTTP/HTTPS proxies, one per line"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show debug information including API responses",
    )
    args = parser.parse_args()

    url = "https://login.microsoftonline.com/common/GetCredentialType"

    # Validate that at least one input method is provided
    if not args.email and not args.file:
        parser.error("You must specify either -e/--email or -f/--file")
        return

    # Load proxies if specified
    proxies = None
    if args.proxy_file:
        proxies = load_proxies(args.proxy_file)
        if not proxies:
            print(
                "WARNING: No valid proxies loaded, continuing without proxy",
                file=sys.stderr,
            )

    # Create a session for connection pooling
    session = req.Session()
    proxy_index = 0

    # Open output file if specified
    output_file = None
    if args.output:
        output_file = open(args.output, "a")

    try:
        if args.file:
            # Process file with multiple emails
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

            with open(args.file, "r") as file:
                for line in file:
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
            # Process single email
            failed_proxies = set()
            process_email(
                args.email,
                url,
                session,
                output_file,
                proxies=proxies,
                proxy_index=0,
                verbose=args.verbose,
                failed_proxies=failed_proxies,
            )

    finally:
        # Ensure output file is closed properly
        if output_file:
            output_file.close()
        session.close()


if __name__ == "__main__":
    main()