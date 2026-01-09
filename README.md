## Description
    This is a Python3 script used to validate email accounts that belong to Office 365 tenants. 
    This script takes either a single email address or a list of email addresses as input, 
    sends a request to Office 365 without a password, and looks for the "IfExistsResult"
    parameter to be set to 0 for a valid account. Invalid accounts will return a 1.

## Usage
    Requires Python 3 and the Requests library.

    Arguments:
    -e, --email EMAIL        Single email address to validate
    -f, --file FILE          File containing email addresses (one per line)
    -o, --output FILE        Write valid email addresses to file
    -p, --proxy-file FILE    File containing HTTP/HTTPS proxies (one per line)
    -d, --delay SECONDS      Delay between requests (default: 0.5)
    -v, --verbose            Show detailed debug information

    Examples:
    o365creeper-ng.py -e test@example.com
    o365creeper-ng.py -f emails.txt -o valid.txt
    o365creeper-ng.py -f emails.txt -o valid.txt -p proxies.txt -d 1

## FEATURES
    - Automatic proxy rotation on throttling or connection errors
    - Persistent retry logic - never skips entries
    - Tracks and skips failed proxies automatically
    - Falls back to direct connection if all proxies fail
    - Clean output showing which proxy validated each email

## NOTE
    Office 365 may throttle repeated validation attempts (ThrottleStatus = 1), causing 
    temporary false positives. Using proxies and delays helps avoid throttling. Best 
    results with unique email lists.

    This tool is provided as-is with no warranty. Use at your own risk and discretion
