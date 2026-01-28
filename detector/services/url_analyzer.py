import re
import socket
from urllib.parse import urlparse

import requests
import tldextract


def analyze_url(url: str) -> dict:
    """Extract phishing indicators from a URL."""
    indicators = []
    features = {}

    parsed = urlparse(url)
    extracted = tldextract.extract(url)

    # Basic features
    features['url_length'] = len(url)
    features['domain'] = extracted.registered_domain
    features['subdomain'] = extracted.subdomain
    features['tld'] = extracted.suffix
    features['uses_https'] = parsed.scheme == 'https'
    features['has_port'] = parsed.port is not None
    features['path_depth'] = len([p for p in parsed.path.split('/') if p])

    # Suspicious TLDs commonly used in phishing
    suspicious_tlds = {'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'buzz', 'club', 'work', 'info'}
    if extracted.suffix in suspicious_tlds:
        indicators.append(f"Suspicious TLD: .{extracted.suffix}")

    # IP address instead of domain
    try:
        socket.inet_aton(extracted.domain)
        indicators.append("URL uses an IP address instead of a domain name")
        features['is_ip_based'] = True
    except socket.error:
        features['is_ip_based'] = False

    # Excessive subdomains
    if extracted.subdomain.count('.') >= 2:
        indicators.append(f"Excessive subdomains: {extracted.subdomain}")

    # URL length
    if len(url) > 75:
        indicators.append(f"Unusually long URL ({len(url)} characters)")

    # Special characters
    special_count = len(re.findall(r'[@!#\$%\^&\*]', url))
    if special_count > 0:
        indicators.append(f"Contains {special_count} special character(s)")
        features['special_chars'] = special_count

    # No HTTPS
    if not features['uses_https']:
        indicators.append("Does not use HTTPS")

    # Hyphen abuse in domain
    if extracted.domain.count('-') >= 3:
        indicators.append("Excessive hyphens in domain name")

    # Known brand impersonation keywords
    brand_keywords = ['login', 'signin', 'verify', 'account', 'secure', 'update',
                      'banking', 'paypal', 'apple', 'microsoft', 'google', 'amazon']
    domain_lower = extracted.domain.lower()
    for kw in brand_keywords:
        if kw in domain_lower and extracted.registered_domain not in [
            f'{kw}.com', f'{kw}.org', f'{kw}.net'
        ]:
            indicators.append(f"Domain contains brand keyword '{kw}'")
            break

    # Check redirects
    features['redirects'] = 0
    try:
        resp = requests.head(url, allow_redirects=True, timeout=5)
        features['redirects'] = len(resp.history)
        features['final_url'] = resp.url
        if features['redirects'] > 2:
            indicators.append(f"Multiple redirects detected ({features['redirects']})")
        if resp.url and tldextract.extract(resp.url).registered_domain != extracted.registered_domain:
            indicators.append("Redirects to a different domain")
    except requests.RequestException:
        indicators.append("URL is unreachable or timed out")

    features['indicator_count'] = len(indicators)

    return {
        'features': features,
        'indicators': indicators,
    }
