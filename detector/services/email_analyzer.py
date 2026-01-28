import re
from email import policy
from email.parser import Parser


def analyze_email(raw_email: str) -> dict:
    """Extract phishing indicators from raw email content."""
    indicators = []
    features = {}

    # Try parsing as structured email
    try:
        msg = Parser(policy=policy.default).parsestr(raw_email)
        features['subject'] = msg.get('subject', '')
        features['from'] = msg.get('from', '')
        features['to'] = msg.get('to', '')
        features['reply_to'] = msg.get('reply-to', '')
        body = msg.get_body(preferencelist=('plain', 'html'))
        features['body'] = body.get_content() if body else raw_email
    except Exception:
        # Treat as plain text
        features['subject'] = ''
        features['from'] = ''
        features['to'] = ''
        features['reply_to'] = ''
        features['body'] = raw_email

    body_text = features['body']

    # Urgency keywords
    urgency_words = [
        'urgent', 'immediately', 'action required', 'suspended', 'verify your',
        'confirm your', 'unauthorized', 'expire', 'limited time', 'act now',
        'click here', 'update your', 'unusual activity', 'security alert',
    ]
    found_urgency = [w for w in urgency_words if w.lower() in body_text.lower()]
    if found_urgency:
        indicators.append(f"Urgency/pressure language: {', '.join(found_urgency)}")
    features['urgency_word_count'] = len(found_urgency)

    # Extract URLs from body
    urls = re.findall(r'https?://[^\s<>"\']+', body_text)
    features['url_count'] = len(urls)
    if len(urls) > 5:
        indicators.append(f"Contains many URLs ({len(urls)})")

    # Check for mismatched sender
    sender = features.get('from', '')
    reply_to = features.get('reply_to', '')
    if sender and reply_to and sender != reply_to:
        sender_domain = _extract_domain(sender)
        reply_domain = _extract_domain(reply_to)
        if sender_domain and reply_domain and sender_domain != reply_domain:
            indicators.append(f"Reply-To domain ({reply_domain}) differs from sender ({sender_domain})")

    # Generic greeting
    generic_greetings = ['dear customer', 'dear user', 'dear account holder', 'dear valued']
    for g in generic_greetings:
        if g in body_text.lower():
            indicators.append("Uses generic greeting instead of your name")
            break

    # Asks for sensitive info
    sensitive_patterns = [
        r'password', r'social security', r'ssn', r'credit card',
        r'bank account', r'pin number', r'login credential',
    ]
    for pat in sensitive_patterns:
        if re.search(pat, body_text, re.IGNORECASE):
            indicators.append(f"Requests sensitive information ({pat})")
            break

    # Spelling/grammar signals (simple heuristic)
    misspell_patterns = [r'recieve', r'verifiy', r'accout', r'informations', r'securty']
    for pat in misspell_patterns:
        if re.search(pat, body_text, re.IGNORECASE):
            indicators.append("Contains common misspellings (possible phishing indicator)")
            break

    features['indicator_count'] = len(indicators)

    return {
        'features': features,
        'indicators': indicators,
    }


def _extract_domain(email_str: str) -> str:
    match = re.search(r'@([\w.-]+)', email_str)
    return match.group(1).lower() if match else ''
