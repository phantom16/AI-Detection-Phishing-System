import json
import logging

from django.conf import settings
from groq import Groq

logger = logging.getLogger(__name__)

_client = None


def _get_client():
    global _client
    if _client is None:
        _client = Groq(api_key=settings.GROQ_API_KEY)
    return _client


def classify_phishing(scan_type: str, raw_input: str, analysis: dict) -> dict:
    """
    Send analysis data to Groq LLM for phishing classification.
    Returns: {verdict, risk_score, explanation}
    """
    indicators = analysis.get('indicators', [])
    features = analysis.get('features', {})

    prompt = f"""You are a cybersecurity expert specializing in phishing detection.

Analyze the following {scan_type.upper()} and determine if it is phishing, suspicious, or safe.

--- RAW INPUT ---
{raw_input[:3000]}

--- EXTRACTED FEATURES ---
{json.dumps(features, indent=2, default=str)}

--- DETECTED INDICATORS ---
{chr(10).join(f'- {i}' for i in indicators) if indicators else 'None detected'}

Respond ONLY with valid JSON in this exact format:
{{
  "verdict": "phishing" | "suspicious" | "safe",
  "risk_score": <number 0-100>,
  "explanation": "<2-3 sentence explanation>"
}}"""

    try:
        client = _get_client()
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": "You are a phishing detection AI. Always respond with valid JSON only."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
            max_tokens=300,
        )

        text = response.choices[0].message.content.strip()
        # Extract JSON from response
        start = text.find('{')
        end = text.rfind('}') + 1
        if start != -1 and end > start:
            result = json.loads(text[start:end])
            return {
                'verdict': result.get('verdict', 'suspicious'),
                'risk_score': float(result.get('risk_score', 50)),
                'explanation': result.get('explanation', 'Analysis complete.'),
            }
    except Exception as e:
        logger.error(f"Groq API error: {e}")

    # Fallback: rule-based scoring
    score = min(len(indicators) * 15, 100)
    if score >= 60:
        verdict = 'phishing'
    elif score >= 30:
        verdict = 'suspicious'
    else:
        verdict = 'safe'

    return {
        'verdict': verdict,
        'risk_score': score,
        'explanation': f"AI unavailable. Rule-based analysis found {len(indicators)} indicator(s).",
    }
