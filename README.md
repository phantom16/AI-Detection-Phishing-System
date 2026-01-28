# AI Phishing Detection System

A web-based phishing detection tool built with Django and Groq AI. Analyze URLs and emails for phishing threats using rule-based feature extraction combined with LLM-powered classification.

## Features

- **URL Analysis** — Scans URLs for phishing indicators: suspicious TLDs, IP-based domains, excessive subdomains, redirect chains, brand impersonation keywords, HTTPS checks, and more.
- **Email Analysis** — Parses email headers and body for phishing signals: urgency/pressure language, sender spoofing, mismatched Reply-To domains, requests for sensitive info, generic greetings, and suspicious links.
- **AI Classification** — Sends extracted features to Groq's Llama 3.3 70B model for intelligent phishing/suspicious/safe classification with confidence scores and explanations.
- **Fallback Scoring** — If the AI API is unavailable, the system falls back to rule-based risk scoring using detected indicators.
- **Scan History** — All scan results are stored in the database and displayed on the home page.

## Tech Stack

| Component | Technology |
|-----------|------------|
| Backend | Django 4.2 |
| AI Engine | Groq API (Llama 3.3 70B) |
| Database | SQLite (default) |
| Frontend | Django Templates + CSS |
| Python Libraries | `groq`, `tldextract`, `python-whois`, `beautifulsoup4`, `requests` |

## Project Structure

```
├── manage.py
├── requirements.txt
├── .env                              # API keys (not committed)
├── .gitignore
│
├── phishing_project/                 # Django project config
│   ├── settings.py                   # Settings, GROQ_API_KEY loaded from .env
│   ├── urls.py                       # Root URL routing
│   ├── wsgi.py
│   └── asgi.py
│
├── detector/                         # Main application
│   ├── models.py                     # ScanResult model (type, verdict, risk score, indicators)
│   ├── views.py                      # Page views: index, scan_url, scan_email
│   ├── urls.py                       # App URL routes
│   ├── forms.py                      # URLScanForm, EmailScanForm
│   ├── admin.py                      # Django admin registration
│   │
│   ├── services/                     # Core analysis logic
│   │   ├── url_analyzer.py           # URL feature extraction and indicator detection
│   │   ├── email_analyzer.py         # Email parsing and phishing signal extraction
│   │   └── groq_client.py           # Groq API integration for AI classification
│   │
│   └── templates/detector/           # HTML templates
│       ├── base.html                 # Base layout with nav
│       ├── index.html                # Scan forms + recent scan history
│       └── result.html               # Color-coded result page with indicators
│
└── static/
    └── css/style.css                 # Dark theme UI styles
```

## How It Works

1. User submits a URL or pastes email content via the web form.
2. The **analyzer service** extracts features and detects phishing indicators using rule-based heuristics.
3. The extracted data is sent to the **Groq AI client**, which prompts Llama 3.3 70B to classify the input as `safe`, `suspicious`, or `phishing` with a 0–100 risk score and explanation.
4. Results are saved to the database and displayed with a color-coded verdict (green/yellow/red).

### URL Indicators Checked

- Suspicious TLDs (.tk, .ml, .xyz, etc.)
- IP address instead of domain name
- Excessive subdomains
- Unusually long URLs
- Special characters in URL
- Missing HTTPS
- Excessive hyphens in domain
- Brand impersonation keywords
- Multiple redirects / cross-domain redirects

### Email Indicators Checked

- Urgency and pressure language
- Mismatched sender and Reply-To domains
- Generic greetings ("Dear Customer")
- Requests for sensitive information
- Common misspellings
- Excessive URLs in body

## Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure environment

Create a `.env` file in the project root:

```
GROQ_API_KEY=gsk_your_api_key_here
DJANGO_SECRET_KEY=your-random-secret-key
```

Get a free Groq API key at [console.groq.com](https://console.groq.com).

### 3. Run migrations

```bash
python manage.py migrate
```

### 4. Start the server

```bash
python manage.py runserver
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000) in your browser.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Home page with scan forms and history |
| POST | `/scan/url/` | Analyze a URL for phishing |
| POST | `/scan/email/` | Analyze email content for phishing |

## License

MIT
