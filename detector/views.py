from django.shortcuts import render, redirect
from django.views.decorators.http import require_http_methods
from django.db.models import Count

from .forms import URLScanForm, EmailScanForm
from .models import ScanResult
from .services.url_analyzer import analyze_url
from .services.email_analyzer import analyze_email
from .services.groq_client import classify_phishing


def index(request):
    url_form = URLScanForm()
    email_form = EmailScanForm()
    recent_scans = ScanResult.objects.all()[:10]

    # Get stats
    total_scans = ScanResult.objects.count()
    safe_count = ScanResult.objects.filter(verdict='safe').count()
    suspicious_count = ScanResult.objects.filter(verdict='suspicious').count()
    phishing_count = ScanResult.objects.filter(verdict='phishing').count()

    return render(request, 'detector/index.html', {
        'url_form': url_form,
        'email_form': email_form,
        'recent_scans': recent_scans,
        'total_scans': total_scans,
        'safe_count': safe_count,
        'suspicious_count': suspicious_count,
        'phishing_count': phishing_count,
    })


@require_http_methods(["POST"])
def scan_url(request):
    form = URLScanForm(request.POST)
    if not form.is_valid():
        return redirect('index')

    url = form.cleaned_data['url']
    analysis = analyze_url(url)
    result = classify_phishing('url', url, analysis)

    scan = ScanResult.objects.create(
        scan_type='url',
        input_data=url,
        risk_score=result['risk_score'],
        verdict=result['verdict'],
        explanation=result['explanation'],
        indicators=analysis['indicators'],
    )
    return render(request, 'detector/result.html', {'scan': scan, 'features': analysis['features']})


@require_http_methods(["POST"])
def scan_email(request):
    form = EmailScanForm(request.POST)
    if not form.is_valid():
        return redirect('index')

    email_content = form.cleaned_data['email_content']
    analysis = analyze_email(email_content)
    result = classify_phishing('email', email_content, analysis)

    scan = ScanResult.objects.create(
        scan_type='email',
        input_data=email_content[:5000],
        risk_score=result['risk_score'],
        verdict=result['verdict'],
        explanation=result['explanation'],
        indicators=analysis['indicators'],
    )
    return render(request, 'detector/result.html', {'scan': scan, 'features': analysis['features']})


@require_http_methods(["POST"])
def scan_email_file(request):
    if 'email_file' not in request.FILES:
        return redirect('index')

    uploaded_file = request.FILES['email_file']

    # Validate file extension
    if not uploaded_file.name.endswith('.eml'):
        return redirect('index')

    # Read file content
    try:
        email_content = uploaded_file.read().decode('utf-8', errors='ignore')
    except Exception:
        return redirect('index')

    analysis = analyze_email(email_content)
    result = classify_phishing('email', email_content, analysis)

    scan = ScanResult.objects.create(
        scan_type='email',
        input_data=email_content[:5000],
        risk_score=result['risk_score'],
        verdict=result['verdict'],
        explanation=result['explanation'],
        indicators=analysis['indicators'],
    )
    return render(request, 'detector/result.html', {'scan': scan, 'features': analysis['features']})
