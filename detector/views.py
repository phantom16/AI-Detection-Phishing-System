from django.shortcuts import render, redirect
from django.views.decorators.http import require_http_methods

from .forms import URLScanForm, EmailScanForm
from .models import ScanResult
from .services.url_analyzer import analyze_url
from .services.email_analyzer import analyze_email
from .services.groq_client import classify_phishing


def index(request):
    url_form = URLScanForm()
    email_form = EmailScanForm()
    recent_scans = ScanResult.objects.all()[:10]
    return render(request, 'detector/index.html', {
        'url_form': url_form,
        'email_form': email_form,
        'recent_scans': recent_scans,
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
