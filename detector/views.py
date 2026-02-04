from django.shortcuts import render, redirect
from django.views.decorators.http import require_http_methods
from django.db.models import Count
from PIL import Image
from pyzbar.pyzbar import decode
import io

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


def qr_scanner(request):
    """QR Scanner page view"""
    recent_qr_scans = ScanResult.objects.filter(scan_type='qr')[:10]
    return render(request, 'detector/qr_scanner.html', {
        'recent_qr_scans': recent_qr_scans,
    })


@require_http_methods(["POST"])
def scan_qr(request):
    """Scan uploaded QR code image and extract URL"""
    if 'qr_image' not in request.FILES:
        return redirect('qr_scanner')

    uploaded_file = request.FILES['qr_image']

    # Validate file type
    allowed_types = ['image/png', 'image/jpeg', 'image/jpg', 'image/gif']
    if uploaded_file.content_type not in allowed_types:
        return redirect('qr_scanner')

    try:
        # Read and decode QR code
        image_data = uploaded_file.read()
        image = Image.open(io.BytesIO(image_data))
        decoded_objects = decode(image)

        if not decoded_objects:
            # No QR code found
            return render(request, 'detector/qr_scanner.html', {
                'error': 'No QR code found in the image. Please try another image.',
                'recent_qr_scans': ScanResult.objects.filter(scan_type='qr')[:10],
            })

        # Get the first decoded QR code data
        qr_data = decoded_objects[0].data.decode('utf-8')

        # Check if it's a URL
        if qr_data.startswith(('http://', 'https://', 'www.')):
            url = qr_data if qr_data.startswith('http') else 'https://' + qr_data

            # Analyze the URL
            analysis = analyze_url(url)
            result = classify_phishing('url', url, analysis)

            scan = ScanResult.objects.create(
                scan_type='qr',
                input_data=url,
                risk_score=result['risk_score'],
                verdict=result['verdict'],
                explanation=result['explanation'],
                indicators=analysis['indicators'],
            )
            return render(request, 'detector/result.html', {'scan': scan, 'features': analysis['features']})
        else:
            # Non-URL QR code content
            return render(request, 'detector/qr_scanner.html', {
                'decoded_content': qr_data,
                'is_not_url': True,
                'recent_qr_scans': ScanResult.objects.filter(scan_type='qr')[:10],
            })

    except Exception as e:
        return render(request, 'detector/qr_scanner.html', {
            'error': f'Error processing image: {str(e)}',
            'recent_qr_scans': ScanResult.objects.filter(scan_type='qr')[:10],
        })
