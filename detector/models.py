from django.db import models


class ScanResult(models.Model):
    SCAN_TYPES = [
        ('url', 'URL'),
        ('email', 'Email'),
    ]
    VERDICTS = [
        ('safe', 'Safe'),
        ('suspicious', 'Suspicious'),
        ('phishing', 'Phishing'),
    ]

    scan_type = models.CharField(max_length=10, choices=SCAN_TYPES)
    input_data = models.TextField()
    risk_score = models.FloatField(default=0.0)
    verdict = models.CharField(max_length=20, choices=VERDICTS, default='safe')
    explanation = models.TextField(blank=True)
    indicators = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"[{self.scan_type.upper()}] {self.verdict} - {self.risk_score:.0f}%"
