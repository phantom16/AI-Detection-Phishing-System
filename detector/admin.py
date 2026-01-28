from django.contrib import admin
from .models import ScanResult

@admin.register(ScanResult)
class ScanResultAdmin(admin.ModelAdmin):
    list_display = ('scan_type', 'verdict', 'risk_score', 'created_at')
    list_filter = ('scan_type', 'verdict')
