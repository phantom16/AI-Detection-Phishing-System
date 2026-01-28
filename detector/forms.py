from django import forms


class URLScanForm(forms.Form):
    url = forms.URLField(
        label='URL to scan',
        widget=forms.URLInput(attrs={
            'class': 'form-input',
            'placeholder': 'https://example.com/suspicious-link',
        })
    )


class EmailScanForm(forms.Form):
    email_content = forms.CharField(
        label='Paste email content (headers + body)',
        widget=forms.Textarea(attrs={
            'class': 'form-input',
            'placeholder': 'Paste the full email content here...',
            'rows': 12,
        })
    )
