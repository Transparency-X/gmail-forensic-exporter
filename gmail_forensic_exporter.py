#!/usr/bin/env python3
"""
Gmail Forensic Exporter (GFE)
===========================
Export emails from multiple Gmail accounts filtered by specific
sender/recipient addresses. Generates PDF exports, cryptographic
hashes (SHA-256 + Blake3), and a structured manifest table.

Author: Declan O'Sullivan
License: MIT
"""

import os
import sys
import json
import base64
import hashlib
import argparse
import datetime
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict, Set
from urllib.parse import quote

# ---------------------------------------------------------------------------
# Optional dependencies — graceful degradation
# ---------------------------------------------------------------------------

try:
    import blake3
    HAS_BLAKE3 = True
except ImportError:
    HAS_BLAKE3 = False
    print("[WARN] blake3 not installed. Install: pip install blake3")

try:
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError
    HAS_GOOGLE = True
except ImportError:
    HAS_GOOGLE = False
    print("[WARN] Google API client not installed. Install: pip install google-api-python-client google-auth-httplib2 google-auth-oauthlib")

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False
    print("[WARN] reportlab not installed. Install: pip install reportlab")

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False
    print("[WARN] beautifulsoup4 not installed. Install: pip install beautifulsoup4")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

DEFAULT_CONFIG = {
    "accounts": [
        {
            "name": "account_1",
            "credentials_file": "credentials_account_1.json",
            "token_file": "token_account_1.json"
        }
    ],
    "target_emails": [
        "parent1@example.com",
        "parent2@example.com",
        "sibling@example.com"
    ],
    "output_dir": "./gmail_forensic_export",
    "date_range": {
        "after": "2024-01-01",
        "before": None
    },
    "max_results_per_account": 500,
    "include_attachments": False,
    "pdf_page_size": "A4"
}


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class EmailRecord:
    """Represents a single exported email with forensic metadata."""
    account_name: str
    message_id: str
    thread_id: str
    timestamp: str          # ISO 8601 UTC
    sender: str
    recipients: str         # To + Cc + Bcc as semicolon-separated
    subject: str
    snippet: str
    body_text: str
    body_html: str
    labels: str
    internal_date: int      # Gmail internal timestamp (ms since epoch)
    pdf_filename: str
    sha256_hash: str
    blake3_hash: str
    export_timestamp: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ExportManifest:
    """Top-level manifest for the entire export operation."""
    export_id: str
    export_timestamp: str
    exporter_tool: str
    exporter_version: str
    accounts_processed: List[str]
    target_emails: List[str]
    total_emails_exported: int
    output_directory: str
    manifest_sha256: str
    manifest_blake3: str
    records: List[EmailRecord]


# ---------------------------------------------------------------------------
# Cryptographic Hashing
# ---------------------------------------------------------------------------

def compute_sha256(filepath: Path) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


def compute_blake3(filepath: Path) -> str:
    """Compute Blake3 hash of a file."""
    if not HAS_BLAKE3:
        return "blake3_not_available"
    h = blake3.blake3()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


def compute_string_sha256(data: str) -> str:
    """Compute SHA-256 hash of a string."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


def compute_string_blake3(data: str) -> str:
    """Compute Blake3 hash of a string."""
    if not HAS_BLAKE3:
        return "blake3_not_available"
    return blake3.blake3(data.encode('utf-8')).hexdigest()


# ---------------------------------------------------------------------------
# Gmail API Authentication
# ---------------------------------------------------------------------------

def authenticate_account(account_config: dict, output_dir: Path) -> Optional[Credentials]:
    """Authenticate a single Gmail account via OAuth2."""
    if not HAS_GOOGLE:
        print("[ERROR] Google API libraries not installed.")
        return None

    creds = None
    token_path = output_dir / account_config['token_file']
    credentials_path = Path(account_config['credentials_file'])

    if token_path.exists():
        creds = Credentials.from_authorized_user_file(str(token_path), SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not credentials_path.exists():
                print(f"[ERROR] Credentials file not found: {credentials_path}")
                print(f"        Download from Google Cloud Console > APIs & Services > Credentials")
                return None
            flow = InstalledAppFlow.from_client_secrets_file(
                str(credentials_path), SCOPES)
            creds = flow.run_local_server(port=0)

        # Save token for future runs
        with open(token_path, 'w') as token:
            token.write(creds.to_json())

    return creds


# ---------------------------------------------------------------------------
# Gmail Query Builder
# ---------------------------------------------------------------------------

def build_gmail_query(target_emails: List[str], date_after: Optional[str] = None, 
                       date_before: Optional[str] = None) -> str:
    """Build Gmail search query for target emails (sent OR received)."""
    email_queries = []
    for email in target_emails:
        # Match emails where target is sender OR recipient
        email_queries.append(f"(from:{email} OR to:{email} OR cc:{email} OR bcc:{email})")

    query = " OR ".join(email_queries)

    if date_after:
        query += f" after:{date_after.replace('-', '/')}"
    if date_before:
        query += f" before:{date_before.replace('-', '/')}" 

    return query


# ---------------------------------------------------------------------------
# Email Parsing
# ---------------------------------------------------------------------------

def decode_base64url(data: str) -> bytes:
    """Decode base64url encoded string."""
    padded = data + '=' * (4 - len(data) % 4)
    return base64.urlsafe_b64decode(padded)


def extract_body(parts: list) -> tuple:
    """Recursively extract text and HTML body from message parts."""
    text_body = ""
    html_body = ""

    if not parts:
        return text_body, html_body

    for part in parts:
        mime_type = part.get('mimeType', '')

        if mime_type == 'text/plain' and 'data' in part.get('body', {}):
            text_body += decode_base64url(part['body']['data']).decode('utf-8', errors='replace')
        elif mime_type == 'text/html' and 'data' in part.get('body', {}):
            html_body += decode_base64url(part['body']['data']).decode('utf-8', errors='replace')
        elif 'parts' in part:
            t, h = extract_body(part['parts'])
            text_body += t
            html_body += h

    return text_body, html_body


def html_to_plaintext(html: str) -> str:
    """Convert HTML to plain text for PDF rendering."""
    if HAS_BS4:
        soup = BeautifulSoup(html, 'html.parser')
        return soup.get_text(separator='\n', strip=True)
    # Fallback: simple tag stripping
    import re
    text = re.sub(r'<[^>]+>', '\n', html)
    return re.sub(r'\n+', '\n', text).strip()


def parse_headers(headers: list) -> dict:
    """Extract key headers from Gmail message."""
    result = {
        'From': 'Unknown',
        'To': '',
        'Cc': '',
        'Bcc': '',
        'Subject': '(No Subject)',
        'Date': ''
    }
    for header in headers:
        name = header.get('name', '')
        value = header.get('value', '')
        if name in result:
            result[name] = value
    return result


# ---------------------------------------------------------------------------
# PDF Generation
# ---------------------------------------------------------------------------

def generate_email_pdf(record: EmailRecord, output_path: Path, page_size: str = "A4") -> bool:
    """Generate a forensic PDF for a single email."""
    if not HAS_REPORTLAB:
        print("[WARN] reportlab not installed. Skipping PDF generation.")
        return False

    size = A4 if page_size == "A4" else letter
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=size,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=18
    )

    styles = getSampleStyleSheet()

    # Custom styles
    header_style = ParagraphStyle(
        'ForensicHeader',
        parent=styles['Heading1'],
        fontSize=14,
        textColor=colors.HexColor('#1a1a2e'),
        spaceAfter=12,
        borderWidth=1,
        borderColor=colors.HexColor('#16213e'),
        borderPadding=8,
        backColor=colors.HexColor('#f0f0f0')
    )

    meta_style = ParagraphStyle(
        'MetaData',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.HexColor('#333333'),
        fontName='Courier',
        leading=12
    )

    body_style = ParagraphStyle(
        'EmailBody',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
        spaceAfter=6
    )

    story = []

    # Forensic Header
    story.append(Paragraph("FORENSIC EMAIL EXPORT", header_style))
    story.append(Spacer(1, 12))

    # Metadata Table
    meta_data = [
        ['Message ID:', record.message_id],
        ['Thread ID:', record.thread_id],
        ['Timestamp:', record.timestamp],
        ['From:', record.sender],
        ['To/Cc/Bcc:', record.recipients],
        ['Subject:', record.subject],
        ['Account:', record.account_name],
        ['Labels:', record.labels],
        ['Export Time:', record.export_timestamp],
        ['SHA-256:', record.sha256_hash],
        ['Blake3:', record.blake3_hash],
    ]

    meta_table = Table(meta_data, colWidths=[1.5*inch, 4.5*inch])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e8e8e8')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
        ('ALIGN', (1, 0), (1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Courier-Bold'),
        ('FONTNAME', (1, 0), (1, -1), 'Courier'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 20))

    # Body Header
    story.append(Paragraph("EMAIL CONTENT", header_style))
    story.append(Spacer(1, 12))

    # Body text (escape HTML for PDF)
    body_text = record.body_text or html_to_plaintext(record.body_html)
    # Escape XML special chars for reportlab Paragraph
    body_text = body_text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    # Preserve line breaks
    body_text = body_text.replace('\n', '<br/>')

    story.append(Paragraph(body_text, body_style))
    story.append(Spacer(1, 30))

    # Footer / Chain of Custody
    story.append(Paragraph("CHAIN OF CUSTODY", header_style))
    custody_text = f"""
    This document was generated by Gmail Forensic Exporter (GFE).<br/>
    Export ID: {record.message_id}<br/>
    Cryptographic verification: SHA-256 and Blake3 hashes computed at time of export.<br/>
    Any modification to this PDF will invalidate the hash verification.<br/>
    <br/>
    <b>Integrity Verification:</b><br/>
    SHA-256: {record.sha256_hash}<br/>
    Blake3:  {record.blake3_hash}
    """
    story.append(Paragraph(custody_text, meta_style))

    doc.build(story)
    return True


# ---------------------------------------------------------------------------
# Main Export Logic
# ---------------------------------------------------------------------------

def export_account_emails(account_config: dict, target_emails: List[str],
                          output_dir: Path, date_after: Optional[str] = None,
                          date_before: Optional[str] = None,
                          max_results: int = 500) -> List[EmailRecord]:
    """Export all matching emails from a single Gmail account."""

    if not HAS_GOOGLE:
        print("[ERROR] Cannot export without Google API libraries.")
        return []

    account_name = account_config['name']
    print(f"\n{'='*60}")
    print(f"Processing account: {account_name}")
    print(f"{'='*60}")

    creds = authenticate_account(account_config, output_dir)
    if not creds:
        return []

    service = build('gmail', 'v1', credentials=creds)
    query = build_gmail_query(target_emails, date_after, date_before)

    print(f"Search query: {query}")

    records = []
    page_token = None
    count = 0

    while True:
        try:
            results = service.users().messages().list(
                userId='me',
                q=query,
                maxResults=min(100, max_results - count),
                pageToken=page_token
            ).execute()

            messages = results.get('messages', [])
            if not messages:
                print("No more messages found.")
                break

            for msg_meta in messages:
                if count >= max_results:
                    break

                msg_id = msg_meta['id']
                try:
                    msg = service.users().messages().get(
                        userId='me', 
                        id=msg_id, 
                        format='full'
                    ).execute()
                except HttpError as e:
                    print(f"[ERROR] Failed to fetch message {msg_id}: {e}")
                    continue

                # Parse headers
                payload = msg.get('payload', {})
                headers = parse_headers(payload.get('headers', []))

                # Extract body
                parts = payload.get('parts', [payload])
                text_body, html_body = extract_body(parts)

                # Build recipients string
                recipients = "; ".join(filter(None, [
                    headers['To'], headers['Cc'], headers['Bcc']
                ]))

                # Timestamp
                internal_date_ms = int(msg.get('internalDate', 0))
                dt = datetime.datetime.utcfromtimestamp(internal_date_ms / 1000)
                timestamp_iso = dt.strftime('%Y-%m-%dT%H:%M:%SZ')

                # Labels
                labels = ", ".join(msg.get('labelIds', []))

                # Sanitize filename
                safe_subject = "".join(c if c.isalnum() or c in (' ', '-', '_') else '_' 
                                       for c in headers['Subject'])[:50]
                pdf_filename = f"{account_name}_{dt.strftime('%Y%m%d_%H%M%S')}_{msg_id}_{safe_subject}.pdf"
                pdf_path = output_dir / "pdfs" / pdf_filename

                # Create record (hashes will be added after PDF generation)
                record = EmailRecord(
                    account_name=account_name,
                    message_id=msg_id,
                    thread_id=msg.get('threadId', ''),
                    timestamp=timestamp_iso,
                    sender=headers['From'],
                    recipients=recipients,
                    subject=headers['Subject'],
                    snippet=msg.get('snippet', ''),
                    body_text=text_body,
                    body_html=html_body,
                    labels=labels,
                    internal_date=internal_date_ms,
                    pdf_filename=pdf_filename,
                    sha256_hash="pending",
                    blake3_hash="pending",
                    export_timestamp=datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
                )

                # Generate PDF
                if HAS_REPORTLAB:
                    pdf_path.parent.mkdir(parents=True, exist_ok=True)
                    if generate_email_pdf(record, pdf_path):
                        record.sha256_hash = compute_sha256(pdf_path)
                        record.blake3_hash = compute_blake3(pdf_path)
                        print(f"  [{count+1}] Exported: {pdf_filename}")
                        print(f"       SHA-256: {record.sha256_hash[:16]}...")
                    else:
                        print(f"  [{count+1}] PDF generation failed for {msg_id}")
                else:
                    # No PDF, hash the raw content
                    content = f"{record.body_text}\n{record.body_html}"
                    record.sha256_hash = compute_string_sha256(content)
                    record.blake3_hash = compute_string_blake3(content)
                    print(f"  [{count+1}] No PDF (reportlab missing): {msg_id}")

                records.append(record)
                count += 1

            page_token = results.get('nextPageToken')
            if not page_token or count >= max_results:
                break

        except HttpError as e:
            print(f"[ERROR] Gmail API error: {e}")
            break

    print(f"Total exported from {account_name}: {len(records)} emails")
    return records


# ---------------------------------------------------------------------------
# Manifest & Reporting
# ---------------------------------------------------------------------------

def generate_markdown_table(records: List[EmailRecord], output_path: Path) -> None:
    """Generate a markdown table of all exported emails."""
    lines = [
        "# Gmail Forensic Export — Email Manifest",
        "",
        f"**Export Date:** {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Total Records:** {len(records)}",
        "",
        "| # | Account | Date | From | To/Cc/Bcc | Subject | PDF | SHA-256 (trunc) | Blake3 (trunc) |",
        "|---|---------|------|------|-----------|---------|-----|-----------------|----------------|"
    ]

    for i, r in enumerate(records, 1):
        # Truncate long fields
        subject = r.subject[:40] + "..." if len(r.subject) > 40 else r.subject
        sender = r.sender[:30] + "..." if len(r.sender) > 30 else r.sender
        recipients = r.recipients[:30] + "..." if len(r.recipients) > 30 else r.recipients
        sha_short = r.sha256_hash[:16] + "..." if len(r.sha256_hash) > 16 else r.sha256_hash
        blake_short = r.blake3_hash[:16] + "..." if len(r.blake3_hash) > 16 else r.blake3_hash

        lines.append(
            f"| {i} | {r.account_name} | {r.timestamp[:10]} | {sender} | {recipients} | {subject} | {r.pdf_filename} | {sha_short} | {blake_short} |"
        )

    lines.extend([
        "",
        "## Verification",
        "",
        "To verify integrity of any exported PDF:",
        "",
        "```bash",
        "# SHA-256",
        "sha256sum <pdf_file>",
        "",
        "# Blake3 (requires blake3 CLI)",
        "b3sum <pdf_file>",
        "```",
        "",
        "## Chain of Custody",
        "",
        "All hashes were computed at the time of export. Any modification to the PDF files",
        "will result in a hash mismatch, indicating tampering or corruption.",
        ""
    ])

    output_path.write_text('\n'.join(lines), encoding='utf-8')
    print(f"\n[OK] Markdown manifest saved: {output_path}")


def generate_json_manifest(records: List[EmailRecord], output_dir: Path,
                           accounts: List[str], target_emails: List[str]) -> Path:
    """Generate a machine-readable JSON manifest with top-level hashes."""

    export_id = f"GFE-{datetime.datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
    export_time = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

    manifest = ExportManifest(
        export_id=export_id,
        export_timestamp=export_time,
        exporter_tool="Gmail Forensic Exporter",
        exporter_version="1.0.0",
        accounts_processed=accounts,
        target_emails=target_emails,
        total_emails_exported=len(records),
        output_directory=str(output_dir.resolve()),
        manifest_sha256="pending",
        manifest_blake3="pending",
        records=records
    )

    # Convert to dict
    manifest_dict = {
        "export_id": manifest.export_id,
        "export_timestamp": manifest.export_timestamp,
        "exporter_tool": manifest.exporter_tool,
        "exporter_version": manifest.exporter_version,
        "accounts_processed": manifest.accounts_processed,
        "target_emails": manifest.target_emails,
        "total_emails_exported": manifest.total_emails_exported,
        "output_directory": manifest.output_directory,
        "manifest_sha256": "pending",
        "manifest_blake3": "pending",
        "records": [r.to_dict() for r in records]
    }

    manifest_path = output_dir / "manifest.json"
    json_str = json.dumps(manifest_dict, indent=2, ensure_ascii=False, default=str)
    manifest_path.write_text(json_str, encoding='utf-8')

    # Compute hashes of the manifest file itself
    manifest.sha256_hash = compute_sha256(manifest_path)
    manifest.blake3_hash = compute_blake3(manifest_path)

    # Update and rewrite with hashes
    manifest_dict['manifest_sha256'] = manifest.sha256_hash
    manifest_dict['manifest_blake3'] = manifest.blake3_hash
    json_str = json.dumps(manifest_dict, indent=2, ensure_ascii=False, default=str)
    manifest_path.write_text(json_str, encoding='utf-8')

    print(f"[OK] JSON manifest saved: {manifest_path}")
    print(f"     Manifest SHA-256: {manifest.sha256_hash}")
    print(f"     Manifest Blake3:  {manifest.blake3_hash}")

    return manifest_path


def generate_csv_manifest(records: List[EmailRecord], output_path: Path) -> None:
    """Generate a CSV manifest for spreadsheet import."""
    import csv

    fieldnames = [
        'record_number', 'account_name', 'message_id', 'thread_id',
        'timestamp', 'sender', 'recipients', 'subject', 'snippet',
        'labels', 'pdf_filename', 'sha256_hash', 'blake3_hash',
        'export_timestamp'
    ]

    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for i, r in enumerate(records, 1):
            row = r.to_dict()
            row['record_number'] = i
            writer.writerow(row)

    print(f"[OK] CSV manifest saved: {output_path}")


# ---------------------------------------------------------------------------
# CLI & Entry Point
# ---------------------------------------------------------------------------

def create_sample_config(path: Path) -> None:
    """Create a sample configuration file."""
    path.write_text(json.dumps(DEFAULT_CONFIG, indent=2), encoding='utf-8')
    print(f"[OK] Sample config created: {path}")
    print("     Edit this file with your account details and target emails.")


def main():
    parser = argparse.ArgumentParser(
        description="Gmail Forensic Exporter — Export emails with cryptographic verification",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python gmail_forensic_exporter.py --config config.json
  python gmail_forensic_exporter.py --sample-config
  python gmail_forensic_exporter.py --accounts acct1,acct2 --targets parent@example.com,sibling@example.com
        """
    )
    parser.add_argument('--config', '-c', type=Path, default='gfe_config.json',
                        help='Path to configuration JSON file')
    parser.add_argument('--sample-config', action='store_true',
                        help='Create a sample configuration file and exit')
    parser.add_argument('--accounts', type=str,
                        help='Comma-separated account names (override config)')
    parser.add_argument('--targets', type=str,
                        help='Comma-separated target email addresses (override config)')
    parser.add_argument('--output', '-o', type=Path,
                        help='Output directory (override config)')
    parser.add_argument('--after', type=str,
                        help='Only emails after YYYY-MM-DD')
    parser.add_argument('--before', type=str,
                        help='Only emails before YYYY-MM-DD')
    parser.add_argument('--max-results', type=int, default=500,
                        help='Maximum emails per account (default: 500)')
    parser.add_argument('--no-pdf', action='store_true',
                        help='Skip PDF generation, export metadata only')

    args = parser.parse_args()

    if args.sample_config:
        create_sample_config(Path('gfe_config.json'))
        return

    # Load or build config
    if args.config.exists():
        config = json.loads(args.config.read_text(encoding='utf-8'))
    else:
        print(f"[WARN] Config not found: {args.config}")
        print("       Creating default config...")
        create_sample_config(args.config)
        print("       Please edit the config and re-run.")
        return

    # Override with CLI args
    if args.accounts:
        account_names = args.accounts.split(',')
        config['accounts'] = [
            {"name": name.strip(),
             "credentials_file": f"credentials_{name.strip()}.json",
             "token_file": f"token_{name.strip()}.json"}
            for name in account_names
        ]

    if args.targets:
        config['target_emails'] = [e.strip() for e in args.targets.split(',')]

    if args.output:
        config['output_dir'] = str(args.output)

    if args.after:
        config['date_range']['after'] = args.after
    if args.before:
        config['date_range']['before'] = args.before

    # Setup output directory
    output_dir = Path(config['output_dir'])
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "pdfs").mkdir(exist_ok=True)

    print("="*60)
    print("GMAIL FORENSIC EXPORTER v1.0.0")
    print("="*60)
    print(f"Output directory: {output_dir.resolve()}")
    print(f"Target emails: {', '.join(config['target_emails'])}")
    print(f"Accounts: {', '.join(a['name'] for a in config['accounts'])}")
    print(f"Date range: {config['date_range'].get('after', 'all')} to {config['date_range'].get('before', 'now')}")
    print("="*60)

    # Export all accounts
    all_records: List[EmailRecord] = []

    for account in config['accounts']:
        records = export_account_emails(
            account,
            config['target_emails'],
            output_dir,
            date_after=config['date_range'].get('after'),
            date_before=config['date_range'].get('before'),
            max_results=args.max_results
        )
        all_records.extend(records)

    if not all_records:
        print("\n[!] No emails found matching criteria.")
        return

    # Sort by timestamp
    all_records.sort(key=lambda r: r.internal_date)

    print(f"\n{'='*60}")
    print(f"EXPORT COMPLETE — {len(all_records)} total records")
    print(f"{'='*60}")

    # Generate manifests
    generate_markdown_table(all_records, output_dir / "manifest.md")
    generate_json_manifest(
        all_records, output_dir,
        [a['name'] for a in config['accounts']],
        config['target_emails']
    )
    generate_csv_manifest(all_records, output_dir / "manifest.csv")

    print(f"\n{'='*60}")
    print("ALL OUTPUTS:")
    print(f"  PDFs:      {output_dir / 'pdfs/'}")
    print(f"  Markdown:  {output_dir / 'manifest.md'}")
    print(f"  JSON:      {output_dir / 'manifest.json'}")
    print(f"  CSV:       {output_dir / 'manifest.csv'}")
    print(f"{'='*60}")


if __name__ == '__main__':
    main()
