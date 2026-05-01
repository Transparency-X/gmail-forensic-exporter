# Gmail Forensic Exporter (GFE)

> **Cryptographically-verified email export from multiple Gmail accounts with PDF generation, dual-hash integrity (SHA-256 + Blake3), and structured forensic manifests.**

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Gmail API](https://img.shields.io/badge/Gmail%20API-v1-red.svg)](https://developers.google.com/gmail/api)

---

## Overview

**Gmail Forensic Exporter (GFE)** is a single-file Python tool designed for individuals who need to extract, preserve, and verify email communications from multiple Gmail accounts — particularly for legal, archival, or evidentiary purposes. The tool filters emails by specific sender/recipient addresses (e.g., family members, legal contacts), generates individual PDF exports with embedded metadata, computes **SHA-256** and **Blake3** cryptographic hashes for every file, and produces machine-readable manifests in **Markdown**, **JSON**, and **CSV** formats.

Built with forensic rigor: every export is tamper-evident, timestamped, and includes a chain-of-custody block within each PDF.

---

## Features

### Core Export
- **Multi-Account Support** — Connect to and export from multiple Gmail accounts sequentially via OAuth2
- **Targeted Filtering** — Filter emails by specific addresses across `From`, `To`, `Cc`, and `Bcc` fields
- **Date Range Filtering** — Restrict exports to specific date windows (`after:`, `before:`)
- **Full Message Retrieval** — Fetches complete message payloads including text and HTML bodies

### Forensic Integrity
- **Dual-Hash Verification** — Every exported PDF is hashed with both **SHA-256** (NIST standard) and **Blake3** (high-performance modern hash)
- **Manifest Self-Hashing** — The JSON manifest itself is hashed after generation to detect tampering
- **Chain of Custody** — Each PDF includes an embedded integrity block with export timestamps and hash values
- **Immutable Timestamps** — All records use UTC ISO-8601 timestamps; Gmail internal dates preserved as epoch milliseconds

### Output Formats
- **Individual PDFs** — One PDF per email with forensic header, body content, and custody footer
- **Markdown Manifest** — Human-readable table with truncated hashes for quick review
- **JSON Manifest** — Machine-readable full manifest with all metadata and complete hashes
- **CSV Manifest** — Spreadsheet-compatible for import into Excel, Google Sheets, or databases

### Usability
- **Single-File Script** — No complex package structure; one `.py` file handles everything
- **Configuration-Driven** — JSON config file for repeatable, auditable export profiles
- **CLI Overrides** — Override config values via command-line arguments for one-off runs
- **Graceful Degradation** — Works even if optional dependencies (`blake3`, `reportlab`) are missing
- **Token Persistence** — OAuth2 tokens cached per-account to avoid repeated authentication

---

## Quick Start

### 1. Clone or Download

```bash
git clone https://github.com/declanosullivan/gmail-forensic-exporter.git
cd gmail-forensic-exporter
```

### 2. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate        # Linux/macOS
# venv\Scripts\activate         # Windows
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Set Up Google Cloud Credentials

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project (or select existing)
3. Navigate to **APIs & Services > Credentials**
4. Click **Create Credentials > OAuth client ID**
5. Select **Desktop app** as application type
6. Download the JSON credentials file
7. Rename it to match your config (e.g., `credentials_account_1.json`)

> **Note:** Enable the **Gmail API** under APIs & Services > Library before creating credentials.

### 5. Create Configuration File

```bash
python gmail_forensic_exporter.py --sample-config
```

Edit `gfe_config.json`:

```json
{
  "accounts": [
    {
      "name": "personal",
      "credentials_file": "credentials_personal.json",
      "token_file": "token_personal.json"
    },
    {
      "name": "work",
      "credentials_file": "credentials_work.json",
      "token_file": "token_work.json"
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
    "before": null
  },
  "max_results_per_account": 500,
  "include_attachments": false,
  "pdf_page_size": "A4"
}
```

### 6. Run Export

```bash
python gmail_forensic_exporter.py --config gfe_config.json
```

Or use CLI overrides:

```bash
python gmail_forensic_exporter.py \
  --accounts personal,work \
  --targets parent1@example.com,parent2@example.com \
  --after 2024-01-01 \
  --max-results 200
```

---

## Output Structure

```
gmail_forensic_export/
├── pdfs/
│   ├── personal_20240115_093022_18a3f7..._Subject_Line.pdf
│   ├── personal_20240116_142511_9b2e1d..._Re_Meeting.pdf
│   ├── work_20240120_081134_3c5a8f..._Contract_Draft.pdf
│   └── ...
├── manifest.md          # Human-readable markdown table
├── manifest.json        # Full machine-readable manifest with hashes
└── manifest.csv         # Spreadsheet-compatible CSV
```

---

## Verification

### Verify a Single PDF

```bash
# SHA-256
sha256sum gmail_forensic_export/pdfs/personal_20240115_093022_*.pdf

# Blake3 (requires b3sum)
b3sum gmail_forensic_export/pdfs/personal_20240115_093022_*.pdf
```

### Verify Manifest Integrity

```bash
sha256sum gmail_forensic_export/manifest.json
# Compare against manifest.json -> manifest_sha256 field
```

---

## Requirements

| Dependency | Purpose | Required |
|---|---|---|
| `google-api-python-client` | Gmail API access | Yes |
| `google-auth-httplib2` | HTTP transport for auth | Yes |
| `google-auth-oauthlib` | OAuth2 flow | Yes |
| `reportlab` | PDF generation | No (recommended) |
| `blake3` | Blake3 hashing | No (recommended) |
| `beautifulsoup4` | HTML-to-text conversion | No (recommended) |

See `requirements.txt` for pinned versions.

---

## Command-Line Reference

```
usage: gmail_forensic_exporter.py [-h] [--config CONFIG] [--sample-config]
                                  [--accounts ACCOUNTS] [--targets TARGETS]
                                  [--output OUTPUT] [--after AFTER]
                                  [--before BEFORE] [--max-results MAX_RESULTS]
                                  [--no-pdf]

Gmail Forensic Exporter

optional arguments:
  -h, --help            show this help message and exit
  --config CONFIG, -c CONFIG
                        Path to configuration JSON file (default: gfe_config.json)
  --sample-config       Create a sample configuration file and exit
  --accounts ACCOUNTS   Comma-separated account names (override config)
  --targets TARGETS     Comma-separated target email addresses (override config)
  --output OUTPUT, -o OUTPUT
                        Output directory (override config)
  --after AFTER         Only emails after YYYY-MM-DD
  --before BEFORE       Only emails before YYYY-MM-DD
  --max-results MAX_RESULTS
                        Maximum emails per account (default: 500)
  --no-pdf              Skip PDF generation, export metadata only
```

---

## Roadmap

### v1.1.0 — Attachment Support
- [ ] Export attachments alongside PDFs with individual hash verification
- [ ] Attachment manifest appendix in JSON/CSV outputs
- [ ] MIME type classification and size reporting

### v1.2.0 — Thread Reconstruction
- [ ] Group emails by Gmail `threadId` into consolidated thread PDFs
- [ ] Thread-level manifest entries with participant lists
- [ ] Chronological thread timeline export

### v1.3.0 — Advanced Filtering
- [ ] Label-based filtering (e.g., only `INBOX`, exclude `SPAM`)
- [ ] Keyword/body text search within filtered results
- [ ] Regex-based subject filtering
- [ ] Size-based filtering (e.g., exclude emails > 25MB)

### v1.4.0 — Export Formats
- [ ] **EML export** — Raw RFC-2822 message export for legal tools
- [ ] **MBOX export** — Standard Unix mailbox format
- [ ] **PST export** — Outlook-compatible archive (via `libpff`)

### v1.5.0 — Evidence Packaging
- [ ] **Tamper-evident ZIP** — Export all outputs into a password-protected ZIP with manifest
- [ ] **Digital signature** — Optional GPG signing of manifest and ZIP
- [ ] **Audit log** — Timestamped log of every API call and export action

### v2.0.0 — Multi-Provider Support
- [ ] **Microsoft 365 / Outlook** integration via Microsoft Graph API
- [ ] **IMAP generic backend** for non-Gmail providers
- [ ] Unified manifest schema across all providers

### v2.1.0 — Web Dashboard
- [ ] Streamlit-based local web UI for configuration and export monitoring
- [ ] Real-time export progress with per-account status
- [ ] In-browser PDF preview and hash verification

### v2.2.0 — Legal Compliance
- [ ] **GDPR Article 15** (Right of Access) formatted export template
- [ ] **eDiscovery** metadata standards (EDRM XML output)
- [ ] Bates numbering for PDF pages
- [ ] Redaction support for sensitive third-party data

---

## Security & Privacy

- **Read-Only Access** — Uses `gmail.readonly` OAuth scope; never modifies, deletes, or sends emails
- **Local Processing** — All data processing happens locally; no data is transmitted to third-party servers
- **Token Security** — OAuth tokens are stored locally; treat `token_*.json` files as sensitive
- **Hash Verification** — Dual-hash approach provides defense-in-depth against collision attacks

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Contributing

Contributions welcome. Please open an issue for bug reports or feature requests, or submit a pull request with a clear description of changes.

---

## Acknowledgements

- Built with the [Google Gmail API](https://developers.google.com/gmail/api)
- PDF generation via [ReportLab](https://www.reportlab.com/)
- Blake3 hashing via the [blake3-py](https://github.com/BLAKE3-team/BLAKE3) bindings
