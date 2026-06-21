# VirusTotal-Hash-Enrichment-Script
This Python script enriches malware file hashes using the VirusTotal v3 API. It retrieves file metadata, detection statistics, sandbox behaviour reports, contacted network indicators, community comments, and reputation information for related IP addresses and domains.

The script is designed to work with the VirusTotal Public API while respecting rate limits and daily quota restrictions.

Results are exported into multiple CSV files and JSONL format for further malware analysis, threat hunting, IOC extraction, and reporting.

**Features**
**File Metadata Collection**

For each supplied hash, the script collects:

-MD5, SHA1, SHA256
-File name(s)
-File type
-File size
-Compilation timestamp (PE files)
-First submission date
-Last submission date
-Last analysis date
-Digital signature information
-Threat classification
-Malware family
-Community reputation score
-Detection Statistics

Collects VirusTotal detection statistics including:

Malicious detections
Suspicious detections
Harmless detections
Undetected engines
Sandbox Behaviour Analysis

Uses:

GET /files/{id}/behaviours

to retrieve detailed per-sandbox execution reports.

Behaviour data includes:

-Files opened
-Files written
-Files deleted
-Files dropped
-Registry activity
-Process creation
-Process termination
-Service creation
-Mutex creation
-DNS lookups
-HTTP conversations
-IP traffic
-TLS information
-Command executions
-Loaded modules
-MITRE ATT&CK techniques
-Sigma detections
-IDS alerts
-Signature matches
-Memory dump availability
-Network Indicators

Collects:

-Contacted IP addresses
-Contacted domains
-Contacted URLs
-Reputation Enrichment
-including reputation scores and detection statistics.

Community Intelligence

Retrieves:

VirusTotal community comments

**Requirements**

Python 3.8+

**Required Packages**

Install dependencies:

pip install requests

**Create a file named:**

hashes.txt

**Example:**

44d88612fea8a8f36de82e1278abb02f
275a021bbfb648f0f8a1f5d9b7e0b4c9

One hash per line.

Supported hash types:

MD5
SHA1
SHA256

**Usage**

Run the script:

python vt_hash_enrichment.py

The script will prompt for a VirusTotal API key: Get one from - https://www.virustotal.com

Enter your VirusTotal API Key:

VirusTotal Public API Limits - The script is designed for the VirusTotal Public API.

**Current limits:**

4 requests per minute
500 requests per day

Primary file analysis results Contains:

-Hashes
-File metadata
-Detection statistics
-Threat classification
-Behaviour summary counts
-Contacted IOC counts
-vt_results.jsonl

JSON Lines export containing full results. One JSON object per line.

Detailed sandbox behaviour information.One row per sandbox execution report.

**Contains:**

-Sandbox name
-Verdicts
-MITRE ATT&CK techniques
-DNS lookups
-HTTP activity
-File activity
-Registry activity
-Process activity
-IDS alerts
-Sigma detections


**vt_contacted_ips.csv**

Reputation information for contacted IP addresses Contains:

-IP address
-ASN
-Country
-Reputation score
-Detection statistics
-vt_contacted_domains.csv

Reputation information for contacted domains contains:

-Domain
-Registrar
-DNS records
-Reputation score
-Detection statistics

**vt_contacted_urls.csv**

Extracted URLs contacted during execution. URLs are automatically defanged.

Example:

hxxps://malicious-site[.]com

Example Workflow
1. Read hashes from hashes.txt
2. Query VirusTotal file report
3.Retrieve sandbox behaviour reports
4. Extract network indicators
5. Enrich IP reputation
6. Enrich domain reputation
7. Export results to CSV and JSONL

**Performance Considerations:**

Using the VirusTotal Public API, each hash may require multiple API requests.

**Typical requests per hash:**

File lookup
Behaviour lookup
Contacted IPs
Contacted domains
Contacted URLs
Community comments
IP reputation lookups
Domain reputation lookups

As a result, processing large numbers of hashes may take significant time.

For faster execution:
Disable community comments
Disable IP reputation lookups
Disable domain reputation lookups

The most valuable behavioural information is already available through:

/files/{hash}
/files/{hash}/behaviours

**Notes**
API keys are requested interactively and are not stored.
Data is written immediately after retrieval to prevent loss if execution is interrupted.

**Disclaimer**

This project uses the VirusTotal Public API. Users are responsible for ensuring their usage remains within VirusTotal quota limits and licensing requirements.
