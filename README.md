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

Community Intelligence - Retrieves VirusTotal community comments

**Requirements**

Python 3.8+

**Required Packages**

Install dependencies:

pip install requests

**Usage**
1. Create a file named: hashes.txt

**Example:**

44d88612fea8a8f36de82e1278abb02f
275a021bbfb648f0f8a1f5d9b7e0b4c9

One hash per line.

Supported hash types:

MD5
SHA1
SHA256
Run the script:

2. python vt_hash_enrichment.py

The script will prompt for a VirusTotal API key: Get one from - https://www.virustotal.com

3. Enter your VirusTotal API Key:

**Current limits:**

4 requests per minute
500 requests per day

This Script will generate below 5 CSV files including JSON file.
VirusTotal Public API Limits - The script is designed for the VirusTotal Public API.

**1. vt_results.csv - Primary file analysis results Contains:**

-Hashes
-File metadata
-Detection statistics
-Threat classification
-Behaviour summary counts
-Contacted IOC counts
-vt_results.jsonl

JSON Lines export containing full results. One JSON object per line.

**2. vt_behaviour_details.csv - Detailed sandbox behaviour information. One row per sandbox execution report contains**

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


**3. vt_contacted_ips.csv - Reputation information for contacted IP addresses Contains:**

-IP address
-ASN
-Country
-Reputation score
-Detection statistics
-vt_contacted_domains.csv

**4. vt_contacted_domains.csv- Reputation information for contacted domains contains:**

-Domain
-Registrar
-DNS records
-Reputation score
-Detection statistics

**5. vt_contacted_urls.csv - Extracted URLs contacted during execution. URLs are automatically defanged.**

Example:

hxxps://malicious-site[.]com

**Example Workflow**
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

**Updated Script Capabilities:**
The updated script retains all existing functionality while introducing several enhancements. It allows users to specify custom output file names at runtime, provides enriched intelligence for contacted domains (including WHOIS and registration details), and expands IP address analysis with additional context such as hostnames, associated domains, open ports, SSL/TLS certificate information, ASN details, and other relevant infrastructure metadata.

EXPORT FLAGS (all optional — vt_results.csv + JSON always saved):
  --behaviour         Save per-sandbox behaviour CSV  (vt_behaviour_details.csv)
  --ips               Save contacted IPs CSV          (vt_contacted_ips.csv)
  --ips-shodan        Like --ips, plus Shodan enrichment (open ports, SSL certs,
                      hostnames, CVEs). Requires --shodan-key or SHODAN_API_KEY env var.
  --domains           Save contacted domains CSV      (vt_contacted_domains.csv)
  --domains-whois     Like --domains, plus live WHOIS enrichment via python-whois.
  --urls              Save contacted URLs CSV         (vt_contacted_urls.csv)
  --all               Enable all of the above

**Usage Examples:**
  python vt_enrichment_updated.py
  python vt_enrichment_updated.py --behaviour --ips-shodan --shodan-key YOUR_KEY --domains-whois --urls
  python vt_enrichment_updated.py --all --shodan-key YOUR_KEY

**Testcases where this script will help analysts:**

**1. Malware Triage at Scale**

The core loop — hash → VT detections → sandbox behaviour → contacted IPs/domains — is exactly what analyst do when triaging a batch of suspicious files from an EDR alert, phishing email attachments, or a SIEM detection. Instead of clicking through VT's UI one hash at a time, you process dozens in one run and get a structured CSV ready for review.

**2.Threat Intelligence Enrichment for Customer Advisories**

Analyst get malware family classification, MITRE ATT&CK technique IDs, sigma rule hits, and sandbox verdicts already aggregated — the skeleton of what goes into a CTI's IOC annex. 

**3.Infrastructure Pivot**

The Shodan enrichment is where this gets interesting for CTI. When a sample contacts an IP, you're not just getting VT's malicious/suspicious count — you're getting open ports, JARM fingerprint, SSL cert subject/issuer, and CVEs on that host. A JARM fingerprint cluster across multiple contacted IPs is a strong C2 infrastructure pivot. Combined with the contacted domains WHOIS data (registrar, creation date, registrant org), you can rapidly identify freshly registered domains and bulletproof hosting patterns.

**4.Sandbox Behaviour Baselining**

The per-sandbox behaviour CSV captures things like processes_created, registry_keys_set, files_dropped, mutexes_created, and command_executions per sandbox engine. For malware families you track repeatedly (e.g. a banking trojan variant cluster), running new samples through and diffing the behaviour CSVs across runs tells you when TTPs shift — useful for updating detection logic without manually re-reading sandbox reports each time.
TIBER-EU / Red Team CTI Support

The mitre_technique_ids and mitre_technique_descriptions fields aggregated from sandbox data give you a per-sample ATT&CK coverage map. In a TIBER engagement, if you're building a threat scenario based on a specific threat actor's toolset, running their known malware hashes through this gives you a concrete technique list to brief the Red Team on without relying solely on open-source reports that may be stale.
Dark Web / Underground Market Sample Validation

If your LLM monitoring or dark web collection surfaces file hashes (cracked tools, stealers, RATs being sold), this script lets you quickly validate whether VT has seen them, how widely, and what the sandbox says they actually do — separating genuine threats from vaporware listings.
OT/ICS Threat Hunting (relevant to your current blog post)

**Notes**
API keys are requested interactively and are not stored.
Data is written immediately after retrieval to prevent loss if execution is interrupted.

**Disclaimer**

This project uses the VirusTotal Public API. Users are responsible for ensuring their usage remains within VirusTotal quota limits and licensing requirements.
