#!/usr/bin/env python3

import requests
import time
import json
import csv
import os
import getpass
from datetime import datetime, timezone

# ==========================
# CONFIGURATION
# ==========================

VT_API_KEY = getpass.getpass("Enter your VirusTotal API Key: ")

HASH_FILE = "hashes.txt"

OUTPUT_JSON           = "vt_results.jsonl"
OUTPUT_CSV            = "vt_results.csv"
OUTPUT_IP_CSV         = "vt_contacted_ips.csv"
OUTPUT_DOMAIN_CSV     = "vt_contacted_domains.csv"
OUTPUT_URL_CSV        = "vt_contacted_urls.csv"
OUTPUT_BEHAVIOUR_CSV  = "vt_behaviour_details.csv" 

# Free API limits
RATE_LIMIT_SECONDS  = 16   # ~3.75 req/min (safe under the 4/min cap)
DAILY_REQUEST_LIMIT = 500

HEADERS = {"x-apikey": VT_API_KEY}

# ==========================
# GLOBAL QUOTA TRACKER
# ==========================

_request_count = 0


def tracked_get(url, timeout=20):
    """
    Wrapper around requests.get that:
      - Tracks the daily request count
      - Aborts if the free daily cap is about to be exceeded
      - Handles 429 with a 65-second back-off and one retry
    """
    global _request_count

    if _request_count >= DAILY_REQUEST_LIMIT:
        raise RuntimeError(
            f"[!] Daily request cap of {DAILY_REQUEST_LIMIT} reached. "
            "Stopping to protect your quota."
        )

    try:
        response = requests.get(url, headers=HEADERS, timeout=timeout)
        _request_count += 1

        if response.status_code == 429:
            print(
                f"[!] Rate-limited on {url}. "
                "Sleeping 65 s then retrying once..."
            )
            time.sleep(65)
            response = requests.get(url, headers=HEADERS, timeout=timeout)
            _request_count += 1

        return response

    except requests.RequestException as exc:
        raise exc


# ==========================
# HELPERS
# ==========================

def epoch_to_utc(epoch_value):
    if not epoch_value:
        return ""
    try:
        return datetime.fromtimestamp(
            epoch_value, tz=timezone.utc
        ).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return ""


def human_size(size_bytes):
    if not size_bytes:
        return ""
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(size_bytes)
    for unit in units:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} PB"


def defang_url(url):
    if not url:
        return ""
    return (
        url.replace("https://", "hxxps://")
           .replace("http://", "hxxp://")
           .replace(".", "[.]")
    )


def defang_domain(domain):
    if not domain:
        return ""
    return domain.replace(".", "[.]")


# ==========================
# CSV WRITE HELPERS
# ==========================

def append_result_to_csv(result, output_file):
    """Append a single dict row to a CSV, writing headers if the file is new."""
    if not result:
        return
    try:
        file_exists = os.path.isfile(output_file)
        with open(output_file, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=result.keys())
            if not file_exists:
                writer.writeheader()
            writer.writerow(result)
            f.flush()
    except Exception as e:
        print(f"[!] Failed writing {output_file}: {e}")


def append_json_result(result):
    try:
        with open(OUTPUT_JSON, "a", encoding="utf-8") as f:
            f.write(json.dumps(result, ensure_ascii=False))
            f.write("\n")
            f.flush()
    except Exception as e:
        print(f"[!] Failed to save JSON result: {e}")


def append_csv_result(result):
    append_result_to_csv(result, OUTPUT_CSV)


# ==========================
# VIRUSTOTAL QUERY
# ==========================

def vt_lookup_hash(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    try:
        response = tracked_get(url)
        if response.status_code == 404:
            return {"hash": file_hash, "status": "NOT_FOUND"}
        if response.status_code == 429:
            return {"hash": file_hash, "status": "RATE_LIMITED"}
        response.raise_for_status()
        return parse_result(response.json(), file_hash)
    except RuntimeError:
        raise
    except Exception as e:
        return {"hash": file_hash, "error": str(e)}


# ==========================
# RELATIONSHIP LOOKUPS
# ==========================

def get_contacted_ips(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}/contacted_ips"
    try:
        response = tracked_get(url)
        if response.status_code != 200:
            return []
        return [
            item.get("id")
            for item in response.json().get("data", [])
            if item.get("id")
        ]
    except Exception:
        return []


def get_contacted_domains(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}/contacted_domains"
    try:
        response = tracked_get(url)
        if response.status_code != 200:
            return []
        return [
            item.get("id")
            for item in response.json().get("data", [])
            if item.get("id")
        ]
    except Exception:
        return []


def get_contacted_urls(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}/contacted_urls"
    try:
        response = tracked_get(url)
        if response.status_code != 200:
            return []
        urls = []
        for item in response.json().get("data", []):
            human_url = (
                item.get("context_attributes", {}).get("url")
                or item.get("attributes", {}).get("last_final_url")
            )
            if human_url:
                urls.append(human_url)
        return urls
    except Exception:
        return []


def get_comments(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}/comments"
    try:
        response = tracked_get(url)
        if response.status_code != 200:
            return []
        return [
            item["attributes"].get("text")
            for item in response.json().get("data", [])
            if item["attributes"].get("text")
        ][:5]
    except Exception:
        return []


# ==========================
# PER-SANDBOX BEHAVIOUR
# ==========================

def get_all_sandbox_behaviours(file_hash):
    """
    Fetch the full per-sandbox behaviour list from
    GET /files/{id}/behaviours

    This returns one object per sandbox, avoiding the summary truncation
    you experience with /behaviour_summary. Each object has a stable
    'id' field of the form '{sha256}_{SandboxName}' which is used
    to build the public VT GUI link.

    Returns: list of sandbox behaviour dicts (raw attributes + meta)
    """
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}/behaviours"
    try:
        response = tracked_get(url, timeout=30)
        if response.status_code == 404:
            print(f"    [~] No behaviour reports for {file_hash}")
            return []
        if response.status_code != 200:
            print(
                f"    [!] Behaviour fetch returned HTTP "
                f"{response.status_code} for {file_hash}"
            )
            return []
        data = response.json().get("data", [])
        print(
            f"    [+] Got {len(data)} sandbox report(s) for {file_hash}"
        )
        return data
    except Exception as e:
        print(f"    [!] Behaviour fetch error for {file_hash}: {e}")
        return []


def flatten_behaviour(sandbox_obj, file_hash, file_name):
    """
    Convert one sandbox behaviour object (from the /behaviours list)
    into a flat dict suitable for writing to CSV.

    All list fields are joined with ' | ' so that a single sandbox
    report occupies one CSV row.
    """
    obj_id   = sandbox_obj.get("id", "")
    obj_link = sandbox_obj.get("links", {}).get("self", "")

    # Build a public GUI link: the API self-link points to the API endpoint;
    # the GUI equivalent is at /gui/file/{sha256}/behavior (sandbox tab).
    # We also store the direct API behaviour link for programmatic access.
    gui_link = (
        f"https://www.virustotal.com/gui/file/{file_hash}/behavior"
        if file_hash
        else ""
    )

    attr = sandbox_obj.get("attributes", {})

    sandbox_name  = attr.get("sandbox_name", obj_id.split("_", 1)[-1] if "_" in obj_id else "")
    analysis_date = epoch_to_utc(attr.get("analysis_date"))
    verdicts      = " | ".join(attr.get("verdicts", []))
    behash        = attr.get("behash", "")
    tags          = " | ".join(attr.get("tags", []))

    # --- helper to join list fields ---
    def join_list(key, limit=None):
        items = attr.get(key, [])
        if limit:
            items = items[:limit]
        return " | ".join(str(x) for x in items if x)

    def join_dict_list(key, kfield, vfield, limit=None):
        """For fields like registry_keys_set that are list-of-dicts."""
        items = attr.get(key, [])
        if limit:
            items = items[:limit]
        parts = []
        for item in items:
            if isinstance(item, dict):
                k = item.get(kfield, "")
                v = item.get(vfield, "")
                parts.append(f"{k}={v}")
            else:
                parts.append(str(item))
        return " | ".join(parts)

    def join_complex(key, sub_keys, limit=None):
        """For nested dicts — extract specific sub-keys as key:value pairs."""
        items = attr.get(key, [])
        if limit:
            items = items[:limit]
        parts = []
        for item in items:
            if isinstance(item, dict):
                segment = " ".join(
                    f"{sk}:{item.get(sk, '')}" for sk in sub_keys
                )
                parts.append(segment)
            else:
                parts.append(str(item))
        return " | ".join(parts)

    # --- IDS alerts ---
    ids_alerts = attr.get("ids_alerts", [])
    ids_summary = " | ".join(
        f"[{a.get('alert_severity','?')}] {a.get('rule_msg','')} "
        f"(src:{a.get('alert_context',{}).get('src_ip','')} "
        f"dst:{a.get('alert_context',{}).get('dest_ip','')}:"
        f"{a.get('alert_context',{}).get('dest_port','')})"
        for a in ids_alerts[:10]
    )

    # --- MITRE ATT&CK ---
    mitre = attr.get("mitre_attack_techniques", [])
    mitre_ids   = " | ".join(m.get("id", "")          for m in mitre)
    mitre_descs = " | ".join(m.get("signature_description", "") for m in mitre[:10])

    # --- Sigma results ---
    sigma = attr.get("sigma_analysis_results", [])
    sigma_rules = " | ".join(
        f"[{s.get('rule_level','?')}] {s.get('rule_title','')}"
        for s in sigma[:10]
    )

    # --- Signature matches (YARA/CAPA/OpenIOC) ---
    sig_matches = attr.get("signature_matches", [])
    sig_names = " | ".join(
        f"[{s.get('format','')}] {s.get('name','')}"
        for s in sig_matches[:10]
    )

    # --- TLS certificates ---
    tls_entries = attr.get("tls", [])
    tls_snis = " | ".join(t.get("sni", "") for t in tls_entries if t.get("sni"))
    tls_ja3  = " | ".join(t.get("ja3", "")  for t in tls_entries if t.get("ja3"))

    # --- ip_traffic ---
    ip_traffic = attr.get("ip_traffic", [])
    ip_traffic_str = " | ".join(
        f"{t.get('transport_layer_protocol','')}/"
        f"{t.get('destination_ip','')}:"
        f"{t.get('destination_port','')}"
        for t in ip_traffic[:20]
    )

    # --- http_conversations ---
    http_convs = attr.get("http_conversations", [])
    http_urls_str = " | ".join(
        h.get("url", "") for h in http_convs[:20] if h.get("url")
    )

    # --- dns_lookups ---
    dns_lookups = attr.get("dns_lookups", [])
    dns_str = " | ".join(
        d.get("hostname", str(d)) for d in dns_lookups[:20]
    )

    # --- files_dropped ---
    dropped = attr.get("files_dropped", [])
    dropped_paths = " | ".join(
        d.get("path", "") for d in dropped[:20] if isinstance(d, dict)
    )
    dropped_hashes = " | ".join(
        d.get("sha256", "") for d in dropped[:20]
        if isinstance(d, dict) and d.get("sha256")
    )

    # --- processes_tree (flatten to names) ---
    def flatten_tree(nodes, depth=0):
        result = []
        for node in nodes:
            prefix = "  " * depth
            result.append(f"{prefix}{node.get('name','?')}")
            result.extend(flatten_tree(node.get("children", []), depth + 1))
        return result

    proc_tree_str = " | ".join(
        flatten_tree(attr.get("processes_tree", []))[:20]
    )

    # Permissions requested (Android) or process token privileges (Windows)
    permissions = join_list("permissions_requested", limit=30)

    row = {
        # --- Identity ---
        "hash":              file_hash,
        "file_name":         file_name,
        "sandbox_id":        obj_id,
        "sandbox_name":      sandbox_name,
        "analysis_date":     analysis_date,
        "behash":            behash,
        "verdicts":          verdicts,
        "tags":              tags,

        # --- Links ---
        "vt_gui_behaviour_link": gui_link,
        "vt_api_behaviour_link": obj_link,

        # --- Availability flags ---
        "has_html_report":   attr.get("has_html_report", False),
        "has_pcap":          attr.get("has_pcap", False),
        "has_evtx":          attr.get("has_evtx", False),
        "has_memdump":       attr.get("has_memdump", False),

        # --- File activity ---
        "files_opened_count":           len(attr.get("files_opened", [])),
        "files_opened":                 join_list("files_opened", limit=30),
        "files_written_count":          len(attr.get("files_written", [])),
        "files_written":                join_list("files_written", limit=30),
        "files_deleted_count":          len(attr.get("files_deleted", [])),
        "files_deleted":                join_list("files_deleted", limit=30),
        "files_attribute_changed":      join_list("files_attribute_changed", limit=20),
        "files_dropped_count":          len(dropped),
        "files_dropped_paths":          dropped_paths,
        "files_dropped_hashes":         dropped_hashes,

        # --- Process activity ---
        "processes_created_count":      len(attr.get("processes_created", [])),
        "processes_created":            join_list("processes_created", limit=20),
        "processes_terminated_count":   len(attr.get("processes_terminated", [])),
        "processes_terminated":         join_list("processes_terminated", limit=20),
        "processes_killed":             join_list("processes_killed", limit=10),
        "processes_injected":           join_list("processes_injected", limit=10),
        "processes_tree":               proc_tree_str,

        # --- Registry (Windows) ---
        "registry_keys_opened_count":   len(attr.get("registry_keys_opened", [])),
        "registry_keys_opened":         join_list("registry_keys_opened", limit=30),
        "registry_keys_set_count":      len(attr.get("registry_keys_set", [])),
        "registry_keys_set":            join_dict_list("registry_keys_set", "key", "value", limit=20),
        "registry_keys_deleted_count":  len(attr.get("registry_keys_deleted", [])),
        "registry_keys_deleted":        join_list("registry_keys_deleted", limit=20),

        # --- Services ---
        "services_created":             join_list("services_created", limit=10),
        "services_started":             join_list("services_started", limit=10),
        "services_stopped":             join_list("services_stopped", limit=10),
        "services_deleted":             join_list("services_deleted", limit=10),
        "services_opened":              join_list("services_opened", limit=10),

        # --- Mutexes ---
        "mutexes_created_count":        len(attr.get("mutexes_created", [])),
        "mutexes_created":              join_list("mutexes_created", limit=20),
        "mutexes_opened":               join_list("mutexes_opened", limit=10),

        # --- Network ---
        "ip_traffic_count":             len(ip_traffic),
        "ip_traffic":                   ip_traffic_str,
        "http_conversations_count":     len(http_convs),
        "http_urls":                    http_urls_str,
        "dns_lookups_count":            len(dns_lookups),
        "dns_lookups":                  dns_str,
        "tls_snis":                     tls_snis,
        "tls_ja3":                      tls_ja3,
        "ja3_digests":                  join_list("ja3_digests", limit=10),

        # --- Commands ---
        "command_executions_count":     len(attr.get("command_executions", [])),
        "command_executions":           join_list("command_executions", limit=20),
        "calls_highlighted":            join_list("calls_highlighted", limit=20),

        # --- Modules (Windows) ---
        "modules_loaded_count":         len(attr.get("modules_loaded", [])),
        "modules_loaded":               join_list("modules_loaded", limit=30),

        # --- Crypto ---
        "crypto_algorithms_observed":   join_list("crypto_algorithms_observed"),
        "crypto_keys":                  join_list("crypto_keys", limit=10),

        # --- Detections ---
        "ids_alerts_count":             len(ids_alerts),
        "ids_alerts":                   ids_summary,
        "sigma_rules_count":            len(sigma),
        "sigma_rules":                  sigma_rules,
        "signature_matches_count":      len(sig_matches),
        "signature_matches":            sig_names,
        "mitre_technique_ids":          mitre_ids,
        "mitre_technique_descriptions": mitre_descs,

        # --- Android specific ---
        "activities_started":           join_list("activities_started", limit=10),
        "permissions_requested":        permissions,
        "signals_observed":             join_list("signals_observed", limit=10),
        "invokes_count":                len(attr.get("invokes", [])),
        "invokes":                      join_list("invokes", limit=20),
        "shared_preferences_sets":      join_dict_list("shared_preferences_sets", "key", "value", limit=10),
        "databases_opened":             join_list("databases_opened", limit=10),
        "content_model_observers":      join_list("content_model_observers", limit=10),

        # --- Misc ---
        "text_highlighted":             join_list("text_highlighted", limit=10),
        "windows_searched":             join_list("windows_searched", limit=10),
        "windows_hidden":               join_list("windows_hidden", limit=10),
        "hosts_file_modified":          bool(attr.get("hosts_file")),
        "hosts_file_content":           (attr.get("hosts_file") or "")[:500],
    }

    return row


# ==========================
# PARSE MAIN FILE RESULT
# ==========================

def parse_result(data, file_hash):
    attr = data["data"]["attributes"]

    result = {}
    result["hash"] = file_hash

    # FILE NAMES
    result["primary_file_name"] = attr.get(
        "meaningful_name", attr.get("names", ["unknown"])[0]
    )
    all_names = attr.get("names", [])
    result["all_file_names"]   = " | ".join(all_names)
    result["file_name_count"]  = len(all_names)
    result["file_name"]        = result["primary_file_name"]
    result["md5"]              = attr.get("md5")
    result["sha1"]             = attr.get("sha1")
    result["sha256"]           = attr.get("sha256")

    # FILE DETAILS
    result["file_type"]              = attr.get("type_description")
    result["size_bytes"]             = attr.get("size")
    result["size"]                   = human_size(attr.get("size"))
    result["first_submission_date"]  = epoch_to_utc(attr.get("first_submission_date"))
    result["last_submission_date"]   = epoch_to_utc(attr.get("last_submission_date"))
    result["last_analysis_date"]     = epoch_to_utc(attr.get("last_analysis_date"))

    signature_info = attr.get("signature_info", {})
    result["signed"]       = bool(signature_info)
    result["signer"]       = signature_info.get("signers", "")
    result["signing_date"] = signature_info.get("signing_date")
    result["product"]      = signature_info.get("product")
    result["publisher"]    = signature_info.get("publisher")

    pe_info = attr.get("pe_info", {})
    result["pe_compile_timestamp"] = epoch_to_utc(pe_info.get("timestamp"))

    # DETECTION STATS
    stats = attr.get("last_analysis_stats", {})
    result["malicious"]        = stats.get("malicious", 0)
    result["suspicious"]       = stats.get("suspicious", 0)
    result["harmless"]         = stats.get("harmless", 0)
    result["undetected"]       = stats.get("undetected", 0)
    result["timeout"]          = stats.get("timeout", 0)
    result["failure"]          = stats.get("failure", 0)
    result["type_unsupported"] = stats.get("type-unsupported", 0)

    # THREAT CLASSIFICATION
    popular_threat = attr.get("popular_threat_classification", {})
    result["threat_category"] = ",".join(
        item.get("value")
        for item in popular_threat.get("popular_threat_category", [])
        if item.get("value")
    )
    result["malware_family"] = ",".join(
        item.get("value")
        for item in popular_threat.get("popular_threat_name", [])
        if item.get("value")
    )

    # TAGS / REPUTATION
    result["tags"]            = ",".join(attr.get("tags", []))
    result["community_score"] = attr.get("reputation")

    # SANDBOX VERDICTS (from the file attributes — these are compact)
    sandbox_verdicts = attr.get("sandbox_verdicts", {})
    result["sandbox_count"] = len(sandbox_verdicts)
    sandbox_verdict_list = []
    for sb_name, verdict in sandbox_verdicts.items():
        cat    = verdict.get("category", "")
        mal    = verdict.get("malware_classification", [])
        detail = ",".join(mal) if mal else cat
        sandbox_verdict_list.append(f"{sb_name}: {detail}")
    result["sandbox_verdicts"] = " | ".join(sandbox_verdict_list)

    # SANDBOX GUI LINKS — one consolidated VT behaviour page per hash,
    # plus one direct API link per sandbox (from sandbox_verdicts keys)
    result["vt_behaviour_gui_link"] = (
        f"https://www.virustotal.com/gui/file/{file_hash}/behavior"
        if file_hash else ""
    )

    # CONTACTED IPs / DOMAINS / URLs
    time.sleep(RATE_LIMIT_SECONDS)
    contacted_ips     = get_contacted_ips(file_hash)
    contacted_domains = get_contacted_domains(file_hash)
    contacted_urls    = get_contacted_urls(file_hash)

    result["contacted_ips"]          = ",".join(contacted_ips)
    result["contacted_domains"]      = ",".join(contacted_domains)
    result["contacted_urls"]         = ",".join(contacted_urls)
    result["contacted_ip_count"]     = len(contacted_ips)
    result["contacted_domain_count"] = len(contacted_domains)
    result["contacted_url_count"]    = len(contacted_urls)

    # COMMUNITY COMMENTS
    time.sleep(RATE_LIMIT_SECONDS)
    result["comments"] = " | ".join(get_comments(file_hash))

    # BEHAVIOUR SUMMARY COUNTS (populated later from per-sandbox fetch)
    # These are set to 0 here and updated after get_all_sandbox_behaviours()
    result["behaviour_files_opened"]         = 0
    result["behaviour_files_written"]        = 0
    result["behaviour_files_deleted"]        = 0
    result["behaviour_files_dropped"]        = 0
    result["behaviour_registry_keys_opened"] = 0
    result["behaviour_registry_keys_set"]    = 0
    result["behaviour_registry_keys_deleted"]= 0
    result["behaviour_processes_created"]    = 0
    result["behaviour_processes_terminated"] = 0
    result["behaviour_services_created"]     = 0
    result["behaviour_mutexes_created"]      = 0
    result["behaviour_dns_lookups"]          = 0
    result["behaviour_http_requests"]        = 0
    result["behaviour_tcp_connections"]      = 0
    result["behaviour_command_count"]        = 0
    result["behaviour_commands"]             = ""
    result["behaviour_mitre_techniques"]     = ""
    result["behaviour_sigma_rules"]          = ""
    result["behaviour_ids_alerts"]           = 0

    return result


def enrich_result_with_behaviour(result, sandbox_data):
    """
    Aggregate across all sandbox reports to fill the behaviour summary
    columns in the main result dict.
    Uses sets to deduplicate across sandboxes.
    """
    files_opened   = set()
    files_written  = set()
    files_deleted  = set()
    files_dropped  = set()
    reg_opened     = set()
    reg_set        = set()
    reg_deleted    = set()
    procs_created  = set()
    procs_term     = set()
    services_cr    = set()
    mutexes_cr     = set()
    dns_lookups    = set()
    http_convs     = set()
    ip_traffic     = set()
    commands       = []
    mitre_ids      = set()
    sigma_titles   = set()
    ids_total      = 0

    for sb_obj in sandbox_data:
        attr = sb_obj.get("attributes", {})
        files_opened.update(attr.get("files_opened", []))
        files_written.update(attr.get("files_written", []))
        files_deleted.update(attr.get("files_deleted", []))
        files_dropped.update(
            d.get("path", "") for d in attr.get("files_dropped", [])
            if isinstance(d, dict) and d.get("path")
        )
        reg_opened.update(attr.get("registry_keys_opened", []))
        for rk in attr.get("registry_keys_set", []):
            if isinstance(rk, dict):
                reg_set.add(rk.get("key", ""))
            else:
                reg_set.add(str(rk))
        reg_deleted.update(attr.get("registry_keys_deleted", []))
        procs_created.update(attr.get("processes_created", []))
        procs_term.update(attr.get("processes_terminated", []))
        services_cr.update(attr.get("services_created", []))
        mutexes_cr.update(attr.get("mutexes_created", []))
        for dl in attr.get("dns_lookups", []):
            if isinstance(dl, dict):
                dns_lookups.add(dl.get("hostname", str(dl)))
            else:
                dns_lookups.add(str(dl))
        http_convs.update(
            h.get("url", "") for h in attr.get("http_conversations", [])
            if isinstance(h, dict) and h.get("url")
        )
        for it in attr.get("ip_traffic", []):
            if isinstance(it, dict):
                ip_traffic.add(
                    f"{it.get('destination_ip','')}:"
                    f"{it.get('destination_port','')}"
                )
        for cmd in attr.get("command_executions", []):
            if cmd and cmd not in commands:
                commands.append(cmd)
        for m in attr.get("mitre_attack_techniques", []):
            if m.get("id"):
                mitre_ids.add(m["id"])
        for s in attr.get("sigma_analysis_results", []):
            if s.get("rule_title"):
                sigma_titles.add(f"[{s.get('rule_level','?')}]{s['rule_title']}")
        ids_total += len(attr.get("ids_alerts", []))

    result["behaviour_files_opened"]          = len(files_opened)
    result["behaviour_files_written"]         = len(files_written)
    result["behaviour_files_deleted"]         = len(files_deleted)
    result["behaviour_files_dropped"]         = len(files_dropped)
    result["behaviour_registry_keys_opened"]  = len(reg_opened)
    result["behaviour_registry_keys_set"]     = len(reg_set)
    result["behaviour_registry_keys_deleted"] = len(reg_deleted)
    result["behaviour_processes_created"]     = len(procs_created)
    result["behaviour_processes_terminated"]  = len(procs_term)
    result["behaviour_services_created"]      = len(services_cr)
    result["behaviour_mutexes_created"]       = len(mutexes_cr)
    result["behaviour_dns_lookups"]           = len(dns_lookups)
    result["behaviour_http_requests"]         = len(http_convs)
    result["behaviour_tcp_connections"]       = len(ip_traffic)
    result["behaviour_command_count"]         = len(commands)
    result["behaviour_commands"]              = " | ".join(commands[:20])
    result["behaviour_mitre_techniques"]      = " | ".join(sorted(mitre_ids))
    result["behaviour_sigma_rules"]           = " | ".join(sorted(sigma_titles))
    result["behaviour_ids_alerts"]            = ids_total

    return result


# ==========================
# IP / DOMAIN REPUTATION
# ==========================

def get_ip_reputation(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    try:
        response = tracked_get(url)
        if response.status_code != 200:
            return None
        attr  = response.json().get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})
        return {
            "ip":         ip,
            "country":    attr.get("country"),
            "asn":        attr.get("asn"),
            "as_owner":   attr.get("as_owner"),
            "network":    attr.get("network"),
            "reputation": attr.get("reputation"),
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless", 0),
        }
    except Exception:
        return None


def get_domain_reputation(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    try:
        response = tracked_get(url)
        time.sleep(RATE_LIMIT_SECONDS)
        if response.status_code != 200:
            return None
        attr  = response.json().get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})
        dns_records = []
        for record in attr.get("last_dns_records", []):
            value       = record.get("value")
            record_type = record.get("type")
            if value:
                dns_records.append(f"{record_type}:{value}")
        return {
            "domain":                domain,
            "reputation":            attr.get("reputation"),
            "dns_records":           " | ".join(dns_records),
            "registrar":             attr.get("registrar"),
            "creation_date":         epoch_to_utc(attr.get("creation_date")),
            "last_modification_date":epoch_to_utc(attr.get("last_modification_date")),
            "whois_date":            epoch_to_utc(attr.get("whois_date")),
            "categories":            ",".join(attr.get("tags", [])),
            "malicious":             stats.get("malicious", 0),
            "suspicious":            stats.get("suspicious", 0),
            "harmless":              stats.get("harmless", 0),
            "undetected":            stats.get("undetected", 0),
        }
    except Exception:
        return None


# ==========================
# MAIN
# ==========================

def main():
    global _request_count

    if not os.path.exists(HASH_FILE):
        print(f"[!] Input file not found: {HASH_FILE}")
        return

    with open(HASH_FILE, "r", encoding="utf-8") as f:
        hashes = [x.strip() for x in f if x.strip()]

    print(f"[+] Processing {len(hashes)} hashes")
    print(
        f"[+] Free API budget: {DAILY_REQUEST_LIMIT} requests "
        f"(~{DAILY_REQUEST_LIMIT // len(hashes) if hashes else 0} per hash)"
    )

    for idx, file_hash in enumerate(hashes, 1):
        print(f"\n[+] [{idx}/{len(hashes)}] Checking {file_hash}  "
              f"(requests used so far: {_request_count})")

        try:
            # ---- 1. Main file lookup (1 request) ----
            time.sleep(RATE_LIMIT_SECONDS)
            result = vt_lookup_hash(file_hash)

            if result.get("status") in ("NOT_FOUND", "RATE_LIMITED") or "error" in result:
                print(f"    [!] Skipping: {result}")
                append_json_result(result)
                append_csv_result(result)
                continue

            file_name = result.get("file_name", "")

            # ---- 2. Per-sandbox behaviours (1 request, returns all sandboxes) ----
            time.sleep(RATE_LIMIT_SECONDS)
            sandbox_data = get_all_sandbox_behaviours(file_hash)

            # Write each sandbox row to the behaviour CSV immediately
            for sb_obj in sandbox_data:
                behaviour_row = flatten_behaviour(sb_obj, file_hash, file_name)
                append_result_to_csv(behaviour_row, OUTPUT_BEHAVIOUR_CSV)

            # Aggregate behaviour counts into the main result
            if sandbox_data:
                result = enrich_result_with_behaviour(result, sandbox_data)

            # ---- 3. IP reputation (1 request per IP) ----
            ips = [
                x.strip()
                for x in result.get("contacted_ips", "").split(",")
                if x.strip()
            ]
            for ip in ips:
                try:
                    time.sleep(RATE_LIMIT_SECONDS)
                    ip_info = get_ip_reputation(ip)
                    if ip_info:
                        ip_info["hash"]      = file_hash
                        ip_info["file_name"] = file_name
                        append_result_to_csv(ip_info, OUTPUT_IP_CSV)
                except RuntimeError:
                    raise
                except Exception as e:
                    print(f"    [!] IP lookup failed for {ip}: {e}")

            # ---- 4. Domain reputation (1 request per domain) ----
            domains = [
                x.strip()
                for x in result.get("contacted_domains", "").split(",")
                if x.strip()
            ]
            for domain in domains:
                try:
                    time.sleep(RATE_LIMIT_SECONDS)
                    domain_info = get_domain_reputation(domain)
                    if domain_info:
                        domain_info["hash"]      = file_hash
                        domain_info["file_name"] = file_name
                        append_result_to_csv(domain_info, OUTPUT_DOMAIN_CSV)
                except RuntimeError:
                    raise
                except Exception as e:
                    print(f"    [!] Domain lookup failed for {domain}: {e}")

            # ---- 5. URL CSV (no extra API calls needed) ----
            urls = [
                x.strip()
                for x in result.get("contacted_urls", "").split(",")
                if x.strip()
            ]
            for url in urls:
                url_info = {
                    "hash":      file_hash,
                    "file_name": file_name,
                    "url":       defang_url(url),
                }
                append_result_to_csv(url_info, OUTPUT_URL_CSV)

            # ---- 6. Save main result ----
            append_json_result(result)
            append_csv_result(result)

            print(
                f"    [+] Saved. Malicious: {result.get('malicious')}, "
                f"Sandboxes: {result.get('sandbox_count')}, "
                f"Requests used: {_request_count}"
            )

        except RuntimeError as e:
            # Daily quota exhausted — stop cleanly
            print(f"\n[!] {e}")
            break

        except Exception as e:
            error_result = {"hash": file_hash, "error": str(e)}
            append_json_result(error_result)
            append_csv_result(error_result)
            print(f"    [!] Error processing {file_hash}: {e}")

    print(f"\n[+] Processing completed. Total API requests used: {_request_count}")
    print("[+] Output files:")
    for f in [OUTPUT_JSON, OUTPUT_CSV, OUTPUT_BEHAVIOUR_CSV,
              OUTPUT_IP_CSV, OUTPUT_DOMAIN_CSV, OUTPUT_URL_CSV]:
        if os.path.exists(f):
            size = os.path.getsize(f)
            print(f"    {f}  ({human_size(size)})")


if __name__ == "__main__":
    main()
