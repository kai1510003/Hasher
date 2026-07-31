#!/usr/bin/env python3
"""
VirusTotal API v3 Client for Hash & File Analysis
Integrates with VirusTotal v3 REST API using standard Python library (urllib).
"""

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, Any, Optional

from hash_tool import compute_hash, is_valid_hash

VT_API_BASE_URL = "https://www.virustotal.com/api/v3"
VT_GUI_BASE_URL = "https://www.virustotal.com/gui/file"


class VirusTotalError(Exception):
    """Custom exception for VirusTotal API errors."""
    pass


def get_api_key(passed_key: Optional[str] = None) -> Optional[str]:
    """
    Get VirusTotal API Key from passed argument or VIRUSTOTAL_API_KEY environment variable.
    """
    if passed_key and passed_key.strip():
        return passed_key.strip()
    env_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    return env_key if env_key else None


def check_hash_virustotal(hash_digest: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    """
    Query VirusTotal API v3 for a file hash digest (SHA-256, MD5, or SHA-1).

    Returns structured dictionary with fields:
        - success: bool
        - found: bool
        - hash: str
        - stats: dict (malicious, suspicious, harmless, undetected, timeout)
        - reputation: int
        - meaningful_name: str
        - size: int
        - type_description: str
        - permalink: str
        - scan_date: str
        - threat_label: str
        - detections: dict (engine_name -> {category, result})
        - error: str (if success is False)
    """
    key = get_api_key(api_key)
    if not key:
        return {
            "success": False,
            "found": False,
            "hash": hash_digest,
            "error": "VirusTotal API Key missing. Set VIRUSTOTAL_API_KEY env var or pass --api-key.",
        }

    clean_hash = hash_digest.strip().lower()
    if not is_valid_hash(clean_hash):
        return {
            "success": False,
            "found": False,
            "hash": hash_digest,
            "error": f"Invalid hash digest format: '{hash_digest}'. Must be hex format.",
        }

    url = f"{VT_API_BASE_URL}/files/{clean_hash}"
    req = urllib.request.Request(url, headers={"x-apikey": key, "Accept": "application/json"})

    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            res_data = json.loads(response.read().decode("utf-8"))
            data = res_data.get("data", {})
            attrs = data.get("attributes", {})

            stats = attrs.get("last_analysis_stats", {})
            results = attrs.get("last_analysis_results", {})
            pop_threat = attrs.get("popular_threat_classification", {})

            scan_timestamp = attrs.get("last_analysis_date")
            scan_date_str = (
                time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(scan_timestamp))
                if scan_timestamp
                else "N/A"
            )

            # Filter for engines that detected threats (malicious or suspicious)
            flagged_detections = {}
            for eng, det in results.items():
                cat = det.get("category", "")
                if cat in ("malicious", "suspicious"):
                    flagged_detections[eng] = {
                        "category": cat,
                        "result": det.get("result") or "Detected",
                        "engine_name": det.get("engine_name", eng),
                    }

            return {
                "success": True,
                "found": True,
                "hash": clean_hash,
                "stats": {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "timeout": stats.get("timeout", 0),
                },
                "reputation": attrs.get("reputation", 0),
                "meaningful_name": attrs.get("meaningful_name") or (attrs.get("names", ["N/A"])[0] if attrs.get("names") else "N/A"),
                "size": attrs.get("size", 0),
                "type_description": attrs.get("type_description", "Unknown"),
                "permalink": f"{VT_GUI_BASE_URL}/{clean_hash}",
                "scan_date": scan_date_str,
                "threat_label": pop_threat.get("suggested_threat_label", "None"),
                "detections": flagged_detections,
                "all_results": results,
                "error": None,
            }

    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {
                "success": True,
                "found": False,
                "hash": clean_hash,
                "permalink": f"{VT_GUI_BASE_URL}/{clean_hash}",
                "error": "Hash not found in VirusTotal database.",
            }
        elif e.code == 401:
            return {
                "success": False,
                "found": False,
                "hash": clean_hash,
                "error": "Unauthorized: Invalid VirusTotal API key (401).",
            }
        elif e.code == 429:
            return {
                "success": False,
                "found": False,
                "hash": clean_hash,
                "error": "Rate limit exceeded: VirusTotal API request quota hit (429).",
            }
        else:
            return {
                "success": False,
                "found": False,
                "hash": clean_hash,
                "error": f"VirusTotal API HTTP error {e.code}: {e.reason}",
            }
    except Exception as e:
        return {
            "success": False,
            "found": False,
            "hash": clean_hash,
            "error": f"Connection error: {str(e)}",
        }


def upload_file_virustotal(file_path: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    """
    Upload a local file to VirusTotal v3 API for analysis.
    """
    key = get_api_key(api_key)
    if not key:
        return {
            "success": False,
            "error": "VirusTotal API Key missing. Set VIRUSTOTAL_API_KEY env var or pass --api-key.",
        }

    if not os.path.isfile(file_path):
        return {
            "success": False,
            "error": f"File not found: '{file_path}'",
        }

    filename = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)

    # 32MB standard limit for standard upload endpoint
    if file_size > 32 * 1024 * 1024:
        return {
            "success": False,
            "error": "File size exceeds 32MB upload limit for standard VirusTotal API endpoint.",
        }

    url = f"{VT_API_BASE_URL}/files"
    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"

    try:
        with open(file_path, "rb") as f:
            file_bytes = f.read()

        body = bytearray()
        body.extend(f"--{boundary}\r\n".encode("utf-8"))
        body.extend(f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode("utf-8"))
        body.extend(b"Content-Type: application/octet-stream\r\n\r\n")
        body.extend(file_bytes)
        body.extend(b"\r\n")
        body.extend(f"--{boundary}--\r\n".encode("utf-8"))

        headers = {
            "x-apikey": key,
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": str(len(body)),
        }

        req = urllib.request.Request(url, data=bytes(body), headers=headers, method="POST")

        with urllib.request.urlopen(req, timeout=30) as response:
            res_data = json.loads(response.read().decode("utf-8"))
            data = res_data.get("data", {})
            analysis_id = data.get("id")

            file_hash = compute_hash(file_path, "sha256")

            return {
                "success": True,
                "analysis_id": analysis_id,
                "file_name": filename,
                "hash": file_hash,
                "permalink": f"{VT_GUI_BASE_URL}/{file_hash}",
                "message": f"File successfully uploaded for analysis. Analysis ID: {analysis_id}",
            }

    except urllib.error.HTTPError as e:
        if e.code == 401:
            return {"success": False, "error": "Unauthorized: Invalid VirusTotal API key (401)."}
        elif e.code == 429:
            return {"success": False, "error": "Rate limit exceeded (429)."}
        else:
            return {"success": False, "error": f"VirusTotal Upload HTTP Error {e.code}: {e.reason}"}
    except Exception as e:
        return {"success": False, "error": f"Upload failed: {str(e)}"}


def analyze_file_or_hash(
    file_or_hash: str,
    api_key: Optional[str] = None,
    upload_if_missing: bool = False,
) -> Dict[str, Any]:
    """
    Analyze either a local file (computes SHA-256 first) or a raw hash digest.
    If file is not found in VirusTotal and upload_if_missing is True, submits it.
    """
    is_file = os.path.isfile(file_or_hash)

    if is_file:
        file_hash = compute_hash(file_or_hash, "sha256")
        report = check_hash_virustotal(file_hash, api_key)
        report["local_file_path"] = file_or_hash

        if report.get("success") and not report.get("found") and upload_if_missing:
            upload_res = upload_file_virustotal(file_or_hash, api_key)
            report["upload_attempted"] = True
            report["upload_result"] = upload_res
        return report
    else:
        return check_hash_virustotal(file_or_hash, api_key)
